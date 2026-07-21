// Package server is the HTTP edge: Fiber app + middleware + route registration.
// Domain logic lives in internal/domain/<thing>/.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/tlsutils"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

type Server struct {
	app        *fiber.App
	rt         *env.Runtime
	tlsCfg     *tls.Config // nil = serve plain HTTP
	metrics    *httpMetrics
	metricsSrv *http.Server // nil until Start (and when metrics are disabled)
}

type Options struct {
	Runtime *env.Runtime
	// Store is the aggregate persistence handle (per-domain stores), passed to
	// handlers alongside Runtime. It lives outside Runtime to avoid an env cycle.
	Store *store.Store
}

// bodyLimit caps the request body across the whole API. Individual secret size
// is enforced per-request against secrets.max_size_bytes; this is generous
// headroom above that.
const bodyLimit = 2 * 1024 * 1024

// baseFiberConfig is the Fiber config shared by the real server and its tests.
//
// UnescapePath MUST stay true: path params are URL-encoded by the SPA, and the
// user-search/recipient routes are keyed by email (which contains "@" -> "%40").
// Without this c.Params would keep the literal "%40" and lookups miss.
func baseFiberConfig() fiber.Config {
	return fiber.Config{
		DisableStartupMessage: true,
		BodyLimit:             bodyLimit,
		UnescapePath:          true,
	}
}

// New builds the Fiber app, resolves the TLS config, and registers routes. The
// *tls.Config is materialized here (not at Start) so a bad cert path / missing
// ACME hosts fails at boot. With server.tls.mode=none the server listens plain -
// run it behind a TLS-terminating reverse proxy and set server.behind_tls_proxy.
func New(opts Options) (*Server, error) {
	tlsCfg, err := tlsutils.Build(opts.Runtime.Config.Server.TLS)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	fiberCfg := baseFiberConfig()
	// File uploads can exceed the JSON-API headroom: lift the global body limit
	// to the configured file ceiling plus slack (the per-request file size is
	// still enforced exactly in the files handler).
	if fc := opts.Runtime.Config.Files; fc.Enabled && fc.MaxSizeBytes+1024*1024 > fiberCfg.BodyLimit {
		fiberCfg.BodyLimit = fc.MaxSizeBytes + 1024*1024
	}
	if proxies := opts.Runtime.Config.Server.TrustedProxies; len(proxies) > 0 {
		fiberCfg.EnableTrustedProxyCheck = true
		fiberCfg.TrustedProxies = proxies
		fiberCfg.ProxyHeader = fiber.HeaderXForwardedFor
	}

	app := fiber.New(fiberCfg)
	app.Use(safeRecover)
	var m *httpMetrics
	if opts.Runtime.Config.Metrics.Enabled {
		m = newHTTPMetrics()
		app.Use(m.middleware())
	}
	app.Use(securityHeaders(opts.Runtime.Config.Server.BehindTLSProxy))
	app.Use(defaultNoCache)
	app.Use(accessLog(opts.Runtime.Log))

	registerRoutes(app, opts.Runtime, opts.Store)
	return &Server{app: app, rt: opts.Runtime, tlsCfg: tlsCfg, metrics: m}, nil
}

// App exposes the underlying Fiber app (for tests).
func (s *Server) App() *fiber.App { return s.app }

func (s *Server) Start() error {
	addr := s.rt.Config.Server.Addr
	if s.metrics != nil {
		s.metricsSrv = s.metrics.startServer(s.rt.Config.Metrics.Addr, s.rt.Log)
	}
	if s.tlsCfg != nil {
		ln, err := tls.Listen("tcp", addr, s.tlsCfg)
		if err != nil {
			return fmt.Errorf("tls listen %s: %w", addr, err)
		}
		slog.Info("server start", "addr", addr, "tls", s.rt.Config.Server.TLS.Mode)
		return s.app.Listener(ln)
	}
	slog.Info("server start", "addr", addr, "tls", "none")
	return s.app.Listen(addr)
}

// Shutdown drains the Fiber app (and the metrics listener), bounded so a
// lingering connection can't hang process exit forever.
func (s *Server) Shutdown() error {
	if s.metricsSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.metricsSrv.Shutdown(ctx); err != nil {
			s.rt.Log.Warn("metrics server shutdown", "err", err)
		}
	}
	return s.app.ShutdownWithTimeout(10 * time.Second)
}

// safeRecover catches panics, logs them with a stack, and returns a generic 500
// (no internal-state leakage).
func safeRecover(c *fiber.Ctx) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered",
				"reason", fmt.Sprintf("%v", r),
				"path", c.Path(),
				"method", c.Method(),
				"client_ip", c.IP(),
				"stack", string(debug.Stack()),
			)
			err = response.Internal(c, nil)
		}
	}()
	return c.Next()
}

func securityHeaders(behindTLSProxy bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// HSTS only over TLS: this hop is HTTPS, or an upstream proxy terminates it.
		if behindTLSProxy || c.Protocol() == "https" {
			c.Set("Strict-Transport-Security", "max-age=31536000")
		}
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		// no-referrer matters here: the share-link fragment (#k=) must never leak
		// via Referer to any subresource. The app loads only same-origin assets.
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Cross-Origin-Opener-Policy", "same-origin")
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		return c.Next()
	}
}

// accessLog logs one line per request. Static assets log at DEBUG so they don't
// drown the INFO log on every page load.
func accessLog(log *slog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		status := c.Response().StatusCode()
		p := c.Path()
		level := slog.LevelInfo
		if isAssetPath(p) || isHealthzPath(p) {
			level = slog.LevelDebug
		}
		log.Log(c.UserContext(), level, "http",
			"method", c.Method(),
			"path", p,
			"status", status,
			"client_ip", c.IP(),
		)
		return err
	}
}

// isAssetPath reports whether p is a static UI asset, so accessLog can log it at
// DEBUG instead of INFO.
func isAssetPath(p string) bool {
	if strings.Contains(p, "/_app/") {
		return true
	}
	switch path.Ext(p) {
	case ".js", ".mjs", ".css", ".map", ".ico", ".png", ".jpg", ".jpeg",
		".gif", ".svg", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".wasm":
		return true
	}
	return false
}

// isHealthzPath reports whether p is the /healthz, so accessLog can log it at
// DEBUG instead of INFO.
func isHealthzPath(p string) bool {
	if strings.Contains(p, "/healthz") {
		return true
	}
	return false
}
