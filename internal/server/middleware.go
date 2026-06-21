package server

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

// verifySession checks the session cookie and re-reads the user store, which is
// authoritative for role + enabled-state (a role change or disable/delete takes
// effect on the next request, not just the next login). On success it writes the
// resolved claims to Locals and returns (true, nil). Returns (false, nil) for no
// or invalid session, and (false, err) only on a store error.
func verifySession(rt *env.Runtime, st *store.Store, c *fiber.Ctx) (bool, error) {
	claims, ok := session.FromCtx(c, rt.SessionSecret)
	if !ok {
		return false, nil
	}
	p, err := st.Users.Get(c.UserContext(), claims.Email)
	if err != nil {
		return false, err
	}
	if p == nil || !p.Enabled {
		return false, nil
	}
	claims.Role = string(p.Role)
	c.Locals(session.LocalsKey, claims)
	return true, nil
}

// requireAuth lets authenticated requests through and 401s the rest. A no-op
// passthrough when auth is disabled (it is only attached to routes when auth is
// enabled). The resolved role is written onto the Locals claims for requireRole +
// handlers.
func requireAuth(rt *env.Runtime, st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !rt.Config.Auth.Enabled {
			return c.Next()
		}
		ok, err := verifySession(rt, st, c)
		if err != nil {
			return response.Internal(c, err)
		}
		if !ok {
			return response.Unauthorized(c, "")
		}
		return c.Next()
	}
}

// revealGate gates the preview (meta) and reveal endpoints. Order of precedence:
//   - auth disabled       -> always open (no sessions exist to enforce).
//   - gate == "all"       -> always require a session (operator floor).
//   - otherwise           -> require a session only if THIS secret is private.
//
// Per-secret private is read from the visibility store keyed by the path :id, so
// a public secret stays openable by anyone with the link while a private one
// 401s an anonymous caller (the SPA then redirects to /signin).
func revealGate(rt *env.Runtime, st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !rt.Config.Auth.Enabled {
			return c.Next()
		}
		needAuth := rt.Config.Auth.Gate == "all"
		if !needAuth {
			priv, err := st.Visibility.IsPrivate(c.UserContext(), c.Params("id"))
			if err != nil {
				return response.Internal(c, err)
			}
			needAuth = priv
		}
		if needAuth {
			ok, err := verifySession(rt, st, c)
			if err != nil {
				return response.Internal(c, err)
			}
			if !ok {
				return response.Unauthorized(c, "")
			}
		}
		return c.Next()
	}
}

// captureVisibility runs around the create handler: it lets the handler mint the
// secret, then - if the request asked for a private secret and the create
// succeeded - records the new id as private BEFORE the response is flushed (so a
// private secret is never briefly public). A no-op when auth is disabled (no
// sessions exist, so private would be unrevealable). Visibility-write failures
// are logged, not fatal: the secret simply stays public.
func captureVisibility(rt *env.Runtime, st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := c.Next(); err != nil {
			return err
		}
		if !rt.Config.Auth.Enabled {
			return nil
		}
		if code := c.Response().StatusCode(); code < 200 || code >= 300 {
			return nil
		}
		var req struct {
			Private bool `json:"private"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil || !req.Private {
			return nil
		}
		var resp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(c.Response().Body(), &resp); err != nil || resp.ID == "" {
			return nil
		}
		if err := st.Visibility.SetPrivate(c.UserContext(), resp.ID); err != nil {
			rt.Log.Error("failed to record secret visibility", "id", resp.ID, "err", err)
		}
		return nil
	}
}

// dropVisibilityOnBurn runs after the reveal handler: once a secret is
// successfully revealed (and thus burned), its visibility record is dropped so
// it doesn't linger. Best-effort.
func dropVisibilityOnBurn(rt *env.Runtime, st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		if err == nil && c.Response().StatusCode() == fiber.StatusOK {
			if e := st.Visibility.Delete(c.UserContext(), c.Params("id")); e != nil {
				rt.Log.Warn("failed to drop secret visibility record", "id", c.Params("id"), "err", e)
			}
		}
		return err
	}
}

// requireRole gates a route on a minimum role. It must run after requireAuth,
// which populates the authoritative role on the request. admin satisfies every
// role; a user hitting an admin-only route gets 403.
func requireRole(want user.Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := session.FromLocals(c)
		if claims == nil {
			return response.Unauthorized(c, "")
		}
		role, _ := user.ParseRole(claims.Role)
		if !role.Allows(want) {
			return response.Forbidden(c, "insufficient role")
		}
		return c.Next()
	}
}

// loginRateLimiter throttles login attempts per client IP so credentials can't
// be brute-forced at network speed. In-memory: fine for one instance, resets on
// restart.
func loginRateLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return response.Error(c, fiber.StatusTooManyRequests, "too many login attempts; try again in a minute")
		},
	})
}

// defaultNoCache sets Cache-Control: no-cache as the baseline for every response.
// It runs before the handler so anything downstream can override it: cacheable
// static assets do (uiCacheControl, which runs after the filesystem write), and
// the /api group upgrades it to the stronger no-store (noStoreCache). What's left
// is every non-asset route with no explicit cache handling - e.g. /healthz - which
// must never be served stale. Net effect: assets cache, everything else no-caches.
func defaultNoCache(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-cache")
	return c.Next()
}

// noStoreCache forces Cache-Control: no-store on every /api/* response. Critical
// here so a revealed secret is never cached. Stronger than the defaultNoCache
// baseline (no-store forbids storing at all; no-cache only forces revalidation).
func noStoreCache(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Next()
}

// requireSameOrigin is the CSRF guard for state-changing API requests. A
// Fetch-Metadata + Origin check (the OWASP resource isolation pattern) blocks
// cross-site POSTs. Safe methods (GET/HEAD/OPTIONS) are never gated, and a
// request with no browser-origin signal (curl) passes through.
func requireSameOrigin(c *fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
		return c.Next()
	}

	switch c.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return c.Next()
	case "same-site", "cross-site":
		return response.Forbidden(c, "cross-origin request blocked")
	}

	origin := c.Get(fiber.HeaderOrigin)
	if origin == "" {
		return c.Next()
	}
	if u, err := url.Parse(origin); err == nil && u.Hostname() != "" &&
		strings.EqualFold(u.Hostname(), hostWithoutPort(c.Hostname())) {
		return c.Next()
	}
	return response.Forbidden(c, "cross-origin request blocked")
}

// hostWithoutPort strips a trailing :port from a Host value (handling IPv6
// "[::1]:8443"). A bare host without a port is returned unchanged.
func hostWithoutPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// rateLimiter throttles per client IP (in-memory; fine for one instance, resets
// on restart). Applied to the create and reveal endpoints.
func rateLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        60,
		Expiration: time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return response.TooManyRequests(c, "too many requests; slow down")
		},
	})
}
