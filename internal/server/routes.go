package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"

	secretshareui "github.com/YouSysAdmin/secret-share"
	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/domain/auth"
	"github.com/YouSysAdmin/secret-share/internal/domain/secrets"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/domain/users"
	usermodel "github.com/YouSysAdmin/secret-share/internal/models/user"
)

func registerRoutes(app *fiber.App, rt *env.Runtime, st *store.Store) {
	// Liveness probe at the root so health checks don't need any prefix.
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// noStoreCache keeps API responses out of caches; requireSameOrigin is the
	// CSRF guard on state-changing methods. Sub-groups inherit both.
	api := app.Group("/api", noStoreCache, requireSameOrigin)

	authEnabled := rt.Config.Auth.Enabled
	// authGate is the single session check; it's a no-op passthrough when auth is
	// disabled. The same gate is attached to different route sets below depending
	// on auth.gate (the configurable-gate decision).
	authGate := requireAuth(rt, st)
	ah := &auth.Handler{Runtime: rt, Store: st}

	// UI limits (lifetime presets, max size) plus the auth posture so the create
	// form can render presets and decide whether to prompt sign-in.
	api.Get("/config", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"allowed_ttls":   rt.Config.Secrets.AllowedTTLs,
			"default_ttl":    rt.Config.Secrets.DefaultTTL,
			"max_ttl":        rt.Config.Secrets.MaxTTL,
			"max_size_bytes": rt.Config.Secrets.MaxSizeBytes,
			"auth_enabled":   authEnabled,
			"gate":           rt.Config.Auth.Gate,
		})
	})

	// Auth endpoints needed before a session exists are always reachable. Login
	// methods are only mounted when auth + local login are on (OIDC routes are
	// added by the OIDC layer).
	api.Get("/auth/me", ah.Me)
	api.Get("/auth/info", ah.Info)
	api.Post("/auth/logout", ah.Logout)
	if authEnabled && rt.Config.Auth.LocalLogin {
		api.Post("/auth/login", loginRateLimiter(), ah.PasswordLogin)
		api.Post("/auth/passkey/login/begin", ah.PasskeyLoginBegin)
		api.Post("/auth/passkey/login/finish", ah.PasskeyLoginFinish)
	}
	// OIDC start/callback are GETs (top-level navigations, exempt from the
	// same-origin guard); the provider id is in the path and re-checked against
	// the signed state cookie inside the handler.
	if authEnabled && rt.OIDC.Enabled() {
		api.Get("/auth/oidc/:provider/start", ah.OIDCStart)
		api.Get("/auth/oidc/:provider/callback", ah.OIDCCallback)
	}

	// Secrets. meta never burns; reveal is the single burn path and is POST so
	// link prefetchers (GET/HEAD) can't trigger it.
	//
	// The gate (all middlewares are no-ops when auth is disabled):
	//   - create:  requires a session whenever auth is on (authGate). captureVisibility
	//              records the new secret as private when the request asked for it.
	//   - meta/reveal: revealGate requires a session when gate=="all" OR this
	//              specific secret is private; otherwise it stays open so an external
	//              recipient with just the link can preview/reveal it.
	sh := &secrets.Handler{Runtime: rt, Store: st}
	api.Post("/secrets", rateLimiter(), authGate, captureVisibility(rt, st), sh.Create)
	api.Get("/secrets/:id/meta", revealGate(rt, st), sh.Meta)
	api.Post("/secrets/:id/reveal", rateLimiter(), revealGate(rt, st), dropVisibilityOnBurn(rt, st), sh.Reveal)

	// Self-service account + admin management. Only mounted (and only meaningful)
	// when auth is enabled, since they all require a session.
	if authEnabled {
		acct := api.Group("", authGate)
		acct.Post("/account/email", ah.ChangeEmail)
		acct.Post("/account/password", ah.ChangePassword)
		acct.Post("/account/2fa/setup", ah.TwoFASetup)
		acct.Post("/account/2fa/confirm", ah.TwoFAConfirm)
		acct.Post("/account/2fa/disable", ah.TwoFADisable)
		acct.Post("/account/2fa/recovery-codes", ah.TwoFARecoveryRegenerate)
		acct.Get("/account/passkeys", ah.PasskeyList)
		acct.Post("/account/passkeys/register/begin", ah.PasskeyRegisterBegin)
		acct.Post("/account/passkeys/register/finish", ah.PasskeyRegisterFinish)
		acct.Delete("/account/passkeys/:id", ah.PasskeyDelete)

		// Admin-only user management. requireRole(admin) runs after authGate.
		adminOnly := requireRole(usermodel.RoleAdmin)
		ph := &users.Handler{Runtime: rt, Store: st}
		acct.Get("/users", adminOnly, ph.List)
		acct.Post("/users", adminOnly, ph.Create)
		acct.Put("/users/:email", adminOnly, ph.Update)
		acct.Delete("/users/:email", adminOnly, ph.Delete)
	}

	// Unknown /api paths: 404 JSON instead of the SPA index.html fallback.
	api.Use(func(c *fiber.Ctx) error {
		return response.NotFound(c, "")
	})

	// SPA fallback. Register LAST so /api/* matches first.
	sub, err := fs.Sub(secretshareui.Frontend, "frontend/dist")
	if err != nil {
		app.Use("/", func(c *fiber.Ctx) error {
			return c.Status(http.StatusInternalServerError).SendString("spa embed unavailable: " + err.Error())
		})
		return
	}
	app.Use("/", uiCacheControl, filesystem.New(filesystem.Config{
		Root:         http.FS(sub),
		Index:        "index.html",
		NotFoundFile: "index.html",
	}))
}

// uiCacheControl sets Cache-Control on embedded UI assets after the filesystem
// middleware writes the body.
func uiCacheControl(c *fiber.Ctx) error {
	if err := c.Next(); err != nil {
		return err
	}
	p := c.Path()
	switch {
	case strings.Contains(p, "/_app/immutable/"):
		c.Set(fiber.HeaderCacheControl, "public, max-age=31536000, immutable")
	case p == "/" || strings.HasSuffix(p, ".html") || path.Ext(p) == "":
		// "/" and every extension-less client route (/signin, /s/<id>, /account,
		// /users, ...) are served the SPA shell (index.html via the fallback).
		// Never cache the shell: otherwise, after a deploy, those routes keep
		// running the old bundle (it references stale asset hashes) until the
		// browser cache expires.
		c.Set(fiber.HeaderCacheControl, "no-cache")
	default:
		c.Set(fiber.HeaderCacheControl, "public, max-age=86400")
	}
	return nil
}
