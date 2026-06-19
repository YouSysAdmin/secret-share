package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"

	secretshareui "github.com/YouSysAdmin/secret-share"
	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/domain/secrets"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

func registerRoutes(app *fiber.App, rt *env.Runtime, st *store.Store) {
	// Liveness probe at the root so health checks don't need any prefix.
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// noStoreCache keeps API responses out of caches; requireSameOrigin is the
	// CSRF guard on state-changing methods. Every endpoint is open - there are no
	// accounts.
	api := app.Group("/api", noStoreCache, requireSameOrigin)

	// UI limits (lifetime presets, max size) so the create form can render them.
	api.Get("/config", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"allowed_ttls":   rt.Config.Secrets.AllowedTTLs,
			"default_ttl":    rt.Config.Secrets.DefaultTTL,
			"max_ttl":        rt.Config.Secrets.MaxTTL,
			"max_size_bytes": rt.Config.Secrets.MaxSizeBytes,
		})
	})

	// Secrets. meta never burns; reveal is the single burn path and is POST so
	// link prefetchers (GET/HEAD) can't trigger it.
	sh := &secrets.Handler{Runtime: rt, Store: st}
	api.Post("/secrets", rateLimiter(), sh.Create)
	api.Get("/secrets/:id/meta", sh.Meta)
	api.Post("/secrets/:id/reveal", rateLimiter(), sh.Reveal)

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
	case p == "/" || strings.HasSuffix(p, ".html"):
		c.Set(fiber.HeaderCacheControl, "no-cache")
	default:
		c.Set(fiber.HeaderCacheControl, "public, max-age=86400")
	}
	return nil
}
