package server

import (
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"

	"github.com/YouSysAdmin/secret-share/internal/core/response"
)

// noStoreCache forces Cache-Control: no-store on every /api/* response. Critical
// here so a revealed secret is never cached.
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
