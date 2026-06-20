// Package auth wires private-mode sign-in (local password, TOTP 2FA, passkeys,
// and - in oidc.go - SSO) and the session cookie. It is an orthogonal access
// gate: it never touches the opaque ciphertext a secret holds.
package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

type Handler struct {
	Runtime *env.Runtime
	Store   *store.Store
}

// Me returns the current session state. Open by design (no requireAuth) so the
// SPA's "am I logged in?" probe can distinguish three outcomes:
//
//	{auth_enabled: false, user: null} - auth is off, render everything
//	{auth_enabled: true,  user: {...}} - session valid, render user
//	{auth_enabled: true,  user: null}  - no session, send to /signin
//
// A 401 here would loop the client with /signin; the user field avoids that.
func (h *Handler) Me(c *fiber.Ctx) error {
	resp := fiber.Map{
		"auth_enabled": h.Runtime.Config.Auth.Enabled,
		"user":         nil,
	}
	if !h.Runtime.Config.Auth.Enabled {
		return c.JSON(resp)
	}
	claims, ok := session.FromCtx(c, h.Runtime.SessionSecret)
	if !ok {
		return c.JSON(resp)
	}
	// Re-read the user: role and enabled-state can change after the cookie
	// was minted. A disabled (or deleted) user reads as logged-out.
	role := claims.Role
	totpEnabled := false
	hasPassword := false
	source := ""
	if p, err := h.Store.Users.Get(c.UserContext(), claims.Email); err == nil && p != nil {
		if !p.Enabled {
			return c.JSON(resp)
		}
		role = string(p.Role)
		totpEnabled = p.TOTPEnabled
		hasPassword = p.PasswordHash != ""
		source = p.Source
	}
	resp["user"] = fiber.Map{
		"sub":          claims.Subject,
		"email":        claims.Email,
		"name":         claims.Name,
		"groups":       claims.Groups,
		"role":         role,
		"totp_enabled": totpEnabled,
		// has_password drives the SPA: local-credential self-service (password,
		// email, 2FA, passkeys) only applies to accounts that have a password.
		"has_password": hasPassword,
		"source":       source,
	}
	return c.JSON(resp)
}

// Info reports which auth methods are configured so the SPA can render the right
// login options. oidc_providers is populated by the OIDC layer (oidc.go).
func (h *Handler) Info(c *fiber.Ctx) error {
	cfg := h.Runtime.Config.Auth
	localOn := cfg.Enabled && cfg.LocalLogin
	info := fiber.Map{
		"auth_enabled":     cfg.Enabled,
		"gate":             cfg.Gate,
		"password_enabled": localOn,
		"passkey_enabled":  localOn,
		"oidc_providers":   h.oidcButtons(), // empty until OIDC is wired (oidc.go)
	}
	return c.JSON(info)
}

// PasswordLogin signs in a local (email+password) user and mints the session
// cookie. Open by design (login can't require a session). Available only when
// local login is enabled.
func (h *Handler) PasswordLogin(c *fiber.Ctx) error {
	cfg := h.Runtime.Config.Auth
	if !cfg.Enabled {
		return response.Error(c, http.StatusBadRequest, "auth is disabled")
	}
	if !cfg.LocalLogin {
		return response.Forbidden(c, "password login is disabled; sign in with SSO")
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"` // TOTP or recovery code, second step
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	email := user.NormalizeEmail(body.Email)
	ctx := c.UserContext()

	p, err := h.Store.Users.Get(ctx, email)
	if err != nil {
		return response.Internal(c, err)
	}
	// Same failure response whether the account is missing, has no local password,
	// is disabled, or the password is wrong - never disclose which.
	// FakePasswordCheck keeps the no-such-account branch as costly as a real
	// bcrypt compare (no timing leak).
	ok := false
	if p != nil && p.Enabled && p.PasswordHash != "" {
		ok = p.CheckPassword(body.Password)
	} else {
		user.FakePasswordCheck(body.Password)
	}
	if !ok {
		h.Runtime.Log.Warn("auth: password login failed", "email", email, "client_ip", c.IP())
		return response.Unauthorized(c, "invalid email or password")
	}

	// Second factor (local accounts only). Reached only after a correct password,
	// so "mfa_required" leaks nothing more. The UI re-submits with the same
	// email+password plus the code.
	if p.TOTPEnabled {
		code := strings.TrimSpace(body.Code)
		if code == "" {
			return c.JSON(fiber.Map{"mfa_required": true})
		}
		if !h.verifySecondFactor(ctx, p, code) {
			h.Runtime.Log.Warn("auth: 2fa failed", "email", p.Email, "client_ip", c.IP())
			return response.Unauthorized(c, "invalid authentication code")
		}
	}

	exp := time.Now().Add(h.Runtime.SessionTTL)
	cookieValue, err := session.Sign(session.Claims{
		Subject: p.Email,
		Email:   p.Email,
		Name:    p.Name,
		Role:    string(p.Role),
	}, h.Runtime.SessionSecret, exp)
	if err != nil {
		return response.Internal(c, err)
	}
	session.Set(c, cookieValue, h.Runtime.SessionTTL, h.secure(c))

	p.LastLoginAt = ptr(time.Now().UTC())
	if err := h.Store.Users.Upsert(ctx, p); err != nil {
		h.Runtime.Log.Warn("auth: last_login update failed", "email", p.Email, "err", err)
	}
	h.Runtime.Log.Info("auth: password login", "email", p.Email, "role", p.Role, "client_ip", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// Logout clears the session cookie. Returns 200 even with no cookie - POST
// /logout is idempotent.
func (h *Handler) Logout(c *fiber.Ctx) error {
	session.Clear(c, h.secure(c))
	return c.JSON(fiber.Map{"ok": true})
}

// secure reports whether cookies should be marked Secure, accounting for an
// upstream TLS terminator (server.behind_tls_proxy).
func (h *Handler) secure(c *fiber.Ctx) bool {
	return session.Secure(c, h.Runtime.Config.Server.BehindTLSProxy)
}

// ptr returns a pointer to v. Used for optional time fields like LastLoginAt.
func ptr[T any](v T) *T { return &v }
