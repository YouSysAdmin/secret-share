package auth

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

// reissueSession re-mints the session cookie for p, e.g. after an email change.
func (h *Handler) reissueSession(c *fiber.Ctx, p *user.User) error {
	exp := time.Now().Add(h.Runtime.SessionTTL)
	v, err := session.Sign(session.Claims{
		Subject: p.Email,
		Email:   p.Email,
		Name:    p.Name,
		Role:    string(p.Role),
	}, h.Runtime.SessionSecret, exp)
	if err != nil {
		return err
	}
	session.Set(c, v, h.Runtime.SessionTTL, h.secure(c))
	return nil
}

// ChangeEmail changes the local account's email (its primary key), re-keying the
// user in the store and re-issuing the session. Requires the current
// password.
func (h *Handler) ChangeEmail(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	if p.PasswordHash == "" {
		return response.Forbidden(c, "changing email requires a local password account")
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	if !p.CheckPassword(body.Password) {
		return response.Forbidden(c, "incorrect password")
	}
	newEmail := user.NormalizeEmail(body.Email)
	if newEmail == "" || !strings.Contains(newEmail, "@") {
		return response.Error(c, fiber.StatusBadRequest, "a valid email is required")
	}
	old := p.Email
	if newEmail == old {
		return c.JSON(fiber.Map{"ok": true, "email": old})
	}

	ctx := c.UserContext()
	if existing, err := h.Store.Users.Get(ctx, newEmail); err != nil {
		return response.Internal(c, err)
	} else if existing != nil {
		return response.Error(c, fiber.StatusConflict, "that email is already in use")
	}

	// Upsert the new key before deleting the old, so a failed second op can't lose
	// the account. CreatedAt is preserved (Upsert only stamps it when zero).
	p.Email = newEmail
	if err := h.Store.Users.Upsert(ctx, p); err != nil {
		return response.Internal(c, err)
	}
	if err := h.Store.Users.Delete(ctx, old); err != nil {
		h.Runtime.Log.Warn("account: deleting old user key failed", "old", old, "err", err)
	}
	if err := h.reissueSession(c, p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("account: email changed", "old", old, "new", newEmail)
	return c.JSON(fiber.Map{"ok": true, "email": newEmail})
}

// ChangePassword sets a new password after verifying the current one.
func (h *Handler) ChangePassword(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	if p.PasswordHash == "" {
		return response.Forbidden(c, "this account has no password to change")
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	if !p.CheckPassword(body.CurrentPassword) {
		return response.Forbidden(c, "incorrect password")
	}
	if n := len(body.NewPassword); n < 8 || n > 72 {
		// 72 bytes is bcrypt's hard limit; reject here for a clean 400 instead of
		// a 500 from SetPassword.
		return response.Error(c, fiber.StatusBadRequest, "password must be 8-72 characters")
	}
	if err := p.SetPassword(body.NewPassword); err != nil {
		return response.Internal(c, err)
	}
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("account: password changed", "email", p.Email)
	return c.JSON(fiber.Map{"ok": true})
}
