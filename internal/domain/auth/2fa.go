package auth

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/secretbox"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/core/totp"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

const recoveryCodeCount = 10

// localSelfUser loads the signed-in user for self-service security (2FA,
// passkeys). The per-action password checks already require a local password, so
// an OIDC-only account simply can't pass them. On a guard failure it writes the
// response and returns a non-nil error for the caller to propagate.
func (h *Handler) localSelfUser(c *fiber.Ctx) (*user.User, error) {
	cl := session.FromLocals(c)
	if cl == nil || cl.Email == "" {
		return nil, response.Unauthorized(c, "")
	}
	p, err := h.Store.Users.Get(c.UserContext(), cl.Email)
	if err != nil {
		return nil, response.Internal(c, err)
	}
	if p == nil || !p.Enabled {
		return nil, response.Unauthorized(c, "")
	}
	return p, nil
}

func (h *Handler) totpKey() []byte { return secretbox.DeriveKey(h.Runtime.SessionSecret) }

// TwoFASetup begins TOTP enrollment: generates a secret (stored sealed, pending)
// and returns the QR + base32 secret. 2FA stays inactive until TwoFAConfirm
// proves the user can produce a valid code.
func (h *Handler) TwoFASetup(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	if p.PasswordHash == "" {
		return response.Forbidden(c, "two-factor auth requires a local password account")
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	if !p.CheckPassword(body.Password) {
		return response.Forbidden(c, "incorrect password")
	}
	if p.TOTPEnabled {
		return response.Error(c, fiber.StatusConflict, "two-factor auth is already enabled; disable it first")
	}
	enr, err := totp.Enroll(p.Email)
	if err != nil {
		return response.Internal(c, err)
	}
	enc, err := secretbox.Seal(h.totpKey(), enr.Secret)
	if err != nil {
		return response.Internal(c, err)
	}
	p.TOTPSecretEnc = enc // pending; TOTPEnabled stays false until confirmed
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	return c.JSON(fiber.Map{
		"secret":        enr.Secret,
		"otpauth_url":   enr.URL,
		"qr_png_base64": enr.QRPNGBase64,
	})
}

// TwoFAConfirm verifies a code against the pending secret, enables 2FA, and
// returns one-time recovery codes (shown to the user exactly once).
func (h *Handler) TwoFAConfirm(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	if p.TOTPEnabled {
		return response.Error(c, fiber.StatusConflict, "two-factor auth is already enabled")
	}
	if p.TOTPSecretEnc == "" {
		return response.Error(c, fiber.StatusBadRequest, "start setup first")
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	secret, err := secretbox.Open(h.totpKey(), p.TOTPSecretEnc)
	if err != nil {
		return response.Internal(c, err)
	}
	if !totp.Validate(strings.TrimSpace(body.Code), secret) {
		return response.Error(c, fiber.StatusBadRequest, "invalid code")
	}
	codes, err := user.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return response.Internal(c, err)
	}
	if err := p.SetRecoveryCodes(codes); err != nil {
		return response.Internal(c, err)
	}
	p.TOTPEnabled = true
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("auth: 2fa enabled", "email", p.Email)
	return c.JSON(fiber.Map{"ok": true, "recovery_codes": codes})
}

// TwoFADisable turns 2FA off and wipes the secret + recovery codes. Requires the
// current password so a hijacked session can't drop the factor.
func (h *Handler) TwoFADisable(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	if !p.CheckPassword(body.Password) {
		return response.Forbidden(c, "incorrect password")
	}
	p.TOTPEnabled = false
	p.TOTPSecretEnc = ""
	p.RecoveryCodeHashes = nil
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("auth: 2fa disabled", "email", p.Email)
	return c.JSON(fiber.Map{"ok": true})
}

// TwoFARecoveryRegenerate issues fresh recovery codes, invalidating the old
// ones. Requires the current password.
func (h *Handler) TwoFARecoveryRegenerate(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	if !p.TOTPEnabled {
		return response.Error(c, fiber.StatusBadRequest, "two-factor auth is not enabled")
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	if !p.CheckPassword(body.Password) {
		return response.Forbidden(c, "incorrect password")
	}
	codes, err := user.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return response.Internal(c, err)
	}
	if err := p.SetRecoveryCodes(codes); err != nil {
		return response.Internal(c, err)
	}
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	return c.JSON(fiber.Map{"ok": true, "recovery_codes": codes})
}

// verifySecondFactor checks a login code: a current TOTP code first, then a
// one-time recovery code (consumed and persisted on use).
func (h *Handler) verifySecondFactor(ctx context.Context, p *user.User, code string) bool {
	if p.TOTPSecretEnc != "" {
		if secret, err := secretbox.Open(h.totpKey(), p.TOTPSecretEnc); err == nil && totp.Validate(code, secret) {
			return true
		}
	}
	if p.ConsumeRecoveryCode(code) {
		if err := h.Store.Users.Upsert(ctx, p); err != nil {
			h.Runtime.Log.Warn("auth: persisting recovery-code use failed", "email", p.Email, "err", err)
		}
		return true
	}
	return false
}
