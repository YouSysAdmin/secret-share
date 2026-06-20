package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/YouSysAdmin/secret-share/internal/core/passkey"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/secretbox"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

const (
	waRegCookie   = "share_wa_reg"
	waLoginCookie = "share_wa_login"
	waCookieTTL   = 5 * time.Minute
)

// webauthnService builds the relying party from the browser's Origin (validated
// by requireSameOrigin on state-changing calls). The Origin is exactly what the
// browser signs into the WebAuthn client data, so deriving the RP ID/origin from
// it keeps them equal to what the authenticator binds - in dev and prod alike,
// without depending on the proxy to preserve the request Host.
func (h *Handler) webauthnService(c *fiber.Ctx) (*passkey.Service, error) {
	origin := c.Get(fiber.HeaderOrigin)
	if origin == "" {
		return nil, fmt.Errorf("missing Origin (passkeys require a browser)")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid Origin")
	}
	return passkey.New(u.Hostname(), origin)
}

func (h *Handler) setWebAuthnSession(c *fiber.Ctx, name string, sess *passkey.SessionData) error {
	b, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	enc, err := secretbox.Seal(h.totpKey(), string(b))
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{
		Name: name, Value: enc, Path: "/",
		Expires: time.Now().Add(waCookieTTL), HTTPOnly: true, Secure: h.secure(c), SameSite: "Lax",
	})
	return nil
}

// takeWebAuthnSession reads + clears the ceremony cookie (single use).
func (h *Handler) takeWebAuthnSession(c *fiber.Ctx, name string) (*passkey.SessionData, error) {
	v := c.Cookies(name)
	c.Cookie(&fiber.Cookie{
		Name: name, Value: "", Path: "/",
		Expires: time.Unix(0, 0), MaxAge: -1, HTTPOnly: true, Secure: h.secure(c), SameSite: "Lax",
	})
	if v == "" {
		return nil, fmt.Errorf("no ceremony session")
	}
	plain, err := secretbox.Open(h.totpKey(), v)
	if err != nil {
		return nil, err
	}
	var sd passkey.SessionData
	if err := json.Unmarshal([]byte(plain), &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

// PasskeyRegisterBegin starts enrollment of a new passkey, ensuring a stable
// WebAuthn user handle exists first.
func (h *Handler) PasskeyRegisterBegin(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	if p.PasswordHash == "" {
		return response.Forbidden(c, "passkeys require a local password account")
	}
	// Re-auth: adding a credential is sensitive. Verified server-side so the
	// client can't skip it.
	var body struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return response.BadRequest(c, err)
	}
	if !p.CheckPassword(body.Password) {
		return response.Forbidden(c, "incorrect password")
	}
	svc, err := h.webauthnService(c)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	if len(p.WebAuthnHandle) == 0 {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return response.Internal(c, err)
		}
		p.WebAuthnHandle = buf
		if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
			return response.Internal(c, err)
		}
	}
	stored, err := passkey.Decode(p.Passkeys)
	if err != nil {
		return response.Internal(c, err)
	}
	u := &passkey.User{Handle: p.WebAuthnHandle, Name: p.Email, Display: p.Name, Creds: passkey.Credentials(stored)}
	opts, sess, err := svc.BeginRegistration(u)
	if err != nil {
		return response.Internal(c, err)
	}
	if err := h.setWebAuthnSession(c, waRegCookie, sess); err != nil {
		return response.Internal(c, err)
	}
	return c.JSON(opts)
}

// PasskeyRegisterFinish verifies the attestation and stores the new passkey.
func (h *Handler) PasskeyRegisterFinish(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	svc, err := h.webauthnService(c)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	sess, err := h.takeWebAuthnSession(c, waRegCookie)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, "registration session expired; start again")
	}
	stored, err := passkey.Decode(p.Passkeys)
	if err != nil {
		return response.Internal(c, err)
	}
	u := &passkey.User{Handle: p.WebAuthnHandle, Name: p.Email, Display: p.Name, Creds: passkey.Credentials(stored)}
	cred, err := svc.FinishRegistration(u, *sess, c.Body())
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, "passkey registration failed: "+err.Error())
	}
	name := c.Query("name")
	if name == "" {
		name = "passkey"
	}
	stored = append(stored, passkey.Stored{Credential: *cred, Name: name, AddedAt: time.Now().UTC().Format(time.RFC3339)})
	raw, err := passkey.Encode(stored)
	if err != nil {
		return response.Internal(c, err)
	}
	p.Passkeys = raw
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("auth: passkey added", "email", p.Email, "name", name)
	return c.JSON(fiber.Map{"ok": true})
}

// PasskeyList returns the current account's registered passkeys (no key material).
func (h *Handler) PasskeyList(c *fiber.Ctx) error {
	p, err := h.localSelfUser(c)
	if err != nil {
		return err
	}
	stored, err := passkey.Decode(p.Passkeys)
	if err != nil {
		return response.Internal(c, err)
	}
	out := make([]fiber.Map, 0, len(stored))
	for _, s := range stored {
		out = append(out, fiber.Map{
			"id":       base64.RawURLEncoding.EncodeToString(s.Credential.ID),
			"name":     s.Name,
			"added_at": s.AddedAt,
		})
	}
	return c.JSON(fiber.Map{"passkeys": out})
}

// PasskeyDelete removes a passkey by its (base64url) credential id.
func (h *Handler) PasskeyDelete(c *fiber.Ctx) error {
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
	idBytes, err := base64.RawURLEncoding.DecodeString(c.Params("id"))
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, "invalid passkey id")
	}
	stored, err := passkey.Decode(p.Passkeys)
	if err != nil {
		return response.Internal(c, err)
	}
	kept := make([]passkey.Stored, 0, len(stored))
	removed := false
	for _, s := range stored {
		if bytes.Equal(s.Credential.ID, idBytes) {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	if !removed {
		return response.NotFound(c, "passkey not found")
	}
	raw, err := passkey.Encode(kept)
	if err != nil {
		return response.Internal(c, err)
	}
	p.Passkeys = raw
	if err := h.Store.Users.Upsert(c.UserContext(), p); err != nil {
		return response.Internal(c, err)
	}
	h.Runtime.Log.Info("auth: passkey removed", "email", p.Email)
	return c.JSON(fiber.Map{"ok": true})
}

// --- passwordless login (public) ---

func (h *Handler) passkeyLoginAvailable() bool {
	return h.Runtime.Config.Auth.Enabled && h.Runtime.Config.Auth.LocalLogin
}

// PasskeyLoginBegin starts a usernameless assertion (the browser shows the
// passkey picker; no email needed).
func (h *Handler) PasskeyLoginBegin(c *fiber.Ctx) error {
	if !h.passkeyLoginAvailable() {
		return response.Error(c, fiber.StatusNotImplemented, "passkey login not available")
	}
	svc, err := h.webauthnService(c)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	opts, sess, err := svc.BeginLogin()
	if err != nil {
		return response.Internal(c, err)
	}
	if err := h.setWebAuthnSession(c, waLoginCookie, sess); err != nil {
		return response.Internal(c, err)
	}
	return c.JSON(opts)
}

// PasskeyLoginFinish verifies the assertion, resolves the owning user by
// user handle, and mints the session. A passkey is phishing-resistant, so it
// completes sign-in on its own (no password/TOTP step).
func (h *Handler) PasskeyLoginFinish(c *fiber.Ctx) error {
	if !h.passkeyLoginAvailable() {
		return response.Error(c, fiber.StatusNotImplemented, "passkey login not available")
	}
	svc, err := h.webauthnService(c)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	sess, err := h.takeWebAuthnSession(c, waLoginCookie)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, "login session expired; start again")
	}
	ctx := c.UserContext()

	var matched *user.User
	resolve := func(rawID, userHandle []byte) (*passkey.User, error) {
		ps, err := h.Store.Users.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, pr := range ps {
			if len(pr.WebAuthnHandle) > 0 && bytes.Equal(pr.WebAuthnHandle, userHandle) {
				if !pr.Enabled {
					return nil, fmt.Errorf("user disabled")
				}
				stored, err := passkey.Decode(pr.Passkeys)
				if err != nil {
					return nil, err
				}
				matched = pr
				return &passkey.User{Handle: pr.WebAuthnHandle, Name: pr.Email, Display: pr.Name, Creds: passkey.Credentials(stored)}, nil
			}
		}
		return nil, fmt.Errorf("unknown passkey")
	}

	cred, _, err := svc.FinishLogin(resolve, *sess, c.Body())
	if err != nil || matched == nil {
		h.Runtime.Log.Warn("auth: passkey login failed", "client_ip", c.IP(), "err", err)
		return response.Unauthorized(c, "passkey authentication failed")
	}

	// Clone signal: the asserted sign count didn't advance past the stored one,
	// which per the WebAuthn spec means the credential may have been copied.
	// Refuse the login (don't persist the regressed count). Synced passkeys
	// (iCloud/Google) report a 0 counter and never trip this; it only catches a
	// regression on counter-incrementing hardware keys.
	if cred.Authenticator.CloneWarning {
		h.Runtime.Log.Warn("auth: passkey clone warning - login refused", "email", matched.Email, "client_ip", c.IP())
		return response.Unauthorized(c, "passkey authentication failed")
	}

	// Persist the updated sign count and last-login, then mint the session.
	h.persistPasskeyUse(ctx, matched, cred)

	exp := time.Now().Add(h.Runtime.SessionTTL)
	cookieValue, err := session.Sign(session.Claims{
		Subject: matched.Email,
		Email:   matched.Email,
		Name:    matched.Name,
		Role:    string(matched.Role),
	}, h.Runtime.SessionSecret, exp)
	if err != nil {
		return response.Internal(c, err)
	}
	session.Set(c, cookieValue, h.Runtime.SessionTTL, h.secure(c))
	h.Runtime.Log.Info("auth: passkey login", "email", matched.Email, "role", matched.Role, "client_ip", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// persistPasskeyUse saves the used credential's sign count and the user's
// last-login. Best-effort: a write failure is logged, not fatal to the login.
func (h *Handler) persistPasskeyUse(ctx context.Context, p *user.User, used *passkey.Credential) {
	stored, err := passkey.Decode(p.Passkeys)
	if err != nil {
		return
	}
	for i := range stored {
		if bytes.Equal(stored[i].Credential.ID, used.ID) {
			stored[i].Credential = *used
			break
		}
	}
	if raw, err := passkey.Encode(stored); err == nil {
		p.Passkeys = raw
	}
	p.LastLoginAt = ptr(time.Now().UTC())
	if err := h.Store.Users.Upsert(ctx, p); err != nil {
		h.Runtime.Log.Warn("auth: persisting passkey use failed", "email", p.Email, "err", err)
	}
}
