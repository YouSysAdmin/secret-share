package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"

	paoidc "github.com/YouSysAdmin/secret-share/internal/core/oidc"
	"github.com/YouSysAdmin/secret-share/internal/core/response"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

// oidcButtons returns the {id,label} list the login page renders one button per.
// Empty when no providers are configured.
func (h *Handler) oidcButtons() []fiber.Map {
	if h.Runtime.OIDC == nil {
		return []fiber.Map{}
	}
	btns := h.Runtime.OIDC.Buttons()
	out := make([]fiber.Map, 0, len(btns))
	for _, b := range btns {
		out = append(out, fiber.Map{"id": b.ID, "label": b.Label})
	}
	return out
}

// stateCookiePath scopes the OIDC state cookie to one provider's callback so the
// browser only returns it there.
func stateCookiePath(providerID string) string {
	return "/api/auth/oidc/" + providerID + "/callback"
}

// OIDCStart begins the SSO flow for the :provider in the path: mints
// state/nonce/PKCE (bound to the provider), sets the state cookie, redirects to
// the IdP.
func (h *Handler) OIDCStart(c *fiber.Ctx) error {
	prov, ok := h.provider(c)
	if !ok {
		return response.NotFound(c, "unknown sso provider")
	}
	redirectURL, cookieValue, err := prov.Authorize(h.Runtime.SessionSecret)
	if err != nil {
		return response.Internal(c, err)
	}
	c.Cookie(&fiber.Cookie{
		Name:     paoidc.StateCookie,
		Value:    cookieValue,
		Path:     stateCookiePath(prov.ID()),
		Expires:  time.Now().Add(paoidc.StateCookieTTL),
		HTTPOnly: true,
		Secure:   h.secure(c),
		SameSite: "Lax",
	})
	return c.Redirect(redirectURL, http.StatusFound)
}

// OIDCCallback finishes the SSO flow: validates state (cross-checking the
// provider), exchanges the code, verifies the ID token, checks the allowlist,
// then mints the session cookie and redirects to /.
func (h *Handler) OIDCCallback(c *fiber.Ctx) error {
	prov, ok := h.provider(c)
	if !ok {
		return response.NotFound(c, "unknown sso provider")
	}

	// Clear the state cookie regardless of outcome - it's single-use.
	defer c.Cookie(&fiber.Cookie{
		Name: paoidc.StateCookie, Value: "", Path: stateCookiePath(prov.ID()),
		Expires: time.Unix(0, 0), MaxAge: -1, HTTPOnly: true,
		Secure: h.secure(c), SameSite: "Lax",
	})

	if errStr := c.Query("error"); errStr != "" {
		return h.ssoFail(c, "sso_idp_error", "oidc: idp returned error",
			"error", errStr, "description", c.Query("error_description"))
	}
	state := c.Query("state")
	code := c.Query("code")
	if state == "" || code == "" {
		return h.ssoFail(c, "sso_bad_callback", "oidc: callback missing state/code params")
	}
	stateCookie := c.Cookies(paoidc.StateCookie)
	if stateCookie == "" {
		return h.ssoFail(c, "sso_state_missing", "oidc: state cookie missing (expired or cleared)")
	}

	claims, err := prov.Exchange(c.Context(), h.Runtime.SessionSecret, state, code, stateCookie)
	if err != nil {
		return h.ssoFail(c, "sso_token_invalid", "oidc: exchange failed", "err", err)
	}
	groups, err := prov.Admit(claims)
	if err != nil {
		return h.ssoFail(c, "sso_access_denied", "oidc: admit failed",
			"sub", claims.Subject, "email", claims.Email, "err", err)
	}

	// Role comes from the IdP's groups (re-applied every login); provision or
	// update the user keyed by email.
	p, err := h.provisionOIDC(c.UserContext(), prov, claims, groups)
	if err != nil {
		return h.ssoFail(c, "sso_access_denied", "oidc: provision failed",
			"sub", claims.Subject, "email", claims.Email, "err", err)
	}

	exp := time.Now().Add(h.Runtime.SessionTTL)
	cookieValue, err := session.Sign(session.Claims{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Groups:  groups,
		Role:    string(p.Role),
	}, h.Runtime.SessionSecret, exp)
	if err != nil {
		return h.ssoFail(c, "sso_internal", "oidc: session sign failed", "err", err)
	}
	session.Set(c, cookieValue, h.Runtime.SessionTTL, h.secure(c))
	h.Runtime.Log.Info("auth: oidc login", "provider", prov.ID(), "sub", claims.Subject, "email", claims.Email, "role", p.Role)
	// Back to /signin (not /): the SPA there sees the now-valid session and
	// forwards to the client-side return-to (e.g. the secret link the user
	// originally followed, whose #key never left the browser).
	return c.Redirect("/signin", http.StatusFound)
}

// provider looks up the registry provider named by the :provider path param.
func (h *Handler) provider(c *fiber.Ctx) (*paoidc.Provider, bool) {
	if h.Runtime.OIDC == nil {
		return nil, false
	}
	return h.Runtime.OIDC.Get(c.Params("provider"))
}

// provisionOIDC creates or updates the user for an admitted OIDC login.
// Role and access are re-evaluated every login (IdP groups win). A pinned
// user (CLI-created admin or one matched by admin_emails) always stays
// admin, so an IdP misconfiguration can't strip the last admin. Otherwise, when
// no rule granted a role and default_role is "none", the login is DENIED: the
// user was admitted (by email/domain) but belongs to no admin/user group. A
// disabled user is rejected so a disable takes effect immediately.
func (h *Handler) provisionOIDC(ctx context.Context, prov *paoidc.Provider, claims *paoidc.Claims, groups []string) (*user.User, error) {
	role, pinned, ok := prov.RoleFor(claims, groups)

	p, err := h.Store.Users.Get(ctx, claims.Email)
	if err != nil {
		return nil, err
	}
	if p != nil && !p.Enabled {
		return nil, fmt.Errorf("user %q is disabled", claims.Email)
	}
	pinnedNow := pinned || (p != nil && p.Pinned)
	if !ok && !pinnedNow {
		return nil, fmt.Errorf("access denied: %q matched no admin/user group and default_role is \"none\"", claims.Email)
	}
	if p == nil {
		p = &user.User{Email: user.NormalizeEmail(claims.Email), Enabled: true, Source: user.SourceOIDC}
	}
	if p.Source == "" {
		p.Source = user.SourceOIDC
	}
	p.Subject = claims.Subject
	if claims.Name != "" {
		p.Name = claims.Name
	}
	if pinnedNow {
		p.Pinned = true
		p.Role = user.RoleAdmin
	} else {
		p.Role = role
	}
	p.LastLoginAt = ptr(time.Now().UTC())
	if err := h.Store.Users.Upsert(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// ssoFail logs an OIDC callback failure and redirects to the login page with an
// error code the SPA maps to a message - the callback is a top-level navigation,
// so a JSON error body would render as a bare blob.
func (h *Handler) ssoFail(c *fiber.Ctx, code, logMsg string, args ...any) error {
	h.Runtime.Log.Warn(logMsg, args...)
	return c.Redirect("/signin?err="+code, http.StatusFound)
}
