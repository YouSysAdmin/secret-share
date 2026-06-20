// Package session is the HMAC-signed cookie that remembers an authenticated user
// across requests. Stateless, no server-side store. Format:
// <b64url(json)>.<hex(hmac-sha256)>.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const CookieName = "share_session"

// LocalsKey is the c.Locals() key the auth middleware stores the verified
// *Claims under for the request. Centralized here so the middleware and any
// reader agree on the key without importing the server package.
const LocalsKey = "share_user"

// Claims is what we sign into the cookie: the identity subset the UI cares about,
// plus the cookie's own expiry.
type Claims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	// Role is the user's access level, baked in at login for the SPA to
	// render with. The server re-validates it against the user store on
	// every protected request, so it's not load-bearing for authorization.
	Role string `json:"role,omitempty"`
	Exp  int64  `json:"exp"`
}

// Sign returns the cookie value for claims with the given expiry.
func Sign(c Claims, secret []byte, exp time.Time) (string, error) {
	c.Exp = exp.Unix()
	body, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(b64))
	return b64 + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks the signature + expiry and returns the claims.
func Verify(cookie string, secret []byte) (*Claims, error) {
	parts := strings.Split(cookie, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed cookie")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad signature")
	}
	if !hmac.Equal(want, got) {
		return nil, fmt.Errorf("bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if time.Now().Unix() > c.Exp {
		return nil, fmt.Errorf("session expired")
	}
	return &c, nil
}

// Secure reports whether the client reaches us over TLS: either this hop is
// HTTPS (c.Protocol()) or server.behind_tls_proxy declares an external TLS
// terminator. The latter is needed because a front proxy overwrites
// X-Forwarded-Proto on its loopback hop, so a request that was TLS only up to an
// upstream proxy looks plain to c.Protocol().
func Secure(c *fiber.Ctx, behindTLSProxy bool) bool {
	return behindTLSProxy || c.Protocol() == "https"
}

// Set writes the session cookie. HttpOnly + SameSite=Lax; secure marks it Secure
// (see Secure()). Scoped to "/" since secret-share serves the whole app at root.
func Set(c *fiber.Ctx, value string, ttl time.Duration, secure bool) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		HTTPOnly: true,
		Secure:   secure,
		SameSite: "Lax",
	})
}

// Clear expires the cookie immediately. secure must match the attribute used
// when the cookie was set so the browser overwrites the same cookie.
func Clear(c *fiber.Ctx, secure bool) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   secure,
		SameSite: "Lax",
	})
}

// FromLocals returns the verified claims the auth middleware stored on the
// request (under LocalsKey), or nil if the route wasn't gated by requireAuth.
func FromLocals(c *fiber.Ctx) *Claims {
	cl, _ := c.Locals(LocalsKey).(*Claims)
	return cl
}

// FromCtx reads the session cookie from the request and verifies it.
// Returns (claims, true) on success, (nil, false) on any error so
// the caller can decide between "401" and "send to /signin".
func FromCtx(c *fiber.Ctx, secret []byte) (*Claims, bool) {
	v := c.Cookies(CookieName)
	if v == "" {
		return nil, false
	}
	claims, err := Verify(v, secret)
	if err != nil {
		return nil, false
	}
	return claims, true
}
