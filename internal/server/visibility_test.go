package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/core/session"
	"github.com/YouSysAdmin/secret-share/internal/models/user"
)

const testSecret = "0123456789abcdef0123456789abcdef"

// TestPerSecretVisibility: in create mode, a secret marked private requires a
// session to preview, while a public (unmarked) secret stays open.
func TestPerSecretVisibility(t *testing.T) {
	srv, _, st := newTestServer(t, env.AuthConfig{
		Enabled:       true,
		Gate:          "create",
		LocalLogin:    true,
		SessionSecret: testSecret,
	})
	ctx := context.Background()

	// Mark one id private; leave another public.
	if err := st.Visibility.SetPrivate(ctx, "privid"); err != nil {
		t.Fatalf("SetPrivate: %v", err)
	}

	// Private secret, no session -> 401 (gated before the handler).
	if got := status(t, srv, http.MethodGet, "/api/secrets/privid/meta"); got != http.StatusUnauthorized {
		t.Errorf("private meta without session: want 401, got %d", got)
	}
	if got := status(t, srv, http.MethodPost, "/api/secrets/privid/reveal"); got != http.StatusUnauthorized {
		t.Errorf("private reveal without session: want 401, got %d", got)
	}

	// Public secret, no session -> not 401 (reaches the handler; 404 since absent).
	if got := status(t, srv, http.MethodGet, "/api/secrets/pubid/meta"); got == http.StatusUnauthorized {
		t.Errorf("public meta should stay open, got 401")
	}
}

// TestPerSecretVisibility_WithSession: a private secret previews once a valid
// session is presented.
func TestPerSecretVisibility_WithSession(t *testing.T) {
	srv, rt, st := newTestServer(t, env.AuthConfig{
		Enabled:       true,
		Gate:          "create",
		LocalLogin:    true,
		SessionSecret: testSecret,
	})
	ctx := context.Background()

	if err := st.Visibility.SetPrivate(ctx, "privid"); err != nil {
		t.Fatalf("SetPrivate: %v", err)
	}
	// A real, enabled user the session re-check will resolve.
	if err := st.Users.Upsert(ctx, &user.User{Email: "u@acme.com", Role: user.RoleUser, Enabled: true}); err != nil {
		t.Fatalf("Upsert user: %v", err)
	}
	cookie, err := session.Sign(session.Claims{Email: "u@acme.com", Role: "user"}, rt.SessionSecret, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/secrets/privid/meta", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: cookie})
	resp, err := srv.App().Test(req)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("private meta with valid session should pass the gate, got 401")
	}
}
