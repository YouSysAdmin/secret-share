package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/database/boltkv"
	"github.com/YouSysAdmin/secret-share/internal/domain/store"
)

// newTestServer builds a real server (Fiber app + routes) backed by a temp bbolt
// store, for the given auth config. It also returns the Runtime + Store so tests
// can seed users / visibility directly.
func newTestServer(t *testing.T, auth env.AuthConfig) (*Server, *env.Runtime, *store.Store) {
	t.Helper()
	kv, err := boltkv.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = kv.Close() })

	cfg := &env.Config{
		Secrets: env.SecretsConfig{
			MaxSizeBytes: 65536,
			MaxTTL:       "168h",
			DefaultTTL:   "24h",
			AllowedTTLs:  []string{"24h"},
		},
		Auth: auth,
	}
	rt := &env.Runtime{
		Config:        cfg,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionSecret: []byte(auth.SessionSecret),
		SessionTTL:    time.Hour,
	}
	st := &store.Store{}
	boltkv.BindProvider(rt, st, kv)

	srv, err := New(Options{Runtime: rt, Store: st})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, rt, st
}

// status runs a request through the app and returns the response status code.
func status(t *testing.T, srv *Server, method, path string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	resp, err := srv.App().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestGate_PublicMode: auth disabled -> create/meta/reveal all reach the handler
// (never a 401).
func TestGate_PublicMode(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	if got := status(t, srv, http.MethodGet, "/api/secrets/nope/meta"); got == http.StatusUnauthorized {
		t.Errorf("public meta should not be gated, got 401")
	}
	if got := status(t, srv, http.MethodPost, "/api/secrets"); got == http.StatusUnauthorized {
		t.Errorf("public create should not be gated, got 401")
	}
	if got := status(t, srv, http.MethodPost, "/api/secrets/nope/reveal"); got == http.StatusUnauthorized {
		t.Errorf("public reveal should not be gated, got 401")
	}
}

// TestGate_CreateMode: auth enabled, gate=create -> create requires a session
// (401 without one); meta + reveal stay public.
func TestGate_CreateMode(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{
		Enabled:       true,
		Gate:          "create",
		LocalLogin:    true,
		SessionSecret: "0123456789abcdef0123456789abcdef",
	})

	if got := status(t, srv, http.MethodPost, "/api/secrets"); got != http.StatusUnauthorized {
		t.Errorf("create should be gated in create mode: want 401, got %d", got)
	}
	if got := status(t, srv, http.MethodGet, "/api/secrets/nope/meta"); got == http.StatusUnauthorized {
		t.Errorf("meta should stay public in create mode, got 401")
	}
	if got := status(t, srv, http.MethodPost, "/api/secrets/nope/reveal"); got == http.StatusUnauthorized {
		t.Errorf("reveal should stay public in create mode, got 401")
	}
}

// TestGate_AllMode: auth enabled, gate=all -> create, meta, AND reveal all
// require a session.
func TestGate_AllMode(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{
		Enabled:       true,
		Gate:          "all",
		LocalLogin:    true,
		SessionSecret: "0123456789abcdef0123456789abcdef",
	})

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/secrets"},
		{http.MethodGet, "/api/secrets/nope/meta"},
		{http.MethodPost, "/api/secrets/nope/reveal"},
	} {
		if got := status(t, srv, tc.method, tc.path); got != http.StatusUnauthorized {
			t.Errorf("%s %s should be gated in all mode: want 401, got %d", tc.method, tc.path, got)
		}
	}
}
