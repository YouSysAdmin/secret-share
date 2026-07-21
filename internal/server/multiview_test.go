package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
)

// doJSON runs a request with a JSON body through the app and returns the
// status code plus the decoded response body.
func doJSON(t *testing.T, srv *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.App().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestMultiView_EndToEnd: a secret created with views=3 reveals exactly three
// times; the first two come from the side record (with views_remaining), the
// last one burns, and a fourth attempt finds nothing.
func TestMultiView_EndToEnd(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	code, created := doJSON(t, srv, http.MethodPost, "/api/secrets",
		`{"ttl":"24h","ciphertext":"b3BhcXVl","views":3}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("create: want 2xx, got %d (%v)", code, created)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create returned no id: %v", created)
	}

	// meta reports the budget without consuming it.
	code, meta := doJSON(t, srv, http.MethodGet, "/api/secrets/"+id+"/meta", "")
	if code != http.StatusOK {
		t.Fatalf("meta: want 200, got %d", code)
	}
	if vr, _ := meta["views_remaining"].(float64); vr != 3 {
		t.Errorf("meta views_remaining: want 3, got %v", meta["views_remaining"])
	}

	for i := 1; i <= 3; i++ {
		code, body := doJSON(t, srv, http.MethodPost, "/api/secrets/"+id+"/reveal", "")
		if code != http.StatusOK {
			t.Fatalf("reveal %d: want 200, got %d (%v)", i, code, body)
		}
		if ct, _ := body["ciphertext"].(string); ct != "b3BhcXVl" {
			t.Errorf("reveal %d: wrong ciphertext %q", i, ct)
		}
		if i < 3 {
			if vr, _ := body["views_remaining"].(float64); int(vr) != 3-i {
				t.Errorf("reveal %d: views_remaining want %d, got %v", i, 3-i, body["views_remaining"])
			}
		}
	}

	if code, _ := doJSON(t, srv, http.MethodPost, "/api/secrets/"+id+"/reveal", ""); code != http.StatusNotFound {
		t.Errorf("4th reveal: want 404, got %d", code)
	}
	// meta reports a burned secret as gone (200 + exists:false) with no
	// lingering views_remaining.
	code, meta = doJSON(t, srv, http.MethodGet, "/api/secrets/"+id+"/meta", "")
	if exists, _ := meta["exists"].(bool); code == http.StatusOK && exists {
		t.Errorf("meta after burn: secret should be gone, got %v", meta)
	}
	if _, has := meta["views_remaining"]; has {
		t.Errorf("meta after burn: views_remaining should be dropped, got %v", meta)
	}
}

// TestMultiView_DefaultStaysOneTime: without a views field the secret burns on
// the first reveal, exactly as before the feature existed.
func TestMultiView_DefaultStaysOneTime(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	_, created := doJSON(t, srv, http.MethodPost, "/api/secrets",
		`{"ttl":"24h","ciphertext":"b3BhcXVl"}`)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create returned no id: %v", created)
	}

	if code, _ := doJSON(t, srv, http.MethodPost, "/api/secrets/"+id+"/reveal", ""); code != http.StatusOK {
		t.Fatalf("first reveal: want 200, got %d", code)
	}
	if code, _ := doJSON(t, srv, http.MethodPost, "/api/secrets/"+id+"/reveal", ""); code != http.StatusNotFound {
		t.Errorf("second reveal: want 404, got %d", code)
	}
}

// TestMultiView_RejectsOverBudget: a views request above secrets.max_views is
// rejected before the secret is created.
func TestMultiView_RejectsOverBudget(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	code, _ := doJSON(t, srv, http.MethodPost, "/api/secrets",
		`{"ttl":"24h","ciphertext":"b3BhcXVl","views":11}`)
	if code != http.StatusBadRequest {
		t.Errorf("views over max: want 400, got %d", code)
	}
}
