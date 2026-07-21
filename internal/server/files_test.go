package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
	"github.com/YouSysAdmin/secret-share/internal/domain/files"
)

// TestFiles_EndToEnd: upload burns exactly once - meta doesn't consume, the
// first reveal returns the exact bytes, the second finds nothing.
func TestFiles_EndToEnd(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	blob := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	req := httptest.NewRequest(http.MethodPost, "/api/files", bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(files.TTLHeader, "1h")
	resp, err := srv.App().Test(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: want 200, got %d", resp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil || created.ID == "" {
		t.Fatalf("upload returned no id: %v", err)
	}

	// meta never burns.
	for i := 0; i < 2; i++ {
		code, meta := doJSON(t, srv, http.MethodGet, "/api/files/"+created.ID+"/meta", "")
		if code != http.StatusOK {
			t.Fatalf("meta: want 200, got %d", code)
		}
		if exists, _ := meta["exists"].(bool); !exists {
			t.Fatalf("meta %d: file should exist", i)
		}
		if size, _ := meta["size"].(float64); int(size) != len(blob) {
			t.Errorf("meta size: want %d, got %v", len(blob), meta["size"])
		}
	}

	// First reveal returns the exact bytes.
	rreq := httptest.NewRequest(http.MethodPost, "/api/files/"+created.ID+"/reveal", nil)
	rresp, err := srv.App().Test(rreq)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	defer rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("reveal: want 200, got %d", rresp.StatusCode)
	}
	got, _ := io.ReadAll(rresp.Body)
	if !bytes.Equal(got, blob) {
		t.Errorf("reveal bytes mismatch: want %v, got %v", blob, got)
	}

	// Burned: second reveal 404, meta reports gone.
	if code, _ := doJSON(t, srv, http.MethodPost, "/api/files/"+created.ID+"/reveal", ""); code != http.StatusNotFound {
		t.Errorf("second reveal: want 404, got %d", code)
	}
	if _, meta := doJSON(t, srv, http.MethodGet, "/api/files/"+created.ID+"/meta", ""); meta["exists"] != false {
		t.Errorf("meta after burn: want exists=false, got %v", meta)
	}
}

// TestFiles_SizeLimit: a blob over files.max_size_bytes is rejected with 413.
func TestFiles_SizeLimit(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	blob := bytes.Repeat([]byte{0x42}, 1024*1024+1)
	req := httptest.NewRequest(http.MethodPost, "/api/files", bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := srv.App().Test(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize upload: want 413, got %d", resp.StatusCode)
	}
}

// TestFiles_TTLCeiling: a ttl above secrets.max_ttl is rejected.
func TestFiles_TTLCeiling(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	req := httptest.NewRequest(http.MethodPost, "/api/files", bytes.NewReader([]byte{1}))
	req.Header.Set(files.TTLHeader, "9000h")
	resp, err := srv.App().Test(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("over-max ttl: want 400, got %d", resp.StatusCode)
	}
}
