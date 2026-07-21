package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/YouSysAdmin/secret-share/internal/core/env"
)

// TestMetrics_RecordsRouteNotRawPath: with metrics enabled, requests are
// counted and labeled with the registered route pattern, so per-secret ids
// never become label values (cardinality + privacy).
func TestMetrics_RecordsRouteNotRawPath(t *testing.T) {
	srv, _, _ := newTestServer(t, env.AuthConfig{Enabled: false})

	req := httptest.NewRequest(http.MethodGet, "/api/secrets/some-secret-id/meta", nil)
	if _, err := srv.App().Test(req); err != nil {
		t.Fatalf("request: %v", err)
	}

	if srv.metrics == nil {
		t.Fatal("metrics not wired despite metrics.enabled")
	}
	mfs, err := srv.metrics.registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sawRoute bool
	for _, mf := range mfs {
		if mf.GetName() != "secret_share_http_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), "some-secret-id") {
					t.Errorf("raw path leaked into label %s=%s", l.GetName(), l.GetValue())
				}
				if l.GetName() == "route" && l.GetValue() == "/api/secrets/:id/meta" {
					sawRoute = true
				}
			}
		}
	}
	if !sawRoute {
		t.Errorf("expected a request counted under route /api/secrets/:id/meta")
	}
}
