// internal/webdetector/http_api_scope_test.go
//
// Tests for Step 2: scope enforcement on monitoring endpoints.
// Guards:
//   Guard 2 — check ?host= param against scope (handleDrilldown, handleAnalyzeHost)
//   Guard 3 — block IP/global endpoints for scoped tokens entirely
//              (handleHotIPs, handleIPShort, handleIPDrilldown, handleAnalyzeIP)

package webdetector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// newMonitoringTestEngine creates an engine + mux for monitoring endpoint tests.
// We reuse the scopedCtx / adminCtx helpers from traffic_rules_api_handlers_test.go
// (same package, so they're available here automatically).
func newMonitoringTestEngine(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	e := NewEngine(Config{
		TrafficRulesStorePath: filepath.Join(t.TempDir(), "rules.json"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

func get(mux *http.ServeMux, ctx context.Context, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// ── Guard 3: IP / global endpoints must block scoped tokens ──────────────────

func TestMonitoring_HotIPs_ScopedBlocked(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// Admin: should pass (200)
	rr := get(mux, adminCtx(), "/api/v1/webdet/hot-ips")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin hot-ips: expected 200, got %d", rr.Code)
	}

	// Scoped: must be blocked (403)
	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/hot-ips")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped hot-ips: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_Summary_AdminOnly(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	rr := get(mux, adminCtx(), "/api/v1/webdet/summary")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin summary: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/summary")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped summary: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_IPShort_ScopedBlocked(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	rr := get(mux, adminCtx(), "/api/v1/webdet/ip-short")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin ip-short: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/ip-short")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped ip-short: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_IPDrilldown_ScopedBlocked(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	rr := get(mux, adminCtx(), "/api/v1/webdet/ip-drilldown?ip=1.2.3.4")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin ip-drilldown: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/ip-drilldown?ip=1.2.3.4")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped ip-drilldown: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_AccessRecent_ScopedBlocked(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// access-recent exposes requests across ALL vhosts → admin-only.
	rr := get(mux, adminCtx(), "/api/v1/webdet/access-recent?ip=1.2.3.4")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin access-recent: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/access-recent?host=example.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped access-recent: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_AnalyzeIP_ScopedBlocked(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// Admin: 200 (may return empty result if no log, but not 403)
	rr := get(mux, adminCtx(), "/api/v1/webdet/analyze-ip?ip=1.2.3.4")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin analyze-ip: should not be 403")
	}

	// Scoped: 403
	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/analyze-ip?ip=1.2.3.4")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped analyze-ip: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Guard 2: host-param endpoints filter by scope ────────────────────────────

func TestMonitoring_Drilldown_ScopeCheck(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// Admin can drilldown any host
	rr := get(mux, adminCtx(), "/api/v1/webdet/drilldown?host=any.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin drilldown: expected 200, got %d", rr.Code)
	}

	// Scoped token: own host allowed
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/drilldown?host=mysite.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped drilldown own: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped token: other host blocked
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/drilldown?host=other.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped drilldown other: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_AnalyzeHost_ScopeCheck(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// Admin: passes (result may be empty but not forbidden)
	rr := get(mux, adminCtx(), "/api/v1/webdet/analyze-host?host=any.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin analyze-host: should not be 403")
	}

	// Scoped: own host passes
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/analyze-host?host=mysite.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped analyze-host own: expected not-403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped: other host blocked
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/analyze-host?host=competitor.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped analyze-host other: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_HostAccessHistory_ScopeCheck(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// Admin: passes (result may be empty but not forbidden)
	rr := get(mux, adminCtx(), "/api/v1/webdet/host-access-history?host=any.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin host-access-history: should not be 403")
	}

	// Scoped: own host passes the scope gate (a non-403 error is fine here —
	// the test engine has no edge access log for ScanHost to read)
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/host-access-history?host=mysite.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped host-access-history own: expected not-403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped: other host blocked (fail-closed)
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/host-access-history?host=competitor.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped host-access-history other: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped + merge_www: the www/bare TWIN is a separate vhost key and must
	// be in scope too — otherwise merge would leak an out-of-scope host's data.
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/webdet/host-access-history?host=mysite.com&merge_www=1")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped host-access-history merge_www out-of-scope twin: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Guard 1: list endpoints filter rows for scoped tokens ────────────────────

func TestMonitoring_TopShort_ScopedFilters(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	// Both admin and scoped return 200 — scoped just gets fewer rows
	rr := get(mux, adminCtx(), "/api/v1/webdet/top-short")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin top-short: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/top-short")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped top-short: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_Suspicious_ScopedFilters(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	rr := get(mux, adminCtx(), "/api/v1/webdet/suspicious")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin suspicious: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/suspicious")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped suspicious: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_LongTop_ScopedFilters(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	rr := get(mux, adminCtx(), "/api/v1/webdet/long-top")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin long-top: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/long-top")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped long-top: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMonitoring_ScopedHostVhostInjectionRejected(t *testing.T) {
	_, mux := newMonitoringTestEngine(t)

	tests := []struct {
		name string
		path string
	}{
		{name: "top-short vhosts", path: "/api/v1/webdet/top-short?vhosts=other.com"},
		{name: "suspicious vhosts", path: "/api/v1/webdet/suspicious?vhosts=other.com"},
		{name: "long-top vhosts", path: "/api/v1/webdet/long-top?vhosts=other.com"},
		{name: "drilldown host", path: "/api/v1/webdet/drilldown?host=other.com"},
		{name: "analyze-host host", path: "/api/v1/webdet/analyze-host?host=other.com"},
		{name: "vhosts vhost", path: "/api/v1/webdet/vhosts?vhost=other.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := get(mux, scopedCtx("mysite.com"), tc.path)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for scoped injection, got %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
