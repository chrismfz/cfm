package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/alerts"
)

func alertsTestMux(t *testing.T) (*http.ServeMux, *alerts.Store) {
	t.Helper()
	s, err := alerts.Open(filepath.Join(t.TempDir(), "alerts.db"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	prev := alerts.SetDefault(s)
	t.Cleanup(func() { alerts.SetDefault(prev); s.Close() })
	now := time.Now()
	for i, r := range []alerts.Record{
		{TsUnix: now.Add(-3 * time.Hour).Unix(), Kind: "WAF/SQLI", IP: "31.217.169.106", CountryISO: "GR", ASN: "AS6799 OTEnet", Delivery: alerts.DeliveryNotified},
		{TsUnix: now.Add(-2 * time.Hour).Unix(), Kind: "WAF/SQLI", IP: "79.103.201.90", CountryISO: "GR", ASN: "AS1241 Nova", Delivery: alerts.DeliveryDeduped},
		{TsUnix: now.Add(-1 * time.Hour).Unix(), Kind: "MODSEC/403", IP: "168.144.246.79", CountryISO: "SG", Delivery: alerts.DeliveryNotifierOff},
		{TsUnix: now.Add(-50 * time.Hour).Unix(), Kind: "PORTSCAN", IP: "203.0.113.5", Delivery: alerts.DeliveryNotified},
	} {
		r.EventID = string(rune('a' + i))
		s.Add(r)
	}
	s.Flush()
	mux := http.NewServeMux()
	RegisterAlertsEndpoints(mux)
	return mux, s
}

func getJSON(t *testing.T, mux *http.ServeMux, path string, admin bool, wantCode int) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if admin {
		req = adminCtx(req)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != wantCode {
		t.Fatalf("%s: code %d, want %d: %s", path, rr.Code, wantCode, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out
}

func TestAlertsEndpointsAreAdminOnly(t *testing.T) {
	mux, _ := alertsTestMux(t)
	for _, p := range []string{"/api/v1/alerts", "/api/v1/alerts/summary", "/api/v1/alerts/stats"} {
		getJSON(t, mux, p, false, http.StatusForbidden)
	}
}

func TestAlertsList(t *testing.T) {
	mux, _ := alertsTestMux(t)
	out := getJSON(t, mux, "/api/v1/alerts?country=gr&category=WAF", true, http.StatusOK)
	if rows := out["rows"].([]any); len(rows) != 2 {
		t.Fatalf("rows: %v", out)
	}
	out = getJSON(t, mux, "/api/v1/alerts?limit=1", true, http.StatusOK)
	if out["has_more"] != true || out["next_cursor"] == "" {
		t.Fatalf("paging: %v", out)
	}
	next := getJSON(t, mux, "/api/v1/alerts?limit=5&cursor="+out["next_cursor"].(string), true, http.StatusOK)
	if rows := next["rows"].([]any); len(rows) != 2 {
		t.Fatalf("second page (24h window): %v", next)
	}
	if rows := getJSON(t, mux, "/api/v1/alerts?hours=72", true, http.StatusOK)["rows"].([]any); len(rows) != 4 {
		t.Fatalf("72h window: %d rows", len(rows))
	}
	getJSON(t, mux, "/api/v1/alerts?cursor=nope", true, http.StatusBadRequest)
	getJSON(t, mux, "/api/v1/alerts?from=yesterday", true, http.StatusBadRequest)
}

func TestAlertsSummary(t *testing.T) {
	mux, _ := alertsTestMux(t)
	out := getJSON(t, mux, "/api/v1/alerts/summary?group_by=country,delivery", true, http.StatusOK)
	if out["total"].(float64) != 3 {
		t.Fatalf("total: %v", out)
	}
	groups := out["groups"].([]any)
	if len(groups) != 3 {
		t.Fatalf("groups: %v", groups)
	}
	getJSON(t, mux, "/api/v1/alerts/summary?group_by=secret", true, http.StatusBadRequest)
	stats := getJSON(t, mux, "/api/v1/alerts/stats", true, http.StatusOK)
	if stats["rows"].(float64) != 4 {
		t.Fatalf("stats: %v", stats)
	}
}

func TestAlertsWithoutStore(t *testing.T) {
	prev := alerts.SetDefault(nil)
	defer alerts.SetDefault(prev)
	mux := http.NewServeMux()
	RegisterAlertsEndpoints(mux)
	getJSON(t, mux, "/api/v1/alerts", true, http.StatusServiceUnavailable)
}
