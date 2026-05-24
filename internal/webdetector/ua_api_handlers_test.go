package webdetector

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestEngineUA(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	e := NewEngine(Config{
		Every:                 5 * time.Second,
		Window:                2 * time.Minute,
		TrafficRulesStorePath: filepath.Join(dir, "tr.json"),
		UAEmergencyStorePath:  filepath.Join(dir, "ua.json"),
		UAEmergencyAuditLog:   filepath.Join(dir, "ua.log"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

func uaDo(mux *http.ServeMux, ctx context.Context, method, path string, body []byte) *httptest.ResponseRecorder {
	var br *bytes.Reader
	if body != nil {
		br = bytes.NewReader(body)
	} else {
		br = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, br).WithContext(ctx)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestUAEmergencyAPI_AddListRemove(t *testing.T) {
	_, mux := newTestEngineUA(t)

	body, _ := json.Marshal(uaEmergencyPostBody{
		UA:         "facebookexternalhit/1.1",
		Action:     UAActionBlock,
		TTLSeconds: 600,
		Reason:     "ddos-like",
		By:         "operator-1",
	})
	rr := uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/ua-emergency", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST add status=%d body=%s", rr.Code, rr.Body.String())
	}
	var added UAEmergencyRule
	if err := json.Unmarshal(rr.Body.Bytes(), &added); err != nil {
		t.Fatal(err)
	}
	if added.UA != "facebookexternalhit" {
		t.Errorf("UA not normalized: %q", added.UA)
	}
	if added.CreatedBy != "operator-1" {
		t.Errorf("CreatedBy = %q, want operator-1", added.CreatedBy)
	}

	// List.
	rr = uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/ua-emergency", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET list status=%d", rr.Code)
	}
	var list []UAEmergencyRule
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}

	// Delete.
	rr = uaDo(mux, adminCtx(), http.MethodDelete, "/api/v1/webdet/ua-emergency?ua=facebookexternalhit/1.1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/ua-emergency", nil)
	json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Errorf("list after delete = %d, want 0", len(list))
	}
}

func TestUAEmergencyAPI_GoogleWarnList(t *testing.T) {
	_, mux := newTestEngineUA(t)

	// Without confirm: 409.
	body, _ := json.Marshal(uaEmergencyPostBody{
		UA:         "Googlebot/2.1",
		Action:     UAActionBlock,
		TTLSeconds: 600,
	})
	rr := uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/ua-emergency", body)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict, got %d body=%s", rr.Code, rr.Body.String())
	}

	// With confirm: 200.
	body, _ = json.Marshal(uaEmergencyPostBody{
		UA:         "googlebot",
		Action:     UAActionBlock,
		TTLSeconds: 600,
		Confirm:    true,
	})
	rr = uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/ua-emergency", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUAEmergencyAPI_TTLCap(t *testing.T) {
	_, mux := newTestEngineUA(t)

	// Way above cap → should be clamped to UAEmergencyMaxTTL.
	body, _ := json.Marshal(uaEmergencyPostBody{
		UA:         "semrushbot",
		Action:     UAActionThrottle,
		TTLSeconds: 24 * 3600,
	})
	rr := uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/ua-emergency", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var added UAEmergencyRule
	json.Unmarshal(rr.Body.Bytes(), &added)
	if got := added.ExpiresAt.Sub(added.CreatedAt); got != UAEmergencyMaxTTL {
		t.Errorf("TTL = %v, want capped %v", got, UAEmergencyMaxTTL)
	}
}

// An oversize POST body should return 413, not the generic 400 "invalid
// json body" — that distinction matters for operator tooling diagnosing
// "is my request too big" vs "is my JSON malformed".
func TestUAEmergencyAPI_OversizeBody(t *testing.T) {
	_, mux := newTestEngineUA(t)

	// 70 KiB payload, well over the 64 KiB cap. JSON-shaped so the only
	// failure mode is the body cap (not malformed-json).
	pad := strings.Repeat("a", 70*1024)
	body := []byte(`{"ua":"badbot","action":"block","ttl_seconds":600,"reason":"` + pad + `"}`)
	rr := uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/ua-emergency", body)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "too large") {
		t.Errorf("body missing 'too large' hint: %s", rr.Body.String())
	}
}

func TestUAEmergencyAPI_ScopedTokenForbidden(t *testing.T) {
	_, mux := newTestEngineUA(t)

	body, _ := json.Marshal(uaEmergencyPostBody{
		UA:         "ahrefsbot",
		Action:     UAActionBlock,
		TTLSeconds: 600,
	})
	rr := uaDo(mux, scopedCtx("example.com"), http.MethodPost, "/api/v1/webdet/ua-emergency", body)
	if rr.Code != http.StatusForbidden {
		t.Errorf("scoped POST status=%d, want 403", rr.Code)
	}

	rr = uaDo(mux, scopedCtx("example.com"), http.MethodGet, "/api/v1/webdet/ua-top", nil)
	if rr.Code != http.StatusForbidden {
		t.Errorf("scoped GET ua-top status=%d, want 403", rr.Code)
	}
}

func TestUAAPI_TopAndDrill(t *testing.T) {
	e, mux := newTestEngineUA(t)
	now := float64(time.Now().Unix())
	for i := 0; i < 5; i++ {
		e.ingest(LogRec{
			TS: now + float64(i), IP: "57.141.20.1", Host: "x.com",
			Method: "get", URI: "/", Status: 200,
			UA: "facebookexternalhit/1.1",
		}, "raw")
	}

	rr := uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/ua-top", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("ua-top status=%d", rr.Code)
	}
	var rows []UATopRow
	json.Unmarshal(rr.Body.Bytes(), &rows)
	if len(rows) == 0 || rows[0].UA != "facebookexternalhit" {
		t.Fatalf("ua-top wrong shape: %+v", rows)
	}

	rr = uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/ua-drill?ua=facebookexternalhit", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("ua-drill status=%d", rr.Code)
	}
	var d UADetail
	json.Unmarshal(rr.Body.Bytes(), &d)
	if d.Reqs != 5 {
		t.Errorf("drill Reqs=%d want 5", d.Reqs)
	}
}
