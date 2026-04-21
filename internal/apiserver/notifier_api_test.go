package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/notify"
	webdet "cfm/internal/webdetector"
)

func adminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
	return r.WithContext(ctx)
}

func TestNotifierConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	putBody := map[string]any{
		"config": map[string]any{
			"notifier":  map[string]any{"enabled": true, "default_cooldown": "3m"},
			"dedupe":    map[string]any{"key": "{{.Kind}}", "cooldown": "1m"},
			"channels":  []map[string]any{{"id": "ops", "type": "slack", "enabled": true, "webhook_url": "https://example.test/hook"}},
			"detectors": map[string]any{"mysql": map[string]any{"notify": true, "channels": []string{"ops"}}},
		},
	}
	buf, _ := json.Marshal(putBody)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/notifier/config", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rr.Code, rr.Body.String())
	}

	if _, err := filepath.Abs(filepath.Join(dir, "notify.conf")); err != nil {
		t.Fatal(err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/config", nil)
	getRR := httptest.NewRecorder()
	mux.ServeHTTP(getRR, adminCtx(getReq))
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRR.Code, getRR.Body.String())
	}
	if !bytes.Contains(getRR.Body.Bytes(), []byte(`"ops"`)) {
		t.Fatalf("expected channel in GET response: %s", getRR.Body.String())
	}
}

func TestNotifierConfigRequiresAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, t.TempDir())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/config", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rr.Code)
	}
}

func TestNotifierTestEndpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := notify.AdminConfig{
		Notifier: notify.AdminNotifierConfig{Enabled: true},
		Channels: []notify.AdminChannelConfig{
			{ID: "missing-bin", Type: "sendmail", Enabled: true, Path: "/definitely/missing/sendmail", To: []string{"ops@example.test"}},
		},
	}
	if _, err := notify.SaveAdminConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := notify.Reload(dir); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	body := map[string]any{
		"channel":  "missing-bin",
		"detector": "mysql",
		"sample": map[string]any{
			"host": "db01.example.test",
		},
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/test", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"channel":"missing-bin"`)) {
		t.Fatalf("expected channel in response body: %s", rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"status":"failure"`)) {
		t.Fatalf("expected failure status in response body: %s", rr.Body.String())
	}
}

func TestNotifierMetricsEndpoint(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "notify.log.jsonl")
	cfg := notify.AdminConfig{
		Notifier: notify.AdminNotifierConfig{Enabled: true, JSONLPath: jsonl},
	}
	if _, err := notify.SaveAdminConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rows := []string{
		`{"time":"` + now.Add(-30*time.Minute).Format(time.RFC3339) + `","kind":"mysql","err":"","channel":"ops"}`,
		`{"time":"` + now.Add(-20*time.Minute).Format(time.RFC3339) + `","kind":"mysql","err":"smtp timeout","channels":["ops","pager"]}`,
		`{"time":"` + now.Add(-10*time.Minute).Format(time.RFC3339) + `","kind":"ssh","err":""}`,
		`{"time":"` + now.Add(-2*time.Hour).Format(time.RFC3339) + `","kind":"old","err":""}`,
	}
	if err := os.WriteFile(jsonl, []byte(strings.Join(rows, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/metrics?window=1h", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		Window     string         `json:"window"`
		Total      int            `json:"total_attempts"`
		Success    int            `json:"success_count"`
		Errors     int            `json:"error_count"`
		PerKind    map[string]int `json:"per_kind"`
		PerChannel map[string]int `json:"per_channel"`
		Cached     bool           `json:"cached"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	if payload.Window != "1h" {
		t.Fatalf("window=%q", payload.Window)
	}
	if payload.Total != 3 || payload.Success != 2 || payload.Errors != 1 {
		t.Fatalf("unexpected counts total=%d success=%d error=%d", payload.Total, payload.Success, payload.Errors)
	}
	if payload.PerKind["mysql"] != 2 || payload.PerKind["ssh"] != 1 {
		t.Fatalf("unexpected per kind: %#v", payload.PerKind)
	}
	if payload.PerChannel["ops"] != 2 || payload.PerChannel["pager"] != 1 {
		t.Fatalf("unexpected per channel: %#v", payload.PerChannel)
	}
	if payload.Cached {
		t.Fatalf("first request should not be cached")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/metrics?window=1h", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, adminCtx(req2))
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr2.Code, rr2.Body.String())
	}
	var payload2 struct {
		Cached bool `json:"cached"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &payload2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload2.Cached {
		t.Fatalf("second request should be cached")
	}
}

func TestNotifierMetricsInvalidWindow(t *testing.T) {
	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/metrics?window=2h", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}
