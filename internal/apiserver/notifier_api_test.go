package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
