package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestNotifierBackupsListDiffRestore(t *testing.T) {
	dir := t.TempDir()
	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	save := func(cooldown string) {
		putBody := map[string]any{
			"config": map[string]any{
				"notifier": map[string]any{"enabled": true, "default_cooldown": cooldown},
			},
		}
		buf, _ := json.Marshal(putBody)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/notifier/config", bytes.NewReader(buf))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, adminCtx(req))
		if rr.Code != http.StatusOK {
			t.Fatalf("PUT status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	save("1m")
	save("2m")

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/backups", nil)
	listRR := httptest.NewRecorder()
	mux.ServeHTTP(listRR, adminCtx(listReq))
	if listRR.Code != http.StatusOK {
		t.Fatalf("backups list status=%d body=%s", listRR.Code, listRR.Body.String())
	}
	var listPayload struct {
		Backups []struct {
			ID string `json:"id"`
		} `json:"backups"`
	}
	if err := json.Unmarshal(listRR.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listPayload.Backups) == 0 || strings.TrimSpace(listPayload.Backups[0].ID) == "" {
		t.Fatalf("expected at least one backup id: %s", listRR.Body.String())
	}
	backupID := listPayload.Backups[0].ID

	diffReq := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/backups/diff?id="+backupID, nil)
	diffRR := httptest.NewRecorder()
	mux.ServeHTTP(diffRR, adminCtx(diffReq))
	if diffRR.Code != http.StatusOK {
		t.Fatalf("backups diff status=%d body=%s", diffRR.Code, diffRR.Body.String())
	}
	if !strings.Contains(diffRR.Body.String(), "\"diff\"") {
		t.Fatalf("expected diff payload, got: %s", diffRR.Body.String())
	}

	restoreBody := []byte(`{"id":"` + backupID + `"}`)
	restoreReq := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/backups/restore", bytes.NewReader(restoreBody))
	restoreRR := httptest.NewRecorder()
	mux.ServeHTTP(restoreRR, adminCtx(restoreReq))
	if restoreRR.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", restoreRR.Code, restoreRR.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "notify.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "default_cooldown = 1m") {
		t.Fatalf("restore did not roll back content:\n%s", string(raw))
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

func TestNotifierConfigMutationsPreserveUnknownAndRequireExplicitDeletes(t *testing.T) {
	dir := t.TempDir()
	initial := strings.TrimSpace(`
# preamble-preserved
[channel "ops"]
enabled = true
type = smtp
host = smtp.example.test
user = keep-user
pass = keep-pass
custom_channel_key = keep-me

[detector "mysql"]
notify = true
channels = ops
custom_detector_key = keep-det

[detector "ssh"]
notify = true
channels = ops
`) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "notify.conf"), []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	// 1) Partial channel/detector edits should not implicitly delete missing fields.
	putBody := map[string]any{
		"channel_mutations": []map[string]any{
			{"id": "ops", "host": "smtp2.example.test"},
		},
		"detector_mutations": []map[string]any{
			{"name": "mysql", "notify": false},
		},
	}
	buf, _ := json.Marshal(putBody)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/notifier/config", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("partial PUT status=%d body=%s", rr.Code, rr.Body.String())
	}
	afterPartial, err := os.ReadFile(filepath.Join(dir, "notify.conf"))
	if err != nil {
		t.Fatal(err)
	}
	txtPartial := string(afterPartial)
	for _, want := range []string{
		"user = keep-user",
		"pass = keep-pass",
		"custom_channel_key = keep-me",
		"custom_detector_key = keep-det",
		"[detector \"ssh\"]",
	} {
		if !strings.Contains(txtPartial, want) {
			t.Fatalf("expected %q preserved, got:\n%s", want, txtPartial)
		}
	}

	// 2) Explicit delete flags should remove only requested fields/blocks.
	putBody2 := map[string]any{
		"channel_mutations": []map[string]any{
			{"id": "ops", "delete_user": true},
		},
		"delete_detectors": []string{"ssh"},
	}
	buf2, _ := json.Marshal(putBody2)
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/notifier/config", bytes.NewReader(buf2))
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, adminCtx(req2))
	if rr2.Code != http.StatusOK {
		t.Fatalf("delete PUT status=%d body=%s", rr2.Code, rr2.Body.String())
	}
	afterDelete, err := os.ReadFile(filepath.Join(dir, "notify.conf"))
	if err != nil {
		t.Fatal(err)
	}
	txtDelete := string(afterDelete)
	if strings.Contains(txtDelete, "user = keep-user") {
		t.Fatalf("expected user to be explicitly deleted, got:\n%s", txtDelete)
	}
	if strings.Contains(txtDelete, "[detector \"ssh\"]") {
		t.Fatalf("expected ssh detector to be deleted, got:\n%s", txtDelete)
	}
	if !strings.Contains(txtDelete, "pass = keep-pass") {
		t.Fatalf("expected pass to remain without explicit delete, got:\n%s", txtDelete)
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
		"channel": "missing-bin",
		"payload": map[string]any{
			"host":     "db01.example.test",
			"severity": "warn",
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
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"latency":"`)) {
		t.Fatalf("expected latency in response body: %s", rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"correlation_id":"`)) {
		t.Fatalf("expected correlation_id in response body: %s", rr.Body.String())
	}
}

func TestNotifierStatusIncludesRuntimeMetadata(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "notify.log.jsonl")
	now := time.Now().UTC()
	if err := os.WriteFile(jsonl, []byte(`{"time":"`+now.Add(-time.Minute).Format(time.RFC3339Nano)+`","kind":"a"}`+"\n"+`{"time":"`+now.Format(time.RFC3339Nano)+`","kind":"b"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := notify.AdminConfig{
		Notifier: notify.AdminNotifierConfig{Enabled: true, JSONLPath: jsonl, MaxEntries: 100000, MaxAge: "30d"},
	}
	if _, err := notify.SaveAdminConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := notify.Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := notify.Reload(dir); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/status", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("status endpoint code=%d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode status payload: %v", err)
	}
	for _, key := range []string{"loaded_at", "config_path", "last_load_ok"} {
		if strings.TrimSpace(toString(got[key])) == "" && key != "last_load_ok" {
			t.Fatalf("expected %s in status payload: %s", key, rr.Body.String())
		}
	}
	if got["last_load_ok"] != true {
		t.Fatalf("expected last_load_ok=true, got %v", got["last_load_ok"])
	}
	if strings.TrimSpace(toString(got["reloaded_at"])) == "" {
		t.Fatalf("expected reloaded_at to be set after manual reload: %s", rr.Body.String())
	}
	retention, ok := got["retention"].(map[string]any)
	if !ok || retention["max_entries"] == nil || retention["max_age"] == nil {
		t.Fatalf("expected retention object in status payload: %s", rr.Body.String())
	}
	usage, ok := got["usage"].(map[string]any)
	if !ok {
		t.Fatalf("expected usage object in status payload: %s", rr.Body.String())
	}
	if int(usage["entries"].(float64)) != 2 {
		t.Fatalf("expected usage.entries=2, got %#v", usage["entries"])
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
		Window           string         `json:"window"`
		WindowStart      string         `json:"window_start"`
		WindowEnd        string         `json:"window_end"`
		GeneratedAt      string         `json:"generated_at"`
		Source           string         `json:"source"`
		TotalRowsScanned int            `json:"total_rows_scanned"`
		Total            int            `json:"total_attempts"`
		Success          int            `json:"success_count"`
		Errors           int            `json:"error_count"`
		PerKind          map[string]int `json:"per_kind"`
		PerChannel       map[string]int `json:"per_channel"`
		Degraded         bool           `json:"degraded"`
		Warnings         []string       `json:"warnings"`
		Cached           bool           `json:"cached"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	if payload.Window != "1h" {
		t.Fatalf("window=%q", payload.Window)
	}
	if payload.WindowStart == "" || payload.WindowEnd == "" {
		t.Fatalf("missing window bounds")
	}
	if payload.GeneratedAt == "" || payload.Source != "live" {
		t.Fatalf("expected generated_at/source to be set: %#v", payload)
	}
	if payload.TotalRowsScanned != 4 {
		t.Fatalf("expected scanned rows=4, got %d", payload.TotalRowsScanned)
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
	if !payload.Degraded || len(payload.Warnings) == 0 {
		t.Fatalf("expected degraded metrics due to missing channel fields: %#v", payload)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/metrics?window=1h", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, adminCtx(req2))
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr2.Code, rr2.Body.String())
	}
	var payload2 struct {
		Cached bool   `json:"cached"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &payload2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload2.Cached {
		t.Fatalf("second request should be cached")
	}
	if payload2.Source != "cache" {
		t.Fatalf("expected source=cache on cached response, got %q", payload2.Source)
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

func TestNotifierValidateEndpointReturnsStructuredErrors(t *testing.T) {
	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, t.TempDir())

	body := map[string]any{
		"channels": []map[string]any{
			{"id": "ops", "type": "smtp", "host": "", "from": "", "to": []string{}},
			{"id": "ops", "type": "pagerduty"},
			{"id": "slack-main", "type": "slack", "webhook_url": ""},
		},
		"detectors": map[string]any{
			"CLAM/INFECTED": map[string]any{
				"cooldown":     "xyz",
				"min_severity": "panic",
				"channels":     []string{"ops", "missing"},
			},
		},
		"notifier": map[string]any{"default_cooldown": "nope"},
		"dedupe":   map[string]any{"cooldown": "-1m"},
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/validate", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		OK     bool `json:"ok"`
		Errors []struct {
			Path string `json:"path"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if payload.OK {
		t.Fatalf("expected validation to fail: %s", rr.Body.String())
	}
	paths := map[string]bool{}
	for _, e := range payload.Errors {
		paths[e.Path] = true
	}
	for _, want := range []string{
		"notifier.default_cooldown",
		"dedupe.cooldown",
		"channels[0].host",
		"channels[0].from",
		"channels[0].to",
		"channels[1].id",
		"channels[1].type",
		"channels[2].webhook_url",
		"detectors['CLAM/INFECTED'].cooldown",
		"detectors['CLAM/INFECTED'].min_severity",
		"detectors['CLAM/INFECTED'].channels[1]",
	} {
		if !paths[want] {
			t.Fatalf("expected error path %q in response: %s", want, rr.Body.String())
		}
	}
}

func TestNotifierValidateEndpointAcceptsValidDraft(t *testing.T) {
	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, t.TempDir())

	body := map[string]any{
		"config": map[string]any{
			"notifier": map[string]any{"default_cooldown": "5m"},
			"dedupe":   map[string]any{"cooldown": "2m"},
			"channels": []map[string]any{
				{"id": "mail", "type": "sendmail", "path": "/usr/sbin/sendmail"},
				{"id": "ops", "type": "smtp", "host": "smtp.example.test", "from": "noreply@example.test", "to": []string{"ops@example.test"}},
				{"id": "slack-main", "type": "slack_webhook", "webhook_url": "https://example.test/webhook"},
			},
			"detectors": map[string]any{
				"CLAM/INFECTED": map[string]any{"cooldown": "30s", "min_severity": "critical", "channels": []string{"ops", "slack-main"}},
			},
		},
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/validate", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		OK     bool  `json:"ok"`
		Errors []any `json:"errors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if !payload.OK || len(payload.Errors) != 0 {
		t.Fatalf("expected valid payload, got %s", rr.Body.String())
	}
}

func TestNotifierPreviewEndpointReturnsUnifiedDiff(t *testing.T) {
	dir := t.TempDir()
	initial := notify.AdminConfig{
		Notifier: notify.AdminNotifierConfig{Enabled: true, DefaultCooldown: "5m"},
		Channels: []notify.AdminChannelConfig{
			{ID: "ops", Type: "slack", Enabled: true, WebhookURL: "https://example.test/old"},
		},
	}
	if _, err := notify.SaveAdminConfig(dir, initial); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	body := map[string]any{
		"config": map[string]any{
			"notifier": map[string]any{
				"enabled":          true,
				"default_cooldown": "3m",
			},
			"dedupe": map[string]any{
				"key":      "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}",
				"cooldown": "5m",
			},
			"channels": []map[string]any{
				{"id": "ops", "type": "slack", "enabled": true, "webhook_url": "https://example.test/new"},
			},
			"detectors": map[string]any{},
		},
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/preview", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		Diff string `json:"diff"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(payload.Diff, "--- notify.conf") || !strings.Contains(payload.Diff, "+++ notify.conf") {
		t.Fatalf("expected unified diff header, got: %s", payload.Diff)
	}
	if !strings.Contains(payload.Diff, "-default_cooldown = 5m") || !strings.Contains(payload.Diff, "+default_cooldown = 3m") {
		t.Fatalf("expected changed notifier line in diff, got: %s", payload.Diff)
	}
}

func TestNotifierHistoryEndpoint(t *testing.T) {
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
		`{"time":"` + now.Add(-5*time.Minute).Format(time.RFC3339Nano) + `","host":"db01","kind":"mysql","srcip":"1.1.1.1","asn":"13335","ptr":"one.example.test","reason":"slow","channel":"ops","err":""}`,
		`{"time":"` + now.Add(-450*time.Second).Format(time.RFC3339Nano) + `","host":"db01","kind":"NOTIFIER/TEST","srcip":"1.1.1.2","reason":"manual","channel":"ops","status":"success","latency":"10ms","correlation_id":"corr-1","err":""}`,
		`{"time":"` + now.Add(-4*time.Minute).Format(time.RFC3339Nano) + `","host":"db02","kind":"ssh","srcip":"2.2.2.2","asn":"64510","ptr":"attacker.example.test","reason":"bruteforce","channels":["pager"],"err":"smtp timeout"}`,
		`{"time":"` + now.Add(-3*time.Minute).Format(time.RFC3339Nano) + `","host":"db03","kind":"mysql","srcip":"3.3.3.3","reason":"deadlock","channel":"ops","err":""}`,
	}
	if err := os.WriteFile(jsonl, []byte(strings.Join(rows, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/history?limit=2&kind=mysql&channel=ops&status=success", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		Rows          []map[string]any `json:"rows"`
		HasMore       bool             `json:"has_more"`
		NextCursor    string           `json:"next_cursor"`
		TotalEstimate int              `json:"total_estimate"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	if len(payload.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(payload.Rows))
	}
	if payload.Rows[0]["kind"] != "mysql" || payload.Rows[1]["kind"] != "mysql" {
		t.Fatalf("unexpected kinds: %#v", payload.Rows)
	}
	if payload.Rows[0]["status"] != "success" {
		t.Fatalf("expected success status: %#v", payload.Rows[0])
	}
	if payload.HasMore {
		t.Fatalf("expected no more rows")
	}
	if payload.NextCursor != "" {
		t.Fatalf("expected empty next_cursor when has_more=false")
	}
	if payload.TotalEstimate != 2 {
		t.Fatalf("expected total_estimate=2, got %d", payload.TotalEstimate)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/history?limit=1&status=all&kind=NOTIFIER/TEST", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, adminCtx(req2))
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr2.Code, rr2.Body.String())
	}
	var p2 struct {
		Rows          []map[string]any `json:"rows"`
		HasMore       bool             `json:"has_more"`
		NextCursor    string           `json:"next_cursor"`
		TotalEstimate int              `json:"total_estimate"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &p2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(p2.Rows) != 1 || p2.HasMore || p2.NextCursor != "" {
		t.Fatalf("unexpected page-1 payload: %#v", p2)
	}
	if p2.TotalEstimate != 1 {
		t.Fatalf("expected total_estimate=1, got %d", p2.TotalEstimate)
	}
	if p2.Rows[0]["kind"] != "NOTIFIER/TEST" || p2.Rows[0]["correlation_id"] != "corr-1" {
		t.Fatalf("expected test history row with correlation id, got %#v", p2.Rows[0])
	}
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/history?limit=2&status=all", nil)
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, adminCtx(req3))
	if rr3.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr3.Code, rr3.Body.String())
	}
	var p3 struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rr3.Body.Bytes(), &p3); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(p3.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(p3.Rows))
	}
	cursor, ok := p3.Rows[1]["cursor"].(string)
	if !ok || cursor == "" {
		t.Fatalf("expected cursor on row: %#v", p3.Rows[1])
	}

	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/history?limit=10&status=all&cursor="+url.QueryEscape(cursor), nil)
	rr4 := httptest.NewRecorder()
	mux.ServeHTTP(rr4, adminCtx(req4))
	if rr4.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr4.Code, rr4.Body.String())
	}
	var p4 struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rr4.Body.Bytes(), &p4); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(p4.Rows) != 2 {
		t.Fatalf("expected 2 older rows, got %d (%#v)", len(p4.Rows), p4.Rows)
	}
	if got := p4.Rows[0]["srcip"]; got != "1.1.1.1" {
		t.Fatalf("expected first older row srcip=1.1.1.1, got %v", got)
	}

	from := now.Add(-4*time.Minute - 15*time.Second).Format(time.RFC3339Nano)
	to := now.Add(-3*time.Minute + 15*time.Second).Format(time.RFC3339Nano)
	req5 := httptest.NewRequest(http.MethodGet, "/api/v1/notifier/history?status=all&q=attacker&asn=64510&ptr=attacker.example.test&kind=ssh&channel=pager&src_ip=2.2.2.2&from="+url.QueryEscape(from)+"&to="+url.QueryEscape(to), nil)
	rr5 := httptest.NewRecorder()
	mux.ServeHTTP(rr5, adminCtx(req5))
	if rr5.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rr5.Code, rr5.Body.String())
	}
	var p5 struct {
		Rows          []map[string]any `json:"rows"`
		TotalEstimate int              `json:"total_estimate"`
	}
	if err := json.Unmarshal(rr5.Body.Bytes(), &p5); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(p5.Rows) != 1 || p5.TotalEstimate != 1 {
		t.Fatalf("expected one filtered row with total_estimate=1, got rows=%d total=%d", len(p5.Rows), p5.TotalEstimate)
	}
	if p5.Rows[0]["srcip"] != "2.2.2.2" || p5.Rows[0]["kind"] != "ssh" {
		t.Fatalf("unexpected filtered row: %#v", p5.Rows[0])
	}
}

func TestNotifierHistoryTruncateEndpoint(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "notify.log.jsonl")
	cfg := notify.AdminConfig{
		Notifier: notify.AdminNotifierConfig{Enabled: true, JSONLPath: jsonl},
	}
	if _, err := notify.SaveAdminConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonl, []byte("{\"time\":\"2026-01-01T00:00:00Z\"}\n{\"time\":\"2026-01-01T00:00:01Z\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterNotifierEndpoints(mux, dir)

	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/history/truncate", strings.NewReader(`{"confirmation":"NOPE"}`))
	badReq.Header.Set("Content-Type", "application/json")
	badRR := httptest.NewRecorder()
	mux.ServeHTTP(badRR, adminCtx(badReq))
	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("expected bad confirmation to fail with 400, got %d body=%s", badRR.Code, badRR.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifier/history/truncate", strings.NewReader(`{"confirmation":"TRUNCATE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CFM-Actor", "admin-ui")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtx(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("truncate status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload struct {
		OK           bool   `json:"ok"`
		DeletedCount int    `json:"deleted_count"`
		Actor        string `json:"actor"`
		Timestamp    string `json:"timestamp"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.OK || payload.DeletedCount != 2 || payload.Actor != "admin-ui" || payload.Timestamp == "" {
		t.Fatalf("unexpected truncate payload: %#v", payload)
	}
	info, err := os.Stat(jsonl)
	if err != nil {
		t.Fatalf("stat truncated file: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected truncated file size to be 0, got %d", info.Size())
	}
}
