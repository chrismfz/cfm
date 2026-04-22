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

	webdet "cfm/internal/webdetector"
)

func TestDetectorsConfigValidateSaveRestore(t *testing.T) {
	dir := t.TempDir()
	cfg := `[global]
DEFAULT_EVERY = 60s

[ssh_auth]
ENABLED = 1
EVERY = 20s
`
	if err := os.WriteFile(filepath.Join(dir, "detectors.conf"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterDetectorsEndpoints(mux, dir)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/detectors/config", nil)
	getRR := httptest.NewRecorder()
	mux.ServeHTTP(getRR, adminCtxDet(getReq))
	if getRR.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	var payload map[string]any
	_ = json.Unmarshal(getRR.Body.Bytes(), &payload)
	cfgObj := payload["config"].(map[string]any)
	core := cfgObj["core"].([]any)
	first := core[0].(map[string]any)
	keys := first["keys"].(map[string]any)
	keys["EVERY"] = "45s"

	buf, _ := json.Marshal(map[string]any{"config": cfgObj})
	valReq := httptest.NewRequest(http.MethodPost, "/api/v1/detectors/validate", bytes.NewReader(buf))
	valRR := httptest.NewRecorder()
	mux.ServeHTTP(valRR, adminCtxDet(valReq))
	if valRR.Code != http.StatusOK || !strings.Contains(valRR.Body.String(), `"ok":true`) {
		t.Fatalf("validate=%d %s", valRR.Code, valRR.Body.String())
	}

	saveReq := httptest.NewRequest(http.MethodPut, "/api/v1/detectors/config", bytes.NewReader(buf))
	saveRR := httptest.NewRecorder()
	mux.ServeHTTP(saveRR, adminCtxDet(saveReq))
	if saveRR.Code != http.StatusOK {
		t.Fatalf("save=%d %s", saveRR.Code, saveRR.Body.String())
	}
	if !strings.Contains(saveRR.Body.String(), "backup_id") {
		t.Fatalf("expected backup_id: %s", saveRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/detectors/backups", nil)
	listRR := httptest.NewRecorder()
	mux.ServeHTTP(listRR, adminCtxDet(listReq))
	if listRR.Code != http.StatusOK || !strings.Contains(listRR.Body.String(), "backups") {
		t.Fatalf("list=%d %s", listRR.Code, listRR.Body.String())
	}
}

func TestDetectorsCatalogEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	RegisterDetectorsEndpoints(mux, t.TempDir())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/detectors/catalog", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, adminCtxDet(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "catalog") {
		t.Fatalf("expected catalog payload: %s", rr.Body.String())
	}
}

func adminCtxDet(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
	return r.WithContext(ctx)
}
