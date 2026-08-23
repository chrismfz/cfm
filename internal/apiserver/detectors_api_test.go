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

	"cfm/internal/detectorscfg"
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

func TestValidateDetectorDraftCustomFailRegexRules(t *testing.T) {
	cfg := detectorscfg.AdminConfig{
		Core: []detectorscfg.AdminSection{
			{
				Name: "custom:auth",
				Keys: map[string]string{
					"MATCH_TARGET": "ip",
				},
			},
		},
	}
	errs := validateDetectorDraft(cfg)
	if len(errs) == 0 {
		t.Fatalf("expected missing FAIL_REGEX error")
	}
	found := false
	for _, err := range errs {
		if strings.Contains(err.Path, "FAIL_REGEX") && err.Code == "required" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected FAIL_REGEX required error, got %+v", errs)
	}
}

func TestValidateDetectorDraftCustomPerRuleErrors(t *testing.T) {
	cfg := detectorscfg.AdminConfig{
		Core: []detectorscfg.AdminSection{
			{
				Name: "custom:auth",
				Keys: map[string]string{
					"MATCH_TARGET": "both",
					"FAIL_REGEX":   "(?P<ip>\\S+)\n[",
				},
			},
		},
	}
	errs := validateDetectorDraft(cfg)
	if len(errs) == 0 {
		t.Fatalf("expected validation errors")
	}
	var sawPerRule bool
	for _, err := range errs {
		if strings.Contains(err.Path, "FAIL_REGEX[") {
			sawPerRule = true
			break
		}
	}
	if !sawPerRule {
		t.Fatalf("expected per-rule FAIL_REGEX errors, got %+v", errs)
	}
}

// The save-time BLOCK validator must accept the SAME duration grammar the
// runtime's parseBlockPolicy does — including the days extension ("7d",
// "1d12h"). A stricter validator here turned a working config into a false
// "invalid enum/duration for BLOCK" on every UI save.
func TestValidateDetectorDraftBlockAcceptsDays(t *testing.T) {
	mk := func(block string) detectorscfg.AdminConfig {
		return detectorscfg.AdminConfig{
			Global: map[string]string{},
			Core: []detectorscfg.AdminSection{
				{
					Name: "postfix_security",
					Keys: map[string]string{"ENABLED": "1", "BLOCK": block},
				},
			},
		}
	}
	for _, good := range []string{"7d", "1d12h", "1.5d", "30m", "permanent"} {
		errs := validateDetectorDraft(mk(good))
		for _, e := range errs {
			if strings.Contains(e.Path, ".BLOCK") || strings.Contains(e.Message, "BLOCK") {
				t.Fatalf("BLOCK=%q rejected: %+v", good, errs)
			}
		}
	}
	for _, bad := range []string{"7x", "d7", ""} {
		errs := validateDetectorDraft(mk(bad))
		found := false
		for _, e := range errs {
			if strings.Contains(e.Path, ".BLOCK") {
				found = true
			}
		}
		if !found && bad != "" { // empty BLOCK may surface a required-key error instead
			t.Fatalf("BLOCK=%q should be rejected, got %+v", bad, errs)
		}
	}
}
