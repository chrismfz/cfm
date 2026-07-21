package webdetector

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

// /api/v1/clam/health is admin-only (global daemon state, not per-vhost) and
// still returns 200 with available=false when no scanner is wired, so the page
// renders a clean "not running" state. The global scan policy is surfaced from
// the mirrored config.
func TestHandleClamHealth_AdminOnlyAndPolicy(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(Config{
		TrafficRulesStorePath:     filepath.Join(dir, "r.json"),
		ChallengeExcludeStorePath: filepath.Join(dir, "c.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "w.json"),
		ClamScanOverrideStorePath: filepath.Join(dir, "o.json"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

	SetClamScanPolicy(true, true, false)
	t.Cleanup(func() { SetClamScanPolicy(false, false, false) })

	// Scoped tokens must be refused — this is box-level daemon state.
	if rr := get(mux, scopedCtx("x.example.com"), "/api/v1/clam/health"); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped clam/health = %d, want 403", rr.Code)
	}

	// Admin: 200, available=false (no manager wired in-test), global default surfaced.
	rr := get(mux, adminCtx(), "/api/v1/clam/health")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin clam/health = %d, want 200", rr.Code)
	}
	var resp clamHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Available {
		t.Fatal("available should be false when no clam manager is wired")
	}
	if !resp.GlobalScanDefault {
		t.Fatal("global_scan_default should reflect SetClamScanPolicy(_, true)")
	}
}
