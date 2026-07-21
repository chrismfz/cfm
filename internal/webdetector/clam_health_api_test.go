package webdetector

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/clam"
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

// infections_24h is a windowed COUNT from the persisted history store, so it is
// reported even when no scanner is wired (available=false) — past infections
// survive a restart. Older-than-24h events are excluded.
func TestHandleClamHealth_Infections24h(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}
	now := time.Now()
	rec := func(host string, when time.Time) {
		e.RecordClamScanEvent(clam.ScanEvent{
			EventType: "clam_infected", Host: host, IP: "203.0.113.9",
			Signature: "Php.Malware.Agent", When: when,
		})
	}
	rec("a.example.com", now.Add(-1*time.Hour))
	rec("b.example.com", now.Add(-10*time.Hour))
	rec("c.example.com", now.Add(-30*time.Hour)) // outside the 24h window
	// A non-infection event must not be counted.
	e.appendHistory(HistoryEvent{TsUnix: now.Unix(), Type: "waf_trigger", Host: "a.example.com"})

	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	rr := get(mux, adminCtx(), "/api/v1/clam/health")
	if rr.Code != http.StatusOK {
		t.Fatalf("clam/health = %d", rr.Code)
	}
	var resp clamHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Infections24h != 2 {
		t.Fatalf("infections_24h = %d, want 2 (the two within 24h, not the 30h-old one or the waf_trigger)", resp.Infections24h)
	}
}
