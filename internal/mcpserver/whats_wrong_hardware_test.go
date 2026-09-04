package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"cfm/internal/healthmodel"
)

// Drift guard: evalHardware parses the health snapshot's JSON, which is produced
// by marshaling healthmodel.HealthSnapshotV1. If the healthmodel ECC JSON tags
// ever change, this test fails instead of evalHardware silently reading zeros.
func TestWhatsWrong_ECCWireContract(t *testing.T) {
	snap := healthmodel.HealthSnapshotV1{
		Hardware: healthmodel.HardwareHealth{ECC: healthmodel.ECCHealth{
			Present:          true,
			Source:           "edac_sysfs",
			CorrectedTotal:   4,
			UncorrectedTotal: 2,
			DIMMs: []healthmodel.ECCDimm{
				{ID: "mc0/dimm1", Location: "mc#0ch#1", CorrectedCount: 4, UncorrectedCount: 2},
			},
		}},
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fs := evalHardware(body)
	c := findBy(fs, "hardware", sevCritical)
	if c == nil {
		t.Fatalf("wire contract broken: no critical from %s", body)
	}
	if !strings.Contains(c.Detail, "2 uncorrected") || !strings.Contains(c.Detail, "mc#0ch#1") {
		t.Errorf("critical detail from real snapshot wrong: %q", c.Detail)
	}
}

// Corrected ECC errors → a single hardware warning that names the worst DIMM and
// drills in with dmesg_tail.
func TestWhatsWrong_ECCCorrectedWarning(t *testing.T) {
	body := `{"hardware":{"ecc":{"present":true,"source":"edac_sysfs","corrected_total":7,"uncorrected_total":0,` +
		`"dimms":[{"id":"mc0/dimm0","label":"CPU0_DIMM_A1","corrected_count":7,"uncorrected_count":0}]}}}`
	fs := evalHardware([]byte(body))
	f := findBy(fs, "hardware", sevWarning)
	if f == nil {
		t.Fatalf("expected hardware warning, got %+v", fs)
	}
	if findBy(fs, "hardware", sevCritical) != nil {
		t.Fatalf("no critical expected when uncorrected=0: %+v", fs)
	}
	if !strings.Contains(f.Detail, "7 corrected") || !strings.Contains(f.Detail, "CPU0_DIMM_A1") {
		t.Errorf("detail missing count/dimm: %q", f.Detail)
	}
	if f.Tool != "dmesg_tail" || f.Args["grep"] != "Hardware Error" {
		t.Errorf("drilldown wrong: tool=%q args=%v", f.Tool, f.Args)
	}
}

// Uncorrected ECC → critical (and corrected also present → warning too).
func TestWhatsWrong_ECCUncorrectedCritical(t *testing.T) {
	body := `{"hardware":{"ecc":{"present":true,"source":"edac_sysfs","corrected_total":2,"uncorrected_total":1,` +
		`"dimms":[{"id":"mc0/dimm1","location":"mc#0channel#1slot#0","corrected_count":2,"uncorrected_count":1}]}}}`
	fs := evalHardware([]byte(body))
	c := findBy(fs, "hardware", sevCritical)
	if c == nil {
		t.Fatalf("expected hardware critical, got %+v", fs)
	}
	if !strings.Contains(c.Detail, "1 uncorrected") || !strings.Contains(c.Detail, "mc#0channel#1slot#0") {
		t.Errorf("critical detail wrong: %q", c.Detail)
	}
	// The critical subsumes the corrected warning — no redundant warning on the
	// same box (it already says "replace the module").
	if findBy(fs, "hardware", sevWarning) != nil {
		t.Errorf("corrected warning should be suppressed when a critical fires: %+v", fs)
	}
}

// No flag when EDAC is unreadable — unreadable is not "healthy".
func TestWhatsWrong_ECCAbsentNoFinding(t *testing.T) {
	if fs := evalHardware([]byte(`{"hardware":{"ecc":{"present":false}}}`)); len(fs) != 0 {
		t.Fatalf("absent ECC must not flag, got %+v", fs)
	}
	// Present but zero counts → clean box, no finding.
	if fs := evalHardware([]byte(`{"hardware":{"ecc":{"present":true,"corrected_total":0,"uncorrected_total":0}}}`)); len(fs) != 0 {
		t.Fatalf("zero-count ECC must not flag, got %+v", fs)
	}
	// Missing hardware block entirely (older snapshot) → no finding, no panic.
	if fs := evalHardware([]byte(`{"host":{}}`)); len(fs) != 0 {
		t.Fatalf("missing hardware block must not flag, got %+v", fs)
	}
}

// Attributed to no DIMM (AMD "noinfo") → still flags, just without a "worst:" suffix.
func TestWhatsWrong_ECCNoInfoNoDimmSuffix(t *testing.T) {
	body := `{"hardware":{"ecc":{"present":true,"corrected_total":3,"uncorrected_total":0,"dimms":[]}}}`
	f := findBy(evalHardware([]byte(body)), "hardware", sevWarning)
	if f == nil {
		t.Fatalf("expected warning")
	}
	if strings.Contains(f.Detail, "worst:") {
		t.Errorf("no DIMM attributed, should have no worst suffix: %q", f.Detail)
	}
}

// A critical uncorrected-ECC finding sorts ahead of a warning and above lower
// categories, via the full evaluator + ranking.
func TestWhatsWrong_ECCRankingEndToEnd(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"health", `{"host":{"load_avg_5":0.1,"cpu_threads":8},"hardware":{"ecc":{"present":true,"corrected_total":9,"uncorrected_total":2}}}`,
	))
	if got.Status != "issues" {
		t.Fatalf("status=%q want issues", got.Status)
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != sevCritical || got.Findings[0].Category != "hardware" {
		t.Fatalf("expected exactly one critical hardware finding (corrected subsumed): %+v", got.Findings)
	}
	if got.Sources["health"] != "ok" {
		t.Errorf("health source=%q", got.Sources["health"])
	}
}
