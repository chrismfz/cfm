package apiserver

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"cfm/internal/detconf"
)

// missing_sections/missing_keys must consult the MERGED view: a feature the
// operator adopted via a detectors.d overlay is active, not missing — while
// value_diffs stay base-vs-stock (the overlay's override must not count).
func TestDetectorsDriftReportMergedMissing(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "detectors.conf")
	if err := os.WriteFile(livePath, []byte("[ssh_auth]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "detectors.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	overlay := "[waf_security]\nENABLED = 1\n\n[ssh_auth]\nAUTHFAIL_IP = 4\n"
	if err := os.WriteFile(filepath.Join(dir, "detectors.d", "10-local.conf"), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}

	stock := detconf.Sections{ByName: map[string]detconf.KV{
		"global":       {},
		"ssh_auth":     {"ENABLED": "1", "AUTHFAIL_IP": "8"},
		"waf_security": {"ENABLED": "1"},
	}}
	liveSec, err := detconf.ReadSectionsFile(livePath)
	if err != nil {
		t.Fatal(err)
	}

	rep, overlayErr := detectorsDriftReport(stock, liveSec, livePath)
	if overlayErr != "" {
		t.Fatalf("overlay read failed: %s", overlayErr)
	}
	if len(rep.MissingSections) != 0 {
		t.Fatalf("overlay-adopted section still missing: %v", rep.MissingSections)
	}
	if len(rep.MissingKeys) != 0 {
		t.Fatalf("overlay-provided key still missing: %v", rep.MissingKeys)
	}
	// The overlay overrides AUTHFAIL_IP (8 → 4), but value drift is a
	// base-vs-stock comparison — base matches stock, so no diffs.
	if rep.ValueDiffs != 0 {
		t.Fatalf("overlay override must not count as value drift: %d", rep.ValueDiffs)
	}
}

func TestDiffDetectorsConfigIgnoresOptionalCFMEndpointsFamily(t *testing.T) {
	stock := detconf.Sections{ByName: map[string]detconf.KV{
		"global":                 {},
		"cfm_endpoints":          {"ENABLED": "1"},
		"cfm_endpoints:site":     {"WINDOW": "2m"},
		"cfm_endpoints.leniency": {"BLOCK": "15m"},
		"required_detector":      {"ENABLED": "1"},
	}}
	live := detconf.Sections{ByName: map[string]detconf.KV{
		"global":                 {},
		"api_abuse":              {"ENABLED": "1"},
		"api_abuse:old":          {"WINDOW": "9m"},
		"api_abuse:old.leniency": {"BLOCK": "5m"},
		"operator_extra":         {"ENABLED": "1"},
	}}
	rep := diffDetectorsConfig(stock, live)
	if !reflect.DeepEqual(rep.MissingSections, []string{"required_detector"}) {
		t.Fatalf("MissingSections=%v, want required_detector only", rep.MissingSections)
	}
	if !reflect.DeepEqual(rep.ExtraSections, []string{"operator_extra"}) {
		t.Fatalf("ExtraSections=%v, want operator_extra only", rep.ExtraSections)
	}
}
