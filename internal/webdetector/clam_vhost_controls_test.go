package webdetector

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

// The vhost-controls API resolves per-vhost ClamAV state as
// globallyEnabled && (scanDefault XOR override-present). This pins the full
// truth table plus the clam_override_present field the UI toggle relies on to
// choose add-vs-remove.
func TestWebdetVhosts_ClamScanXOR(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(Config{
		TrafficRulesStorePath:     filepath.Join(dir, "rules.json"),
		ChallengeExcludeStorePath: filepath.Join(dir, "challenge_excludes.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "waf_excludes.json"),
		ClamScanOverrideStorePath: filepath.Join(dir, "clam_overrides.json"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

	const overridden = "opt.example.com" // has a clam override
	const plain = "plain.example.com"    // no clam override; present via challenge exclude
	if ok := e.ClamOverrideAdd("host", overridden, nil); !ok {
		t.Fatalf("clam override add failed")
	}
	// Give `plain` a reason to appear as a row (no traffic in a unit test).
	if ok := e.ChallengeExcludeAdd("host", plain, nil); !ok {
		t.Fatalf("challenge exclude add failed")
	}

	// Reset the package policy after the test so it can't leak into others.
	t.Cleanup(func() { SetClamScanPolicy(false, false) })

	rowsFor := func() map[string]webdetVhostControlRow {
		rr := get(mux, adminCtx(), "/api/v1/webdet/vhosts")
		if rr.Code != 200 {
			t.Fatalf("vhosts: status %d body=%s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Rows []webdetVhostControlRow `json:"rows"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out := map[string]webdetVhostControlRow{}
		for _, r := range resp.Rows {
			out[r.Host] = r
		}
		return out
	}

	cases := []struct {
		name                string
		global, scanDefault bool
		wantOverriddenScan  bool // clam_enabled for the overridden host
		wantPlainScan       bool // clam_enabled for the plain host
		wantToggleable      bool
	}{
		// default ON: override = opt-OUT.
		{"default-on", true, true, false, true, true},
		// default OFF: override = opt-IN.
		{"default-off", true, false, true, false, true},
		// clamd globally off: nothing scans, nothing toggles.
		{"global-off", false, true, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SetClamScanPolicy(tc.global, tc.scanDefault)
			rows := rowsFor()
			ov, ok := rows[overridden]
			if !ok {
				t.Fatalf("overridden host missing from rows")
			}
			pl, ok := rows[plain]
			if !ok {
				t.Fatalf("plain host missing from rows")
			}
			if ov.ClamEnabled != tc.wantOverriddenScan {
				t.Errorf("overridden clam_enabled = %v, want %v", ov.ClamEnabled, tc.wantOverriddenScan)
			}
			if pl.ClamEnabled != tc.wantPlainScan {
				t.Errorf("plain clam_enabled = %v, want %v", pl.ClamEnabled, tc.wantPlainScan)
			}
			if ov.ClamToggleable != tc.wantToggleable || pl.ClamToggleable != tc.wantToggleable {
				t.Errorf("clam_toggleable: overridden=%v plain=%v, want %v", ov.ClamToggleable, pl.ClamToggleable, tc.wantToggleable)
			}
			// The toggle-decision field must reflect actual override membership,
			// independent of the resolved scan state.
			if !ov.ClamOverridePresent {
				t.Errorf("overridden host: clam_override_present = false, want true")
			}
			if pl.ClamOverridePresent {
				t.Errorf("plain host: clam_override_present = true, want false")
			}
		})
	}
}
