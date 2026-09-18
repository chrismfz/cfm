package detectorscfg

import (
	"os"
	"path/filepath"
	"testing"
)

func findOverride(overrides []Override, section, key string) (Override, bool) {
	for _, o := range overrides {
		if o.Section == section && o.Key == key {
			return o, true
		}
	}
	return Override{}, false
}

func sectionByName(secs []AdminSection, name string) (AdminSection, bool) {
	for _, s := range secs {
		if s.Name == name {
			return s, true
		}
	}
	return AdminSection{}, false
}

func TestLoadMergedAdminConfig_MergesAndAttributes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := `
[global]
ENRICH=1

[challenge_cookie_discard]
ENABLED = 1
MIN_SOLVES = 1
BLOCK = 6h

[ssh_auth]
IGNORE_NETS = 10.0.0.0/8

[webdetector]
HUMANITY_MIN_OBS = 500
MINORITY_PCT = 1.0
`
	if err := os.WriteFile(filepath.Join(dir, "detectors.conf"), []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	dropin := filepath.Join(dir, "detectors.d")
	if err := os.MkdirAll(dropin, 0o750); err != nil {
		t.Fatal(err)
	}
	overlay := `
[webdetector]
HUMANITY_MIN_OBS = 100
MINORITY_PCT = 5

[challenge_cookie_discard]
BLOCK = 24h

[ssh_auth]
IGNORE_NETS += 203.0.113.0/24

[custom_new]
ENABLED = 1
`
	if err := os.WriteFile(filepath.Join(dropin, "20-tuning.conf"), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := LoadMergedAdminConfig(dir)
	if err != nil {
		t.Fatalf("LoadMergedAdminConfig: %v", err)
	}
	if !m.Exists {
		t.Fatal("Exists = false, want true")
	}
	if len(m.OverlayFiles) != 1 || m.OverlayFiles[0] != "20-tuning.conf" {
		t.Fatalf("overlay_files = %v, want [20-tuning.conf]", m.OverlayFiles)
	}

	// Effective values: overlay wins.
	wd, ok := sectionByName(m.Config.Advanced, "webdetector")
	if !ok {
		t.Fatal("webdetector section missing from Advanced")
	}
	if wd.Keys["HUMANITY_MIN_OBS"] != "100" || wd.Keys["MINORITY_PCT"] != "5" {
		t.Fatalf("effective webdetector keys = %v, want HUMANITY_MIN_OBS=100 MINORITY_PCT=5", wd.Keys)
	}
	cd, ok := sectionByName(m.Config.Core, "challenge_cookie_discard")
	if !ok {
		t.Fatal("challenge_cookie_discard missing from Core")
	}
	if cd.Keys["BLOCK"] != "24h" {
		t.Fatalf("effective BLOCK = %q, want 24h", cd.Keys["BLOCK"])
	}
	// Overlay-only section adopted.
	if _, ok := sectionByName(m.Config.Core, "custom_new"); !ok {
		t.Error("overlay-only section custom_new missing from merged config")
	}
	// += append merged the lists.
	ssh, ok := sectionByName(m.Config.Core, "ssh_auth")
	if !ok {
		t.Fatal("ssh_auth missing from Core")
	}
	if ssh.Keys["IGNORE_NETS"] != "10.0.0.0/8, 203.0.113.0/24" {
		t.Fatalf("effective IGNORE_NETS = %q, want merged list", ssh.Keys["IGNORE_NETS"])
	}

	// Override attribution.
	if o, ok := findOverride(m.Overrides, "webdetector", "HUMANITY_MIN_OBS"); !ok {
		t.Error("no override for HUMANITY_MIN_OBS")
	} else if !o.InBase || o.Base != "500" || o.Effective != "100" || o.Source != "20-tuning.conf" || o.Append {
		t.Errorf("HUMANITY_MIN_OBS override = %+v", o)
	}
	if o, ok := findOverride(m.Overrides, "custom_new", "ENABLED"); !ok {
		t.Error("no override for overlay-only custom_new ENABLED")
	} else if o.InBase || o.Base != "" || o.Effective != "1" || o.Source != "20-tuning.conf" {
		t.Errorf("custom_new ENABLED override = %+v", o)
	}
	if o, ok := findOverride(m.Overrides, "ssh_auth", "IGNORE_NETS"); !ok {
		t.Error("no override for IGNORE_NETS")
	} else if !o.Append || o.Base != "10.0.0.0/8" || o.Effective != "10.0.0.0/8, 203.0.113.0/24" {
		t.Errorf("IGNORE_NETS override = %+v", o)
	}
	// Unchanged key must NOT appear as an override.
	if _, ok := findOverride(m.Overrides, "challenge_cookie_discard", "MIN_SOLVES"); ok {
		t.Error("MIN_SOLVES (unchanged) should not be an override")
	}
}

func TestLoadMergedAdminConfig_NoOverlaysParity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := "[webdetector]\nHUMANITY_MIN_OBS = 500\n"
	if err := os.WriteFile(filepath.Join(dir, "detectors.conf"), []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMergedAdminConfig(dir)
	if err != nil {
		t.Fatalf("LoadMergedAdminConfig: %v", err)
	}
	if len(m.Overrides) != 0 {
		t.Errorf("overrides = %v, want empty with no overlays", m.Overrides)
	}
	wd, ok := sectionByName(m.Config.Advanced, "webdetector")
	if !ok || wd.Keys["HUMANITY_MIN_OBS"] != "500" {
		t.Fatalf("merged base value wrong: %+v (ok=%v)", wd, ok)
	}
	if len(m.OverlayFiles) != 0 {
		t.Errorf("overlay_files = %v, want empty", m.OverlayFiles)
	}
}
