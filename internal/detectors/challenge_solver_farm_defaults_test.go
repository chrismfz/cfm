package detectors

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/solverfarm"
)

// The solver_farm subnet-spread defaults live once, in solverfarm (Default*).
// The register's template and the reference detectors.conf must say the
// same, or a fresh install and an upgraded one run different thresholds
// (2026-10-27: the fleet ran 180s / 15 / 15 by hand while the code shipped
// 60s / 40 / 40).
func TestSolverFarmDefaultsAgree(t *testing.T) {
	want := map[string]string{
		"WINDOW":      solverfarm.DefaultWindow.String(),
		"MIN_SUBNETS": strconv.Itoa(solverfarm.DefaultMinSubnets),
		"MIN_SOLVES":  strconv.Itoa(solverfarm.DefaultMinSolves),
	}
	var tmpl map[string]string
	for _, m := range meta.Catalog() {
		if m.TypeKey == "challenge_solver_farm" {
			tmpl = m.DefaultsTemplate
		}
	}
	if tmpl == nil {
		t.Fatal("challenge_solver_farm is not registered")
	}
	for k, v := range want {
		got := tmpl[k]
		if k == "WINDOW" {
			d, err := parseCfgDuration(got)
			if err != nil || d != solverfarm.DefaultWindow {
				t.Errorf("template %s = %q, want %s", k, got, v)
			}
			continue
		}
		if got != v {
			t.Errorf("template %s = %q, want %s", k, got, v)
		}
	}

	path := filepath.Join("..", "..", "configs", "detectors.conf")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("detectors.conf not found at %s: %v", path, err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatalf("ReadSectionsFile: %v", err)
	}
	sf, ok := secs.ByName["challenge_solver_farm"]
	if !ok {
		t.Fatal("[challenge_solver_farm] section missing from detectors.conf")
	}
	if got := kvDur(sf, "WINDOW", 0); got != solverfarm.DefaultWindow {
		t.Errorf("detectors.conf WINDOW = %s, want %s", got, solverfarm.DefaultWindow)
	}
	if got := kvInt(sf, "MIN_SUBNETS", -1); got != solverfarm.DefaultMinSubnets {
		t.Errorf("detectors.conf MIN_SUBNETS = %d, want %d", got, solverfarm.DefaultMinSubnets)
	}
	if got := kvInt(sf, "MIN_SOLVES", -1); got != solverfarm.DefaultMinSolves {
		t.Errorf("detectors.conf MIN_SOLVES = %d, want %d", got, solverfarm.DefaultMinSolves)
	}
}
