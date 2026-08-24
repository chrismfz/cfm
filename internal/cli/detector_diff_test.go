package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/detectors"
)

func writeDetectorTypesConfig(t *testing.T, extraSections ...string) string {
	t.Helper()
	var config strings.Builder
	config.WriteString("[global]\n")
	for _, typ := range detectors.RegisteredTypes() {
		if detectors.ConfigSectionOptional(typ) {
			continue
		}
		config.WriteString("\n[" + typ + "]\n")
	}
	for _, section := range extraSections {
		config.WriteString("\n[" + section + "]\n")
	}
	path := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(path, []byte(config.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertNoDetectorTypeDrift(t *testing.T, path string) {
	t.Helper()
	missing, extra, err := diffDetectorTypes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("missing=%v extra=%v, want no drift", missing, extra)
	}
}

func TestDiffDetectorTypesAllowsMissingOptionalBuiltin(t *testing.T) {
	assertNoDetectorTypeDrift(t, writeDetectorTypesConfig(t))
}

func TestDiffDetectorTypesAcceptsOptionalLegacyAlias(t *testing.T) {
	assertNoDetectorTypeDrift(t, writeDetectorTypesConfig(t, "api_abuse"))
}

func TestDiffDetectorTypesIgnoresLeniencySections(t *testing.T) {
	assertNoDetectorTypeDrift(t, writeDetectorTypesConfig(t, "ssh_auth.leniency", "api_abuse:old.leniency"))
}

func TestDiffDetectorTypesReportsUnknownLeniencySection(t *testing.T) {
	missing, extra, err := diffDetectorTypes(writeDetectorTypesConfig(t, "typo_detector.leniency"))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 || len(extra) != 1 || extra[0] != "typo_detector" {
		t.Fatalf("missing=%v extra=%v, want unknown leniency base reported", missing, extra)
	}
}
