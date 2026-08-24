package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/detectors"
)

func TestDiffDetectorTypesAcceptsAliasAndOptionalBuiltin(t *testing.T) {
	var config strings.Builder
	config.WriteString("[global]\n")
	for _, typ := range detectors.RegisteredTypes() {
		if detectors.ConfigSectionOptional(typ) {
			continue
		}
		config.WriteString("\n[" + typ + "]\n")
	}
	config.WriteString("\n[api_abuse]\n")
	path := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(path, []byte(config.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	missing, extra, err := diffDetectorTypes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("missing=%v extra=%v, want no drift", missing, extra)
	}
}
