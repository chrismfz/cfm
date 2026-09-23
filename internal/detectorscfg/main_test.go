package detectorscfg

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the live-config fallback (systemConfigPath) at a file that
// does not exist, for the whole package: the real one is a package conffile on
// every node, and tests passing their own cfgDir must never read or save it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-detectorscfg-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "detectorscfg TestMain:", err)
		os.Exit(1)
	}
	systemConfigPath = filepath.Join(dir, "absent", filepath.Base(systemConfigPath))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
