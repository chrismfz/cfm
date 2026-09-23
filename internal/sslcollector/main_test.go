package sslcollector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the collector's default cache dir and the edge snapshot at a
// temp dir for the whole package: tests build collectors from an empty Config,
// and New created the live /var/lib/cfm/sslcollector — the directory whose
// dump.json the edge workers load their certificates from. Tests that write a
// snapshot still point snapshotPathForTests at their own file.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-sslcollector-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sslcollector TestMain:", err)
		os.Exit(1)
	}
	defaultCacheDir = filepath.Join(dir, "sslcollector")
	snapshotPathForTests = filepath.Join(defaultCacheDir, "dump.json")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
