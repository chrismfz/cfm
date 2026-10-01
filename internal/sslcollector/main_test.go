package sslcollector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/hostsecrets"
)

// TestMain points the collector's default cache dir and the edge snapshot at a
// temp dir for the whole package: tests build collectors from an empty Config,
// and New created the live /var/lib/cfm/sslcollector — the directory whose
// dump.json the edge workers load their certificates from. Tests that write a
// snapshot still point snapshotPathForTests at their own file. The token store
// (hostsecrets) is redirected too.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-sslcollector-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sslcollector TestMain:", err)
		os.Exit(1)
	}
	defaultCacheDir = filepath.Join(dir, "sslcollector")
	snapshotPathForTests = filepath.Join(defaultCacheDir, "dump.json")
	// The socket lifecycle resolves SSLCOLLECTOR_SOCK_TOKEN through the
	// per-host token store: never the live /var/lib/cfm/secrets.
	restoreSecrets := hostsecrets.SetDirForTest(filepath.Join(dir, "secrets"))
	code := m.Run()
	restoreSecrets()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
