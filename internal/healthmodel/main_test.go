package healthmodel

import (
	"fmt"
	"os"
	"testing"

	"cfm/internal/hostsecrets"
)

// TestMain points the per-host token store at a temp dir: the challenge-token
// probe falls back to it, and a test must never read (or depend on) the live
// /var/lib/cfm/secrets of the host it runs on (CLAUDE.md §5).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-healthmodel-secrets-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	restore := hostsecrets.SetDirForTest(dir)
	code := m.Run()
	restore()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
