package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/backupcheck"
)

// TestMain keeps every test in this package away from the host's real backup
// CLIs (jetbackup5api / virtualmin / pvesh) and /etc/webmin: BACKUP_ALERT is
// on by default, so a test that builds the detector from the stock config and
// calls RunOnce would otherwise run them, and write the published-state file
// under /var/lib/cfm (CLAUDE.md §5). A test that needs the
// check substitutes its own func.
func TestMain(m *testing.M) {
	backupCheckFunc = func(context.Context, backupcheck.Options) backupcheck.Status {
		return backupcheck.Status{}
	}
	dir, err := os.MkdirTemp("", "cfm-health-test")
	if err != nil {
		panic(err)
	}
	backupStatePath = filepath.Join(dir, "backup_published.json") // never /var/lib/cfm
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
