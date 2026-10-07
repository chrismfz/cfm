package health

import (
	"context"
	"os"
	"testing"

	"cfm/internal/backupcheck"
)

// TestMain keeps every test in this package away from the host's real backup
// CLIs (jetbackup5api / virtualmin / pvesh) and /etc/webmin: BACKUP_ALERT is
// on by default, so a test that builds the detector from the stock config and
// calls RunOnce would otherwise run them (CLAUDE.md §5). A test that needs the
// check substitutes its own func.
func TestMain(m *testing.M) {
	backupCheckFunc = func(context.Context, backupcheck.Options) backupcheck.Status {
		return backupcheck.Status{}
	}
	os.Exit(m.Run())
}
