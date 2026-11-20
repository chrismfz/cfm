package dnat

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the panel DNAT's saved mode and priority at a temp dir for
// every test: a bare `cpanel on` / `status` reads them (CLAUDE.md §5, tests
// never touch the live /var/lib/cfm). Tests that need values set their own.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-dnat-test-")
	if err != nil {
		panic(err)
	}
	panelDNATModePath = filepath.Join(dir, "dnat_panel_mode")
	panelDNATPriorityPath = filepath.Join(dir, "dnat_panel_priority")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
