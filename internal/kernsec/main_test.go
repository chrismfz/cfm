package kernsec

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the boot-arg rollback snapshots at a temp dir for the whole
// package. The backends read the boot config through their (fake, in tests)
// FS, but write the snapshot straight to the real path — and only when none
// exists. So a test run as root on a host that has never applied kernsec left
// a snapshot of TEST args at /var/lib/cfm/kernsec-*-cmdline.cfm-kernsec.bak;
// the host's first real apply then kept it instead of writing its own, and a
// later rollback would restore the test's args. Tests that need their own
// snapshot still override these per test.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-kernsec-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "kernsec TestMain:", err)
		os.Exit(1)
	}
	GRUBManagedBackupPath = filepath.Join(dir, "kernsec-grub-cmdline.cfm-kernsec.bak")
	ProxmoxManagedBackupPath = filepath.Join(dir, "kernsec-proxmox-cmdline.cfm-kernsec.bak")
	BLSBackupPath = filepath.Join(dir, "kernsec-bls-cmdline.cfm-kernsec.bak")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
