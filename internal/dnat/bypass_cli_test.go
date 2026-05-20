package dnat

import (
	"path/filepath"
	"testing"

	"cfm/internal/firewall"
)

// TestRunBypassCLI_UsageWhenNoArgs covers the early-usage exit when an
// operator runs `cfm dnat bypass` (or `cfm dnat cpanel bypass`) with no
// further subcommand. We use code==2 to match the convention used by
// other CLI dispatchers in this package (see runPanelCLI tests).
func TestRunBypassCLI_UsageWhenNoArgs(t *testing.T) {
	for _, scope := range []firewall.DNATBypassScope{firewall.DNATBypassScopeWeb, firewall.DNATBypassScopeCpanel} {
		code := runBypassCLI(nil, scope, nil)
		if code != 2 {
			t.Errorf("scope=%s: expected exit 2 for empty args, got %d", scope, code)
		}
	}
}

// TestRunBypassCLI_AddInvalidIPReturns2 checks the validation path: an
// unparseable target rejects with code 2 BEFORE touching the file or the
// firewall backend. We pass backend=nil to ensure no backend method is
// invoked along the failure path.
func TestRunBypassCLI_AddInvalidIPReturns2(t *testing.T) {
	dir := t.TempDir()
	prev := firewall.DNATBypassWebPath
	firewall.DNATBypassWebPath = filepath.Join(dir, "cfm.dnat_bypass")
	t.Cleanup(func() { firewall.DNATBypassWebPath = prev })

	code := runBypassCLI([]string{"add", "not-an-ip"}, firewall.DNATBypassScopeWeb, nil)
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid IP, got %d", code)
	}
}

// TestRunBypassCLI_AddPersistsEvenWhenBackendNil verifies that the file is
// written even when no backend is wired up. The reload step prints a
// warning + returns non-zero, but the persistent bypass list must already
// have been updated by that point so a subsequent `cfm dnat on` picks it
// up. This is the behaviour an installer/postinst script depends on.
func TestRunBypassCLI_AddPersistsEvenWhenBackendNil(t *testing.T) {
	dir := t.TempDir()
	prev := firewall.DNATBypassWebPath
	firewall.DNATBypassWebPath = filepath.Join(dir, "cfm.dnat_bypass")
	t.Cleanup(func() { firewall.DNATBypassWebPath = prev })

	code := runBypassCLI([]string{"add", "84.54.49.205"}, firewall.DNATBypassScopeWeb, nil)
	// reload step warns + exits 1 because backend is nil, but the add
	// itself must have persisted before that.
	if code == 2 {
		t.Fatalf("unexpected validation failure: got %d", code)
	}
	if code != 1 {
		t.Errorf("expected exit code 1 (no backend warning), got %d", code)
	}
	entries, _, err := firewall.LoadDNATBypass(firewall.DNATBypassWebPath)
	if err != nil {
		t.Fatalf("LoadDNATBypass after add: %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "84.54.49.205" {
		t.Errorf("expected entry persisted, got %+v", entries)
	}
}

// TestRunBypassCLI_RemoveIdempotent verifies that removing an entry that
// isn't present is a no-op success (exit 0), not an error. This matters
// for ansible/scripts that idempotently re-apply state.
func TestRunBypassCLI_RemoveIdempotent(t *testing.T) {
	dir := t.TempDir()
	prev := firewall.DNATBypassCpanelPath
	firewall.DNATBypassCpanelPath = filepath.Join(dir, "cfm.dnat_cpanel_bypass")
	t.Cleanup(func() { firewall.DNATBypassCpanelPath = prev })

	// File doesn't exist yet.
	code := runBypassCLI([]string{"remove", "84.54.49.205"}, firewall.DNATBypassScopeCpanel, nil)
	if code != 0 {
		t.Errorf("expected exit 0 for remove from missing file, got %d", code)
	}
}
