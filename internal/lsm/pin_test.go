//go:build linux

package lsm

import (
	"os"
	"path/filepath"
	"testing"
)

// fakePinned constructs a pin-directory layout under tmp that looks
// like the result of a successful `cfm lsm enable` without actually
// touching bpffs. Useful for InspectPinned and describeRuntime tests
// — those code paths only stat() files and never open them.
//
// The layout matches what loader.go's pinAll writes:
//
//   <dir>/maps/cfm_events
//   <dir>/links/cfm_memfd_exec
//   <dir>/links/cfm_revshell
//
// Each policy listed in `policies` gets a placeholder link file.
// withMap controls whether the map placeholder exists.
func fakePinned(t *testing.T, dir string, withMap bool, policies ...PolicyID) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, pinSubdirMaps), 0o700); err != nil {
		t.Fatalf("mkdir maps: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, pinSubdirLinks), 0o700); err != nil {
		t.Fatalf("mkdir links: %v", err)
	}
	if withMap {
		if err := os.WriteFile(filepath.Join(dir, pinSubdirMaps, pinFileMap), []byte{}, 0o600); err != nil {
			t.Fatalf("write map placeholder: %v", err)
		}
	}
	for _, p := range policies {
		name := pinLinkFile(p)
		if name == "" {
			t.Fatalf("pinLinkFile(%s) returned empty — test bug", p)
		}
		if err := os.WriteFile(filepath.Join(dir, pinSubdirLinks, name), []byte{}, 0o600); err != nil {
			t.Fatalf("write link placeholder for %s: %v", p, err)
		}
	}
}

func TestInspectPinned_NonExistent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	st := InspectPinned(dir)
	if st.Exists {
		t.Errorf("Exists: got true, want false for non-existent dir")
	}
	if st.MapPresent {
		t.Errorf("MapPresent: got true, want false for non-existent dir")
	}
	if len(st.Links) != 0 {
		t.Errorf("Links: got %v, want empty", st.Links)
	}
	if st.PinDir != dir {
		t.Errorf("PinDir round-trip mismatch: got %q, want %q", st.PinDir, dir)
	}
}

func TestInspectPinned_FullState(t *testing.T) {
	dir := t.TempDir()
	fakePinned(t, dir, true, PolicyMemfdExec, PolicyReverseShell)
	st := InspectPinned(dir)
	if !st.Exists {
		t.Fatal("Exists: got false")
	}
	if !st.MapPresent {
		t.Error("MapPresent: got false, want true")
	}
	if len(st.Links) != 2 {
		t.Fatalf("Links: got %d, want 2", len(st.Links))
	}
}

func TestInspectPinned_PartialState(t *testing.T) {
	// Only EXEC-001 pinned, no map — models a partial-attach
	// scenario or a corrupted-pin recovery.
	dir := t.TempDir()
	fakePinned(t, dir, false, PolicyMemfdExec)
	st := InspectPinned(dir)
	if !st.Exists {
		t.Fatal("Exists: got false")
	}
	if st.MapPresent {
		t.Error("MapPresent: got true, want false")
	}
	if len(st.Links) != 1 || st.Links[0] != PolicyMemfdExec {
		t.Errorf("Links: got %v, want [%s]", st.Links, PolicyMemfdExec)
	}
}

func TestUnpinAll_RemovesEverything(t *testing.T) {
	dir := t.TempDir()
	pinDir := filepath.Join(dir, "cfm")
	fakePinned(t, pinDir, true, PolicyMemfdExec, PolicyReverseShell)

	if err := UnpinAll(pinDir); err != nil {
		t.Fatalf("UnpinAll: %v", err)
	}
	if _, err := os.Stat(pinDir); !os.IsNotExist(err) {
		t.Errorf("pinDir still exists after UnpinAll: err=%v", err)
	}
	// A second call must succeed (idempotent).
	if err := UnpinAll(pinDir); err != nil {
		t.Errorf("second UnpinAll on absent dir: %v", err)
	}
}

func TestUnpinAll_NonExistentIsNoOp(t *testing.T) {
	if err := UnpinAll(filepath.Join(t.TempDir(), "never-existed")); err != nil {
		t.Errorf("UnpinAll on non-existent dir should be nil, got %v", err)
	}
}

func TestPinLinkFile_Coverage(t *testing.T) {
	// Every policy in AllPolicies() must have a non-empty pin file
	// name. If not, the pinning loop in pinAll would silently skip
	// it and the policy would not be persisted.
	for _, p := range AllPolicies() {
		if pinLinkFile(p.ID) == "" {
			t.Errorf("policy %s has no pin file name; pinAll would silently skip it", p.ID)
		}
	}
	// Unknown ID returns empty — sanity check for the switch's
	// default branch.
	if got := pinLinkFile("CFML-BOGUS-999"); got != "" {
		t.Errorf("unknown policy returned %q, want \"\"", got)
	}
}

func TestDescribeRuntime_LiveStateBeatsPrediction(t *testing.T) {
	// When a policy is in PinnedState.Links, describeRuntime should
	// report "attached" regardless of preflight or conf state. The
	// pinned state IS the source of truth.
	pinned := PinnedState{
		PinDir:     "/sys/fs/bpf/cfm",
		Exists:     true,
		MapPresent: true,
		Links:      []PolicyID{PolicyMemfdExec},
	}
	pf := Preflight{OK: false} // pretend preflight broke after enable
	conf := &Conf{Enabled: false}

	got := describeRuntime(pf, conf, pinned, ModeMonitor, PolicyMemfdExec)
	if got == "" || got[:8] != "attached" {
		t.Errorf("pinned policy: got %q, want attached* (live state wins over preflight/conf)", got)
	}

	// A policy that's NOT pinned should fall through to the
	// preflight/conf prediction path.
	got = describeRuntime(pf, conf, pinned, ModeMonitor, PolicyReverseShell)
	if got == "" || got[:4] != "skip" {
		t.Errorf("unpinned policy with conf disabled: got %q, want skip*", got)
	}
}

func TestDescribeRuntime_NoPinSuggestsEnable(t *testing.T) {
	pinned := PinnedState{PinDir: "/sys/fs/bpf/cfm"} // not exists
	pf := Preflight{OK: true}
	conf := &Conf{Enabled: true}

	got := describeRuntime(pf, conf, pinned, ModeMonitor, PolicyMemfdExec)
	if got == "" || !contains(got, "cfm lsm enable") {
		t.Errorf("would-attach text should point at `cfm lsm enable`, got: %q", got)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
