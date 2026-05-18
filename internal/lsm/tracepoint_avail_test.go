//go:build linux

package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubTracefsEvents redirects tracefsTracepointEventDirs at a t.TempDir()
// fixture and creates per-tracepoint subdirectories (with an empty `id`
// file) for each "category/name" pair in present. The original value is
// restored on test cleanup.
func stubTracefsEvents(t *testing.T, present ...string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "tracing", "events")
	for _, tp := range present {
		dir := filepath.Join(root, tp)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "id"), []byte("0\n"), 0o644); err != nil {
			t.Fatalf("write id: %v", err)
		}
	}
	prev := tracefsTracepointEventDirs
	tracefsTracepointEventDirs = []string{root}
	t.Cleanup(func() { tracefsTracepointEventDirs = prev })
	return root
}

func TestTracepointAvailable(t *testing.T) {
	stubTracefsEvents(t, "syscalls/sys_enter_kexec_file_load")
	if !tracepointAvailable("syscalls", "sys_enter_kexec_file_load") {
		t.Error("kexec_file_load should be reported available")
	}
	if tracepointAvailable("syscalls", "sys_enter_kexec_load") {
		t.Error("kexec_load should NOT be reported available")
	}
	if tracepointAvailable("syscalls", "sys_enter_bogus") {
		t.Error("unknown tracepoint should be unavailable")
	}
}

func TestTracepointAvailable_NoTracefs(t *testing.T) {
	// Redirect to a path that doesn't exist — models a host where
	// tracefs is not mounted at the well-known locations.
	prev := tracefsTracepointEventDirs
	tracefsTracepointEventDirs = []string{filepath.Join(t.TempDir(), "no-tracefs", "events")}
	t.Cleanup(func() { tracefsTracepointEventDirs = prev })
	if tracepointAvailable("syscalls", "sys_enter_bpf") {
		t.Error("tracepointAvailable must return false when the events dir does not exist")
	}
}

func TestCheckKexecLoadAvailability(t *testing.T) {
	cases := []struct {
		name      string
		present   []string
		available bool
		// substrings the Reason must contain
		wantInReason []string
	}{
		{
			name:         "both tracepoints present",
			present:      []string{"syscalls/sys_enter_kexec_load", "syscalls/sys_enter_kexec_file_load"},
			available:    true,
			wantInReason: []string{"both"},
		},
		{
			name:         "only kexec_file_load (RHEL 10 shape)",
			present:      []string{"syscalls/sys_enter_kexec_file_load"},
			available:    true,
			wantInReason: []string{"partial", "kexec_file_load", "kexec_load"},
		},
		{
			name:         "only kexec_load (legacy / signed-not-required)",
			present:      []string{"syscalls/sys_enter_kexec_load"},
			available:    true,
			wantInReason: []string{"partial", "kexec_load", "kexec_file_load"},
		},
		{
			name:         "neither (CONFIG_KEXEC=n + CONFIG_KEXEC_FILE=n)",
			present:      nil,
			available:    false,
			wantInReason: []string{"neither", "CONFIG_KEXEC"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubTracefsEvents(t, tc.present...)
			pa := checkKexecLoadAvailability()
			if pa.PolicyID != PolicyKexecLoad {
				t.Fatalf("PolicyID = %s, want %s", pa.PolicyID, PolicyKexecLoad)
			}
			if pa.Available != tc.available {
				t.Errorf("Available = %t, want %t (reason=%q)", pa.Available, tc.available, pa.Reason)
			}
			for _, s := range tc.wantInReason {
				if !strings.Contains(pa.Reason, s) {
					t.Errorf("Reason %q missing substring %q", pa.Reason, s)
				}
			}
		})
	}
}

func TestPinPartialAdoptable(t *testing.T) {
	if !pinPartialAdoptable(PolicyKexecLoad) {
		t.Error("PolicyKexecLoad must be partial-adoptable (kexec_load / kexec_file_load are independently CONFIG-gated)")
	}
	// Spot-check a few all-or-nothing policies.
	for _, id := range []PolicyID{
		PolicyMemfdExec,
		PolicySensitiveWrite,
		PolicyKernelModuleLoad,
		PolicyPrivInstall,
	} {
		if pinPartialAdoptable(id) {
			t.Errorf("%s must be all-or-nothing; partial pin would indicate corruption", id)
		}
	}
}

