package kernsec

import (
	"os"
	"path/filepath"
	"testing"
)

// makeFakeProc builds a minimal fake /proc tree with a /<pid>/comm
// file per entry in commByPID. Returns the procDir path.
func makeFakeProc(t *testing.T, commByPID map[string]string) string {
	t.Helper()
	procDir := t.TempDir()
	for pid, comm := range commByPID {
		dir := filepath.Join(procDir, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Throw a non-numeric directory in for good measure — the probe
	// must skip it without erroring.
	if err := os.MkdirAll(filepath.Join(procDir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return procDir
}

func TestContainerProbe_DaemonProcess(t *testing.T) {
	tests := []struct {
		name string
		comm string
		want bool
	}{
		{"dockerd present", "dockerd", true},
		{"crio present", "crio", true},
		{"containerd present", "containerd", true},
		{"conmon present", "conmon", true},
		{"lxd present", "lxd", true},
		{"podman present", "podman", true},
		{"kubelet present", "kubelet", true},
		{"systemd-nspawn present", "systemd-nspawn", true},
		{"kata-runtime present", "kata-runtime", true},
		{"runsc present", "runsc", true},
		{"runc present", "runc", true},
		{"unrelated binary not detected", "nginx", false},
		{"prefix collision not detected", "runcheck", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			procDir := makeFakeProc(t, map[string]string{
				"1":    "systemd",
				"4242": tc.comm,
			})
			p := containerProbe{procDir: procDir, nspawnDir: t.TempDir()}
			if got := p.detect(); got != tc.want {
				t.Fatalf("detect() = %v, want %v (comm=%q)", got, tc.want, tc.comm)
			}
		})
	}
}

func TestContainerProbe_ContainerdShimPrefix(t *testing.T) {
	procDir := makeFakeProc(t, map[string]string{
		"1":   "systemd",
		"123": "containerd-shim-runc-v2",
	})
	p := containerProbe{procDir: procDir, nspawnDir: t.TempDir()}
	if !p.detect() {
		t.Fatal("expected containerd-shim-runc-v2 to be detected")
	}
}

func TestContainerProbe_DaemonSocket(t *testing.T) {
	tmp := t.TempDir()
	// Empty /proc — no container processes.
	procDir := makeFakeProc(t, map[string]string{"1": "systemd"})
	sock := filepath.Join(tmp, "docker.sock")
	if err := os.WriteFile(sock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p := containerProbe{
		procDir:   procDir,
		sockets:   []string{sock},
		nspawnDir: t.TempDir(),
	}
	if !p.detect() {
		t.Fatal("expected daemon socket to trigger detection")
	}
}

func TestContainerProbe_NspawnMachine(t *testing.T) {
	procDir := makeFakeProc(t, map[string]string{"1": "systemd"})
	nspawnDir := t.TempDir()
	// One registered machine entry.
	if err := os.WriteFile(filepath.Join(nspawnDir, "alpine.nspawn"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p := containerProbe{procDir: procDir, nspawnDir: nspawnDir}
	if !p.detect() {
		t.Fatal("expected /run/systemd/nspawn entry to trigger detection")
	}
}

func TestContainerProbe_EmptyHost(t *testing.T) {
	procDir := makeFakeProc(t, map[string]string{
		"1":   "systemd",
		"100": "sshd",
		"200": "nginx",
	})
	// Sockets list points at a clean tempdir; nspawnDir is empty.
	tmp := t.TempDir()
	p := containerProbe{
		procDir:   procDir,
		sockets:   []string{filepath.Join(tmp, "missing.sock")},
		nspawnDir: t.TempDir(),
	}
	if p.detect() {
		t.Fatal("expected empty host to report no containers")
	}
}

func TestContainerProbe_MissingProcDir(t *testing.T) {
	// Pointing procDir at a path that doesn't exist must not panic and
	// must not return true on its own.
	tmp := t.TempDir()
	p := containerProbe{
		procDir:   filepath.Join(tmp, "no-such-proc"),
		sockets:   []string{filepath.Join(tmp, "missing.sock")},
		nspawnDir: filepath.Join(tmp, "no-nspawn"),
	}
	if p.detect() {
		t.Fatal("missing /proc should not assert containers")
	}
}

func TestSkipReason_BluetoothBusGroup(t *testing.T) {
	// modules.bus.bluetooth must skip when HasBluetoothHardware.
	p := HostProfile{HasBluetoothHardware: true}
	if r := p.SkipReason("modules.bus.bluetooth"); r == "" {
		t.Error("expected non-empty skip reason for modules.bus.bluetooth on BT-hw host")
	}
	// firewire / thunderbolt / misc must NOT be skipped just because
	// Bluetooth is present — that was the bug: the old single
	// modules.bus group skipped everything together.
	for _, g := range []string{"modules.bus.firewire", "modules.bus.thunderbolt", "modules.bus.misc"} {
		if r := p.SkipReason(g); r != "" {
			t.Errorf("unexpected skip on %s with only Bluetooth hw: %q", g, r)
		}
	}
}

func TestSkipReason_ThunderboltBusGroup(t *testing.T) {
	p := HostProfile{HasThunderbolt: true}
	if r := p.SkipReason("modules.bus.thunderbolt"); r == "" {
		t.Error("expected non-empty skip reason for modules.bus.thunderbolt on TB-hw host")
	}
	// Symmetric: TB-only host must not blanket-skip Bluetooth or
	// firewire or misc.
	for _, g := range []string{"modules.bus.bluetooth", "modules.bus.firewire", "modules.bus.misc"} {
		if r := p.SkipReason(g); r != "" {
			t.Errorf("unexpected skip on %s with only Thunderbolt hw: %q", g, r)
		}
	}
}

func TestSkipReason_BusGroupsApplyOnCleanHost(t *testing.T) {
	// No hardware → all four bus groups apply (no skip).
	p := HostProfile{}
	for _, g := range []string{
		"modules.bus.bluetooth",
		"modules.bus.firewire",
		"modules.bus.thunderbolt",
		"modules.bus.misc",
	} {
		if r := p.SkipReason(g); r != "" {
			t.Errorf("clean host should not skip %s: got %q", g, r)
		}
	}
}

func TestSkipReason_OldModulesBusNoLongerMatches(t *testing.T) {
	// The bare `modules.bus` group is gone after the rename. SkipReason
	// must return "" — falling through to apply — so any stale rule
	// metadata (or a rogue conf override referencing the old group)
	// does not silently match every host. Sub-groups handle the gate.
	p := HostProfile{HasBluetoothHardware: true, HasThunderbolt: true}
	if r := p.SkipReason("modules.bus"); r != "" {
		t.Errorf("stale group `modules.bus` should not match SkipReason: %q", r)
	}
}

func TestDefaultContainerProbe_ShapeOnly(t *testing.T) {
	// Sanity: the default probe points at real host paths. Run it on
	// the test host — result is whatever it is, but it must not panic
	// and the procDir must be /proc.
	p := defaultContainerProbe()
	if p.procDir != "/proc" {
		t.Errorf("default procDir = %q, want /proc", p.procDir)
	}
	if len(p.sockets) == 0 {
		t.Error("default sockets list should not be empty")
	}
	if p.nspawnDir == "" {
		t.Error("default nspawnDir should not be empty")
	}
	_ = p.detect()
}

func TestSkipReason_LockdownGatesOnDKMSAndKdump(t *testing.T) {
	// Phase: tier2.lockdown skips on EITHER DKMS evidence OR kdump
	// — the probe was previously DKMS-only; the safety audit
	// flagged kdump as an under-recognised brick path because
	// lockdown=integrity restricts kexec primitives.
	tests := []struct {
		name    string
		profile HostProfile
		group   string
		wantSet bool // true → expect non-empty SkipReason
	}{
		{"clean host", HostProfile{}, "tier2.lockdown", false},
		{"DKMS only", HostProfile{HasDKMS: true}, "tier2.lockdown", true},
		{"kdump only", HostProfile{HasKdump: true}, "tier2.lockdown", true},
		{"both", HostProfile{HasDKMS: true, HasKdump: true}, "tier2.lockdown", true},
		// boot.lockdown shares the same gate
		{"boot.lockdown DKMS", HostProfile{HasDKMS: true}, "boot.lockdown", true},
		{"boot.lockdown kdump", HostProfile{HasKdump: true}, "boot.lockdown", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.profile.SkipReason(tc.group)
			if (got != "") != tc.wantSet {
				t.Errorf("SkipReason(%q) on %+v = %q, wantSet=%v",
					tc.group, tc.profile, got, tc.wantSet)
			}
		})
	}
}

func TestSkipReason_ModuleSigEnforceStillDKMSOnly(t *testing.T) {
	// module.sig_enforce is purely a module-signing rule — kdump
	// doesn't need unsigned modules, so the kdump escape doesn't
	// apply here. Lock that into a test so a future broaden-the-
	// gates change has to be deliberate.
	if got := (HostProfile{HasKdump: true}).SkipReason("tier2.module-sig-enforce"); got != "" {
		t.Errorf("module-sig-enforce should NOT skip on kdump-only host (DKMS=false): got %q", got)
	}
	if got := (HostProfile{HasDKMS: true}).SkipReason("tier2.module-sig-enforce"); got == "" {
		t.Errorf("module-sig-enforce SHOULD skip on DKMS host: got empty")
	}
}

func TestHasOutOfTreeModuleEvidence_NoEvidence(t *testing.T) {
	// Smoke: function returns a bool without panicking on a stock
	// CI host (no zfs, no nvidia, no /var/lib/dkms, no akmods).
	// Cannot assert false because the build host might legitimately
	// have one of these; just exercise the code path.
	_ = hasOutOfTreeModuleEvidence()
}

func TestHasKdump_SmokeNoCrash(t *testing.T) {
	// Smoke: no panic on stock CI host. Test environment is unlikely
	// to have kdump configured, but don't assert false either.
	_ = hasKdump()
}
