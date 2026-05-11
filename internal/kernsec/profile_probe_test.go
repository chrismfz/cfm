package kernsec

import (
	"os"
	"path/filepath"
	"strings"
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

func TestSkipReasonDoesNotGateRemovedSysctlGroups(t *testing.T) {
	p := HostProfile{HasKdump: true, HasDKMS: true}
	for _, group := range []string{
		"sysctl.kernel." + "kexec",
		"sysctl.kernel." + "lock" + "down",
		"sysctl.module." + "sig",
	} {
		if reason := p.SkipReason(group); reason != "" {
			t.Fatalf("removed sysctl group %q still has host-profile gate %q", group, reason)
		}
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

func TestHasOutOfTreeModuleEvidence_NoEvidence(t *testing.T) {
	// Smoke: function returns a bool without panicking on a stock
	// CI host (no zfs, no nvidia, no /var/lib/dkms, no akmods).
	// Cannot assert false because the build host might legitimately
	// have one of these; just exercise the code path.
	_ = hasOutOfTreeModuleEvidence(HostProfile{})
}

func TestHasKdump_SmokeNoCrash(t *testing.T) {
	// Smoke: no panic on stock CI host. Test environment is unlikely
	// to have kdump configured, but don't assert false either.
	_ = hasKdump()
}

func withHostProfileRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := hostProfileProbeRoot
	hostProfileProbeRoot = root
	t.Cleanup(func() { hostProfileProbeRoot = old })
	return root
}

func touchHostPath(t *testing.T, root, path string) {
	t.Helper()
	full := filepath.Join(root, path[1:])
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mkdirHostPath(t *testing.T, root, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, path[1:]), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeHostModules(t *testing.T, root string, names ...string) {
	t.Helper()
	var body string
	for _, name := range names {
		body += name + " 1 0 - Live 0x0\n"
	}
	touchHostPath(t, root, "/proc/.keep")
	if err := os.WriteFile(filepath.Join(root, "proc/modules"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectHostProfile_HostingPlatformsFromSafeIndicators(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
		check func(HostProfile) bool
	}{
		{"cpanel", func(t *testing.T, root string) { mkdirHostPath(t, root, "/usr/local/cpanel") }, func(p HostProfile) bool { return p.IsCPanel && p.HasHostingPanelWorkload }},
		{"directadmin", func(t *testing.T, root string) { mkdirHostPath(t, root, "/usr/local/directadmin") }, func(p HostProfile) bool { return p.IsDirectAdmin && p.HasHostingPanelWorkload }},
		{"cloudlinux proc lve", func(t *testing.T, root string) { mkdirHostPath(t, root, "/proc/lve") }, func(p HostProfile) bool { return p.HasCloudLinuxLVE && p.HasHostingPanelWorkload && p.HasDKMS }},
		{"cloudlinux module lve", func(t *testing.T, root string) { writeHostModules(t, root, "lve") }, func(p HostProfile) bool { return p.HasCloudLinuxLVE && p.HasHostingPanelWorkload && p.HasDKMS }},
		{"cloudlinux module kmodlve", func(t *testing.T, root string) { writeHostModules(t, root, "kmodlve") }, func(p HostProfile) bool { return p.HasCloudLinuxLVE && p.HasHostingPanelWorkload && p.HasDKMS }},
		{"cagefs", func(t *testing.T, root string) { touchHostPath(t, root, "/usr/sbin/cagefsctl") }, func(p HostProfile) bool { return p.HasCageFS && p.HasHostingPanelWorkload }},
		{"imunify360", func(t *testing.T, root string) { touchHostPath(t, root, "/usr/lib/systemd/system/imunify360.service") }, func(p HostProfile) bool { return p.HasImunify360 && p.HasHostingPanelWorkload }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := withHostProfileRoot(t)
			tc.setup(t, root)
			if got := DetectHostProfile(); !tc.check(got) {
				t.Fatalf("DetectHostProfile() = %+v", got)
			}
		})
	}
}

func TestDetectHostProfile_LivePatchProxmoxZFSAndNVIDIAIndicators(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string)
		check func(HostProfile) bool
	}{
		{"kernelcare", func(t *testing.T, root string) { touchHostPath(t, root, "/usr/bin/kcarectl") }, func(p HostProfile) bool { return p.HasKernelCare && p.HasDKMS }},
		{"ksplice", func(t *testing.T, root string) { touchHostPath(t, root, "/usr/sbin/uptrack-upgrade") }, func(p HostProfile) bool { return p.HasKsplice && p.HasDKMS }},
		{"livepatch module", func(t *testing.T, root string) { writeHostModules(t, root, "livepatch_cve") }, func(p HostProfile) bool { return p.HasLivePatchingModules && p.HasDKMS }},
		{"proxmox", func(t *testing.T, root string) { touchHostPath(t, root, "/usr/sbin/proxmox-boot-tool") }, func(p HostProfile) bool { return p.IsProxmox }},
		{"zfs module", func(t *testing.T, root string) { writeHostModules(t, root, "zfs") }, func(p HostProfile) bool { return p.HasZFS && p.HasDKMS }},
		{"nvidia module", func(t *testing.T, root string) { writeHostModules(t, root, "nvidia") }, func(p HostProfile) bool { return p.HasNVIDIA && p.HasDKMS }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := withHostProfileRoot(t)
			tc.setup(t, root)
			if got := DetectHostProfile(); !tc.check(got) {
				t.Fatalf("DetectHostProfile() = %+v", got)
			}
		})
	}
}

func TestSkipReason_NamespaceGatesHostingPanels(t *testing.T) {
	for _, tc := range []HostProfile{
		{IsCPanel: true, HasHostingPanelWorkload: true},
		{IsDirectAdmin: true, HasHostingPanelWorkload: true},
		{HasCloudLinuxLVE: true, HasHostingPanelWorkload: true},
		{HasCageFS: true, HasHostingPanelWorkload: true},
		{HasImunify360: true, HasHostingPanelWorkload: true},
	} {
		if got := tc.SkipReason("tier2.namespace"); got == "" || !strings.Contains(got, "hosting panel") {
			t.Errorf("SkipReason(tier2.namespace) on %+v = %q, want hosting panel reason", tc, got)
		}
	}
}
