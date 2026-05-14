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

func TestDetectInKernelBridge(t *testing.T) {
	t.Run("no bridges", func(t *testing.T) {
		root := withHostProfileRoot(t)
		mkdirHostPath(t, root, "/sys/class/net/eth0")
		mkdirHostPath(t, root, "/sys/class/net/lo")
		if got := DetectHostProfile(); got.UsesBridge {
			t.Errorf("UsesBridge=true with no bridge sysfs entries; got %+v", got)
		}
	})
	t.Run("docker0 bridge", func(t *testing.T) {
		root := withHostProfileRoot(t)
		mkdirHostPath(t, root, "/sys/class/net/eth0")
		mkdirHostPath(t, root, "/sys/class/net/docker0/bridge")
		if got := DetectHostProfile(); !got.UsesBridge {
			t.Errorf("UsesBridge=false with docker0/bridge present; got %+v", got)
		}
	})
	t.Run("proxmox vmbr0", func(t *testing.T) {
		root := withHostProfileRoot(t)
		mkdirHostPath(t, root, "/sys/class/net/vmbr0/bridge")
		if got := DetectHostProfile(); !got.UsesBridge {
			t.Errorf("UsesBridge=false with vmbr0/bridge present; got %+v", got)
		}
	})
	t.Run("libvirt virbr0", func(t *testing.T) {
		root := withHostProfileRoot(t)
		mkdirHostPath(t, root, "/sys/class/net/virbr0/bridge")
		if got := DetectHostProfile(); !got.UsesBridge {
			t.Errorf("UsesBridge=false with virbr0/bridge present; got %+v", got)
		}
	})
}

func TestDetectLibvirt(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"socket", "/var/run/libvirt/libvirt-sock"},
		{"socket run", "/run/libvirt/libvirt-sock"},
		{"libvirtd binary", "/usr/sbin/libvirtd"},
		{"virsh binary", "/usr/bin/virsh"},
		{"etc libvirt", "/etc/libvirt"},
		{"systemd unit", "/usr/lib/systemd/system/libvirtd.service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := withHostProfileRoot(t)
			if strings.HasSuffix(tc.path, "/libvirt") || strings.HasSuffix(tc.path, "/libvirt-sock") || strings.HasSuffix(tc.path, "/libvirt-sock-ro") {
				touchHostPath(t, root, tc.path)
			} else {
				touchHostPath(t, root, tc.path)
			}
			if got := DetectHostProfile(); !got.HasLibvirt {
				t.Errorf("HasLibvirt=false with %s present; got %+v", tc.path, got)
			}
		})
	}
}

func TestSkipReason_LLCGatesBridgeUsers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile HostProfile
		wantSub string
	}{
		{"UsesBridge", HostProfile{UsesBridge: true}, "in-kernel bridge interface"},
		{"HasContainers", HostProfile{HasContainers: true}, "container runtime"},
		{"IsKVMHost", HostProfile{IsKVMHost: true}, "KVM hypervisor"},
		{"HasLibvirt", HostProfile{HasLibvirt: true}, "libvirt installed"},
		{"IsProxmox", HostProfile{IsProxmox: true}, "Proxmox host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.profile.SkipReason("modules.net.legacy.llc")
			if got == "" || !strings.Contains(got, tc.wantSub) {
				t.Errorf("SkipReason(modules.net.legacy.llc) on %+v = %q, want substring %q", tc.profile, got, tc.wantSub)
			}
		})
	}
	t.Run("clean host applies", func(t *testing.T) {
		if got := (HostProfile{}).SkipReason("modules.net.legacy.llc"); got != "" {
			t.Errorf("clean host SkipReason(modules.net.legacy.llc) = %q, want empty", got)
		}
	})
}

func TestSkipReason_Tier2OopsGatesMultiTenant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile HostProfile
		wantSub string
	}{
		{"IsKVMHost", HostProfile{IsKVMHost: true}, "KVM hypervisor"},
		{"HasLibvirt", HostProfile{HasLibvirt: true}, "libvirt host"},
		{"IsProxmox", HostProfile{IsProxmox: true}, "Proxmox host"},
		{"HasContainers", HostProfile{HasContainers: true}, "container runtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.profile.SkipReason("tier2.oops")
			if got == "" || !strings.Contains(got, tc.wantSub) {
				t.Errorf("SkipReason(tier2.oops) on %+v = %q, want substring %q", tc.profile, got, tc.wantSub)
			}
		})
	}
	t.Run("clean host applies", func(t *testing.T) {
		if got := (HostProfile{}).SkipReason("tier2.oops"); got != "" {
			t.Errorf("clean host SkipReason(tier2.oops) = %q, want empty", got)
		}
	})
}

func TestSkipReason_CoredumpGatesMultiTenant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile HostProfile
		wantSub string
	}{
		{"IsKVMHost", HostProfile{IsKVMHost: true}, "KVM / libvirt host"},
		{"HasLibvirt", HostProfile{HasLibvirt: true}, "KVM / libvirt host"},
		{"HasContainers", HostProfile{HasContainers: true}, "container runtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.profile.SkipReason("sysctl.kernel.coredump")
			if got == "" || !strings.Contains(got, tc.wantSub) {
				t.Errorf("SkipReason(sysctl.kernel.coredump) on %+v = %q, want substring %q", tc.profile, got, tc.wantSub)
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

func TestSkipReason_NamespaceGatesActiveUserNamespaces(t *testing.T) {
	// Active userns probe is the strongest signal — fires before
	// HasContainers / hosting-panel because it catches Chromium /
	// bwrap / flatpak / sshd-sandbox children the daemon-name probe
	// misses.
	p := HostProfile{
		HasActiveUserNamespaces:  true,
		ActiveUserNamespacesNote: "2 non-init user namespace(s), 5 process(es) (e.g. chrome, bwrap)",
	}
	got := p.SkipReason("tier2.namespace")
	if got == "" {
		t.Fatal("expected non-empty SkipReason for HasActiveUserNamespaces=true")
	}
	if !strings.Contains(got, "active user namespace") {
		t.Errorf("SkipReason should cite active userns, got %q", got)
	}
	if !strings.Contains(got, "chrome") {
		t.Errorf("SkipReason should surface probe note, got %q", got)
	}
	// Cleared profile must not skip — the probe is a positive signal,
	// not a default-deny.
	if r := (HostProfile{}).SkipReason("tier2.namespace"); r != "" {
		t.Errorf("clean host should not skip tier2.namespace, got %q", r)
	}
}

// makeFakeProcUserns builds a fake /proc tree where each pid has both
// `comm` and a `ns/user` symlink with the supplied target. initTarget
// is written under <procDir>/<initPID>/ns/user. otherPIDs maps pid →
// (comm, nsTarget): nsTarget equal to initTarget means "in init userns";
// anything else means non-init.
func makeFakeProcUserns(t *testing.T, initPID, initTarget string, otherPIDs map[string]struct {
	comm     string
	nsTarget string
}) string {
	t.Helper()
	procDir := t.TempDir()
	mk := func(pid, comm, nsTarget string) {
		dir := filepath.Join(procDir, pid, "ns")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(procDir, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if nsTarget != "" {
			if err := os.Symlink(nsTarget, filepath.Join(dir, "user")); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk(initPID, "systemd", initTarget)
	for pid, v := range otherPIDs {
		mk(pid, v.comm, v.nsTarget)
	}
	return procDir
}

func TestUsernsProbe_AllInInitNamespace(t *testing.T) {
	initTgt := "user:[4026531837]"
	procDir := makeFakeProcUserns(t, "1", initTgt, map[string]struct {
		comm     string
		nsTarget string
	}{
		"100": {"sshd", initTgt},
		"200": {"nginx", initTgt},
	})
	p := usernsProbe{procDir: procDir, initPID: "1"}
	has, note := p.detect()
	if has {
		t.Errorf("all processes in init userns — detect() = (true, %q), want false", note)
	}
}

func TestUsernsProbe_DetectsNonInitUserns(t *testing.T) {
	initTgt := "user:[4026531837]"
	procDir := makeFakeProcUserns(t, "1", initTgt, map[string]struct {
		comm     string
		nsTarget string
	}{
		"100": {"sshd", initTgt},
		"500": {"chrome", "user:[4026532001]"},
		"501": {"chrome", "user:[4026532001]"}, // same non-init ns — must dedupe
		"600": {"bwrap", "user:[4026532002]"},
	})
	p := usernsProbe{procDir: procDir, initPID: "1"}
	has, note := p.detect()
	if !has {
		t.Fatalf("expected detect() = true, got false (note=%q)", note)
	}
	if !strings.Contains(note, "2 non-init user namespace") {
		t.Errorf("note should report 2 distinct namespaces, got %q", note)
	}
	if !strings.Contains(note, "3 process") {
		t.Errorf("note should report 3 non-init processes, got %q", note)
	}
	if !strings.Contains(note, "chrome") && !strings.Contains(note, "bwrap") {
		t.Errorf("note should sample comm names, got %q", note)
	}
}

func TestUsernsProbe_MissingInitNS(t *testing.T) {
	// fakeroot harnesses without symlink support leave ns/user
	// missing. Probe must silently report "no signal" (false), not
	// crash and not assume active namespaces.
	procDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procDir, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := usernsProbe{procDir: procDir, initPID: "1"}
	if has, _ := p.detect(); has {
		t.Error("missing init ns/user — detect() must not report active")
	}
}

func TestUsernsProbe_MissingProcDir(t *testing.T) {
	p := usernsProbe{procDir: filepath.Join(t.TempDir(), "no-such-proc"), initPID: "1"}
	if has, _ := p.detect(); has {
		t.Error("missing procDir — detect() must not report active")
	}
}

func TestDefaultUsernsProbe_ShapeOnly(t *testing.T) {
	p := defaultUsernsProbe()
	if p.procDir != "/proc" {
		t.Errorf("default procDir = %q, want /proc", p.procDir)
	}
	if p.initPID != "1" {
		t.Errorf("default initPID = %q, want 1", p.initPID)
	}
}
