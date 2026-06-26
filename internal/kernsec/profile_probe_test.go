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

func TestSkipReason_SCTPGate(t *testing.T) {
	// HasSCTPWorkload=true → modules.net.legacy.sctp must skip
	// (telecom signalling host, K8s with SCTP services, monitoring
	// running check_sctp, etc.).
	if r := (HostProfile{HasSCTPWorkload: true}).SkipReason("modules.net.legacy.sctp"); r == "" {
		t.Error("HasSCTPWorkload=true should produce a SkipReason for modules.net.legacy.sctp")
	}
	// Clean hosting box → apply.
	if r := (HostProfile{}).SkipReason("modules.net.legacy.sctp"); r != "" {
		t.Errorf("clean host should not skip modules.net.legacy.sctp; got %q", r)
	}
	// The SCTP gate must not bleed into the bare modules.net.legacy
	// group (smc / smc_diag / slip / slhc / l2tp_* etc. should keep
	// applying on hosts that only have SCTP).
	if r := (HostProfile{HasSCTPWorkload: true}).SkipReason("modules.net.legacy"); r != "" {
		t.Errorf("HasSCTPWorkload=true must not skip the bare modules.net.legacy group: got %q", r)
	}
}

func TestDetectSCTPWorkload_ProcNetSCTP(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc/net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/net/sctp"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if !detectSCTPWorkload() {
		t.Error("/proc/net/sctp presence should signal SCTP workload")
	}
}

func TestDetectSCTPWorkload_ModuleLoaded(t *testing.T) {
	root := withHostProfileRoot(t)
	writeHostModules(t, root, "sctp")
	if !detectSCTPWorkload() {
		t.Error("sctp loaded in /proc/modules should signal SCTP workload")
	}
}

func TestDetectSCTPWorkload_NagiosPlugin(t *testing.T) {
	root := withHostProfileRoot(t)
	touchHostPath(t, root, "/usr/lib64/nagios/plugins/check_sctp")
	if !detectSCTPWorkload() {
		t.Error("Nagios check_sctp plugin presence should signal SCTP workload")
	}
}

func TestDetectSCTPWorkload_NoSCTP(t *testing.T) {
	withHostProfileRoot(t)
	if detectSCTPWorkload() {
		t.Error("empty fakeroot must not signal SCTP workload")
	}
}

func TestAdvisories_BPFDisabled_DevToolsPresent(t *testing.T) {
	notes := (HostProfile{HasDevTools: true}).Advisories("KSEC-SCT-kspp.kernel-003", "kspp.kernel")
	if len(notes) == 0 {
		t.Fatal("expected advisory for unprivileged_bpf_disabled=2 with HasDevTools")
	}
	if !strings.Contains(notes[0], "developer tooling") {
		t.Errorf("advisory should mention developer tooling; got %q", notes[0])
	}
}

func TestAdvisories_BPFDisabled_NoDevTools(t *testing.T) {
	notes := (HostProfile{}).Advisories("KSEC-SCT-kspp.kernel-003", "kspp.kernel")
	if len(notes) != 0 {
		t.Errorf("clean host should produce no advisory; got %v", notes)
	}
}

func TestAdvisories_PtraceScope_DevToolsPresent(t *testing.T) {
	notes := (HostProfile{HasDevTools: true}).Advisories("KSEC-SCT-kspp.kernel-006", "kspp.kernel")
	if len(notes) == 0 {
		t.Fatal("expected advisory for yama.ptrace_scope=2 with HasDevTools")
	}
	if !strings.Contains(notes[0], "sudo") {
		t.Errorf("ptrace advisory should mention sudo; got %q", notes[0])
	}
}

func TestAdvisories_KexecDisabled_LivePatching(t *testing.T) {
	for _, p := range []HostProfile{
		{HasLivePatchingModules: true},
		{HasKernelCare: true},
		{HasKsplice: true},
	} {
		notes := p.Advisories("KSEC-SCT-kspp.kexec-001", "sysctl.kernel.kexec")
		if len(notes) == 0 {
			t.Errorf("expected advisory for kexec_load_disabled with %+v", p)
			continue
		}
		if !strings.Contains(notes[0], "live-patching") {
			t.Errorf("kexec advisory should mention live-patching; got %q", notes[0])
		}
	}
}

func TestAdvisories_InitOnFree_ZFS(t *testing.T) {
	notes := (HostProfile{HasZFS: true}).Advisories("KSEC-BOOT-tier3.mempaint-001", "tier3.mempaint")
	if len(notes) == 0 {
		t.Fatal("expected advisory for init_on_free with HasZFS")
	}
	if !strings.Contains(notes[0], "ZFS") {
		t.Errorf("init_on_free advisory should mention ZFS; got %q", notes[0])
	}
}

func TestAdvisories_OnlyOnApplyDecision(t *testing.T) {
	// Sanity: rule that would normally advisory must NOT carry one
	// when the decision is anything but Apply.
	conf := &Conf{Tier: 0}
	profile := HostProfile{HasDevTools: true}
	rs := Resolve(conf, profile)
	for _, r := range rs.Sysctls {
		if r.ID != "KSEC-SCT-kspp.kernel-003" {
			continue
		}
		if r.Decision == Apply {
			t.Fatalf("test setup broken: tier-0 conf must not Apply %s", r.ID)
		}
		if len(r.Advisories) != 0 {
			t.Errorf("non-Apply rule must not carry advisories; got %v", r.Advisories)
		}
		return
	}
	t.Fatal("KSEC-SCT-kspp.kernel-003 not found in resolved set")
}

func TestSkipReason_KSMBDGate(t *testing.T) {
	if r := (HostProfile{HasKSMBDServer: true}).SkipReason("modules.recent_cves.ksmbd"); r == "" {
		t.Error("HasKSMBDServer=true should produce a SkipReason for modules.recent_cves.ksmbd")
	}
	if r := (HostProfile{}).SkipReason("modules.recent_cves.ksmbd"); r != "" {
		t.Errorf("clean host should not skip modules.recent_cves.ksmbd; got %q", r)
	}
	// The KSMBD gate must not bleed into the bare modules.recent_cves
	// group (other recent-CVE modules like n_hdlc / vivid / watch_queue
	// should keep applying on hosts that happen to run ksmbd).
	if r := (HostProfile{HasKSMBDServer: true}).SkipReason("modules.recent_cves"); r != "" {
		t.Errorf("HasKSMBDServer=true must not skip the bare modules.recent_cves group: got %q", r)
	}
}

func TestDetectKSMBDServer_ModuleLoaded(t *testing.T) {
	root := withHostProfileRoot(t)
	writeHostModules(t, root, "ksmbd")
	if !detectKSMBDServer() {
		t.Error("ksmbd loaded in /proc/modules should signal ksmbd server use")
	}
}

func TestDetectKSMBDServer_Userspace(t *testing.T) {
	root := withHostProfileRoot(t)
	touchHostPath(t, root, "/usr/sbin/ksmbd.mountd")
	if !detectKSMBDServer() {
		t.Error("ksmbd.mountd binary should signal ksmbd server use")
	}
}

func TestDetectKSMBDServer_None(t *testing.T) {
	withHostProfileRoot(t)
	if detectKSMBDServer() {
		t.Error("empty fakeroot must not signal ksmbd server use")
	}
}

func TestSkipReason_TIPCGate(t *testing.T) {
	if r := (HostProfile{HasTIPCWorkload: true}).SkipReason("modules.net.legacy.tipc"); r == "" {
		t.Error("HasTIPCWorkload=true should produce a SkipReason for modules.net.legacy.tipc")
	}
	if r := (HostProfile{}).SkipReason("modules.net.legacy.tipc"); r != "" {
		t.Errorf("clean host should not skip modules.net.legacy.tipc; got %q", r)
	}
}

func TestSkipReason_AFSGate(t *testing.T) {
	if r := (HostProfile{HasAFS: true}).SkipReason("modules.net.legacy.rxrpc"); r == "" {
		t.Error("HasAFS=true should produce a SkipReason for modules.net.legacy.rxrpc")
	}
	if r := (HostProfile{}).SkipReason("modules.net.legacy.rxrpc"); r != "" {
		t.Errorf("clean host should not skip modules.net.legacy.rxrpc; got %q", r)
	}
}

func TestSkipReason_L2TPGate(t *testing.T) {
	if r := (HostProfile{HasL2TPWorkload: true}).SkipReason("modules.net.legacy.l2tp"); r == "" {
		t.Error("HasL2TPWorkload=true should produce a SkipReason for modules.net.legacy.l2tp")
	}
	if r := (HostProfile{}).SkipReason("modules.net.legacy.l2tp"); r != "" {
		t.Errorf("clean host should not skip modules.net.legacy.l2tp; got %q", r)
	}
}

func TestSkipReason_PPPSlhcGate(t *testing.T) {
	// slhc is in modules.net.legacy.ppp and must skip when either
	// L2TP or PPTP workloads are detected (it sits on both data paths
	// via PPP CCP).
	if r := (HostProfile{HasL2TPWorkload: true}).SkipReason("modules.net.legacy.ppp"); r == "" {
		t.Error("HasL2TPWorkload=true should produce a SkipReason for modules.net.legacy.ppp")
	}
	if r := (HostProfile{HasPPTPWorkload: true}).SkipReason("modules.net.legacy.ppp"); r == "" {
		t.Error("HasPPTPWorkload=true should produce a SkipReason for modules.net.legacy.ppp")
	}
	if r := (HostProfile{}).SkipReason("modules.net.legacy.ppp"); r != "" {
		t.Errorf("clean host should not skip modules.net.legacy.ppp; got %q", r)
	}
}

func TestDetectAFS_StubDirectoryDoesNotFire(t *testing.T) {
	// Debian openafs-client creates /afs as an empty stub even when no
	// AFS cell is mounted. Mere existence must NOT trigger HasAFS —
	// only a real `afs` mount in /proc/mounts or actual openafs/kafs
	// tooling installed.
	root := withHostProfileRoot(t)
	mkdirHostPath(t, root, "/afs")
	if detectAFS() {
		t.Error("empty /afs stub directory must not signal AFS workload")
	}
}

func TestSkipReason_PPTPGate(t *testing.T) {
	if r := (HostProfile{HasPPTPWorkload: true}).SkipReason("modules.net.legacy.pptp"); r == "" {
		t.Error("HasPPTPWorkload=true should produce a SkipReason for modules.net.legacy.pptp")
	}
}

func TestSkipReason_RDSGate(t *testing.T) {
	if r := (HostProfile{HasRDSWorkload: true}).SkipReason("modules.net.legacy.rds"); r == "" {
		t.Error("HasRDSWorkload=true should produce a SkipReason for modules.net.legacy.rds")
	}
}

func TestSkipReason_FirewireGate(t *testing.T) {
	if r := (HostProfile{HasFirewireHardware: true}).SkipReason("modules.bus.firewire"); r == "" {
		t.Error("HasFirewireHardware=true should produce a SkipReason for modules.bus.firewire")
	}
	// FireWire-only host must NOT blanket-skip the other bus groups.
	for _, g := range []string{"modules.bus.bluetooth", "modules.bus.thunderbolt", "modules.bus.misc"} {
		if r := (HostProfile{HasFirewireHardware: true}).SkipReason(g); r != "" {
			t.Errorf("HasFirewireHardware=true must not skip %s: got %q", g, r)
		}
	}
}

func TestSkipReason_MountedDeadFSGate(t *testing.T) {
	if r := (HostProfile{HasMountedDeadFS: true, MountedDeadFSDetail: "udf mounted (/proc/mounts)"}).SkipReason("modules.fs.unused"); r == "" {
		t.Error("HasMountedDeadFS=true should produce a SkipReason for modules.fs.unused")
	} else if !strings.Contains(r, "udf") {
		t.Errorf("SkipReason should surface MountedDeadFSDetail; got %q", r)
	}
	if r := (HostProfile{}).SkipReason("modules.fs.unused"); r != "" {
		t.Errorf("clean host should not skip modules.fs.unused; got %q", r)
	}
}

func TestDetectTIPCWorkload_ModuleLoaded(t *testing.T) {
	root := withHostProfileRoot(t)
	writeHostModules(t, root, "tipc")
	if !detectTIPCWorkload() {
		t.Error("tipc loaded in /proc/modules should signal TIPC workload")
	}
}

func TestDetectAFS_AFSMount(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/mounts"),
		[]byte("AFS /afs afs rw,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !detectAFS() {
		t.Error("AFS in /proc/mounts should signal AFS use")
	}
}

func TestDetectL2TPWorkload_Daemon(t *testing.T) {
	root := withHostProfileRoot(t)
	touchHostPath(t, root, "/usr/sbin/xl2tpd")
	if !detectL2TPWorkload() {
		t.Error("xl2tpd binary should signal L2TP workload")
	}
}

func TestDetectPPTPWorkload_Config(t *testing.T) {
	root := withHostProfileRoot(t)
	touchHostPath(t, root, "/etc/pptpd.conf")
	if !detectPPTPWorkload() {
		t.Error("/etc/pptpd.conf should signal PPTP workload")
	}
}

func TestDetectRDSWorkload_OracleOratab(t *testing.T) {
	root := withHostProfileRoot(t)
	touchHostPath(t, root, "/etc/oratab")
	if !detectRDSWorkload() {
		t.Error("/etc/oratab should signal Oracle/RDS workload")
	}
}

func TestDetectMountedDeadFS_ProcMounts(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// udf is in modules.fs.unused; a UDF mount must trigger the gate.
	if err := os.WriteFile(filepath.Join(root, "proc/mounts"),
		[]byte("/dev/sr0 /mnt/iso udf ro,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, detail := detectMountedDeadFS()
	if !got {
		t.Fatal("UDF mount should trigger HasMountedDeadFS")
	}
	if !strings.Contains(detail, "udf") {
		t.Errorf("detail should name the matching FS; got %q", detail)
	}
}

func TestDetectMountedDeadFS_Fstab(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/mounts"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// hpfs in modules.fs.unused, mounted automatically (no `noauto`).
	if err := os.WriteFile(filepath.Join(root, "etc/fstab"),
		[]byte("/dev/sdb1 /mnt/legacy hpfs defaults 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, detail := detectMountedDeadFS()
	if !got {
		t.Fatal("hpfs in /etc/fstab should trigger HasMountedDeadFS")
	}
	if !strings.Contains(detail, "hpfs") {
		t.Errorf("detail should name the fstab match; got %q", detail)
	}
}

// TestDetectMountedDeadFS_FstabNoauto proves the `noauto` filter — an
// entry the operator keeps for documentation but doesn't auto-mount
// must NOT trigger the gate.
func TestDetectMountedDeadFS_FstabNoauto(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/mounts"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/fstab"),
		[]byte("# legacy partition kept for documentation only\n/dev/sdb1 /mnt/legacy hpfs noauto,ro 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, detail := detectMountedDeadFS(); got {
		t.Errorf("noauto fstab entry must not trigger HasMountedDeadFS; got detail %q", detail)
	}
}

func TestDetectMountedDeadFS_NoMatch(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Standard hosting box: ext4 root, xfs data. Nothing in
	// modules.fs.unused — must NOT trigger.
	if err := os.WriteFile(filepath.Join(root, "proc/mounts"),
		[]byte("/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sda2 /var xfs rw,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := detectMountedDeadFS()
	if got {
		t.Error("standard ext4/xfs host must not trigger HasMountedDeadFS")
	}
}

func TestSkipReason_MCTPGate(t *testing.T) {
	// HasMCTPInBand=true → modules.mctp must skip (OpenBMC / NVMe-MI /
	// PCIe VDM host where the kernel mctp stack is actually used).
	if r := (HostProfile{HasMCTPInBand: true}).SkipReason("modules.mctp"); r == "" {
		t.Error("HasMCTPInBand=true should produce a SkipReason for modules.mctp")
	}
	// HasMCTPInBand=false → modules.mctp must apply (classic
	// Supermicro IPMI / Dell iDRAC: out-of-band, kernel mctp stack
	// unused).
	if r := (HostProfile{}).SkipReason("modules.mctp"); r != "" {
		t.Errorf("clean host should not skip modules.mctp; got %q", r)
	}
	// And the MCTP gate must not bleed into unrelated groups.
	for _, g := range []string{"modules.bus.bluetooth", "modules.bus.firewire", "modules.bus.misc", "modules.ipsec"} {
		if r := (HostProfile{HasMCTPInBand: true}).SkipReason(g); r != "" {
			t.Errorf("HasMCTPInBand=true must not skip unrelated group %s: got %q", g, r)
		}
	}
}

func TestDetectMCTPInBand_BusDevices(t *testing.T) {
	root := withHostProfileRoot(t)
	// One registered MCTP endpoint on the bus → probe must fire.
	mkdirHostPath(t, root, "/sys/bus/mctp/devices/mctp0")
	if !detectMCTPInBand() {
		t.Error("/sys/bus/mctp/devices non-empty should signal in-band MCTP")
	}
}

func TestDetectMCTPInBand_NetdevARPHRD(t *testing.T) {
	root := withHostProfileRoot(t)
	// Older kernel layout: no /sys/bus/mctp, no /sys/class/mctp, but
	// the netdev type announces ARPHRD_MCTP (290).
	netDir := filepath.Join(root, "sys/class/net/mctpi2c0")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "type"), []byte("290\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !detectMCTPInBand() {
		t.Error("netdev with type=290 (ARPHRD_MCTP) should signal in-band MCTP")
	}
}

func TestDetectMCTPInBand_NoMCTP(t *testing.T) {
	root := withHostProfileRoot(t)
	// Stock hosting box: regular netdev with Ethernet type (1).
	netDir := filepath.Join(root, "sys/class/net/eth0")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "type"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if detectMCTPInBand() {
		t.Error("plain Ethernet host must not signal in-band MCTP")
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
	// "sysctl.kernel.kexec" used to live here as a permanently-removed
	// group. Re-introduced under KSEC-SCT-kspp.kexec-001 with a HasKdump
	// gate; see TestSkipReason_KexecKdumpGate below for its dedicated
	// regression coverage. Removed-group test still applies to the
	// genuinely-excluded groups.
	p := HostProfile{HasDKMS: true}
	for _, group := range []string{
		"sysctl.kernel." + "lock" + "down",
		"sysctl.module." + "sig",
	} {
		if reason := p.SkipReason(group); reason != "" {
			t.Fatalf("removed sysctl group %q still has host-profile gate %q", group, reason)
		}
	}
}

// TestSkipReason_KexecKdumpGate covers KSEC-SCT-kspp.kexec-001's
// host-profile gate: HasKdump=true must produce a skip reason
// (kexec_load_disabled would break crash-kernel preloading);
// HasKdump=false must NOT skip (apply cleanly on the common case
// where the host has no kdump configured).
func TestSkipReason_KexecKdumpGate(t *testing.T) {
	if reason := (HostProfile{HasKdump: true}).SkipReason("sysctl.kernel.kexec"); reason == "" {
		t.Error("HasKdump=true should produce a SkipReason for sysctl.kernel.kexec")
	}
	if reason := (HostProfile{HasKdump: false}).SkipReason("sysctl.kernel.kexec"); reason != "" {
		t.Errorf("HasKdump=false should NOT skip sysctl.kernel.kexec; got %q", reason)
	}
}

// TestDetectKdump_Crashkernel proves the cmdline-based signal works.
func TestDetectKdump_Crashkernel(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/cmdline"),
		[]byte("BOOT_IMAGE=/vmlinuz crashkernel=512M ro rhgb quiet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !detectKdump() {
		t.Error("crashkernel= in /proc/cmdline should signal kdump configured")
	}
}

// TestDetectKdump_UnitFile proves the systemd-unit signal works.
func TestDetectKdump_UnitFile(t *testing.T) {
	root := withHostProfileRoot(t)
	touchHostPath(t, root, "/usr/lib/systemd/system/kdump.service")
	if !detectKdump() {
		t.Error("kdump.service unit file presence should signal kdump configured")
	}
}

// TestDetectKdump_NoKdump proves the negative path — neither signal,
// no detection. The common case for hosting boxes.
func TestDetectKdump_NoKdump(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/cmdline"),
		[]byte("BOOT_IMAGE=/vmlinuz ro rhgb quiet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if detectKdump() {
		t.Error("no crashkernel= and no kdump.service should NOT signal kdump")
	}
}

// TestDetectKdump_KexecCrashLoaded proves the /sys/kernel/kexec_crash_loaded
// runtime signal works — catches `kexec -p` invocations that bypass the
// unit file entirely.
func TestDetectKdump_KexecCrashLoaded(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Empty cmdline so the crashkernel= branch can't shadow this case.
	if err := os.WriteFile(filepath.Join(root, "proc/cmdline"),
		[]byte("BOOT_IMAGE=/vmlinuz ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/kernel/kexec_crash_loaded"),
		[]byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !detectKdump() {
		t.Error("/sys/kernel/kexec_crash_loaded == 1 should signal kdump configured")
	}
}

// TestDetectKdump_KexecCrashNotLoaded proves the kexec_crash_loaded
// negative path — file reads "0" and there's no other signal, so the
// probe must NOT report kdump.
func TestDetectKdump_KexecCrashNotLoaded(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/cmdline"),
		[]byte("BOOT_IMAGE=/vmlinuz ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sys/kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/kernel/kexec_crash_loaded"),
		[]byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if detectKdump() {
		t.Error("/sys/kernel/kexec_crash_loaded == 0 must NOT signal kdump (no other signal present)")
	}
}

// TestDetectKdump_MaskedUnit proves a masked kdump-tools.service
// (symlink → /dev/null) is NOT treated as kdump-present. systemd masks
// a unit when the operator explicitly disables it; gating the kexec
// sysctl on a masked unit would be the opposite of operator intent.
func TestDetectKdump_MaskedUnit(t *testing.T) {
	root := withHostProfileRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/cmdline"),
		[]byte("BOOT_IMAGE=/vmlinuz ro\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	maskedUnit := filepath.Join(unitDir, "kdump-tools.service")
	if err := os.Symlink("/dev/null", maskedUnit); err != nil {
		t.Fatal(err)
	}
	if detectKdump() {
		t.Error("masked kdump-tools.service (symlink → /dev/null) must NOT signal kdump configured")
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
		{"HasLivePatchingModules", HostProfile{HasLivePatchingModules: true}, "live-patching"},
		{"HasKernelCare", HostProfile{HasKernelCare: true}, "live-patching"},
		{"HasKsplice", HostProfile{HasKsplice: true}, "live-patching"},
		{"IsCPanel", HostProfile{IsCPanel: true, HasHostingPanelWorkload: true}, "multi-tenant hosting panel"},
		{"IsDirectAdmin", HostProfile{IsDirectAdmin: true, HasHostingPanelWorkload: true}, "multi-tenant hosting panel"},
		{"HasCloudLinuxLVE", HostProfile{HasCloudLinuxLVE: true, HasHostingPanelWorkload: true}, "multi-tenant hosting panel"},
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

// writeHostProcComm fakes a running process at /proc/<pid>/comm under the
// host-profile probe root.
func writeHostProcComm(t *testing.T, root, pid, comm string) {
	t.Helper()
	dir := filepath.Join(root, "proc", pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectKVMHost(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string) HostProfile
		want  bool
	}{
		{
			// The titan regression: a bare-metal cPanel/CloudLinux box on
			// VT-x silicon where kvm_intel auto-loaded but no guests run.
			name: "kvm_intel auto-loaded, no virt evidence",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "kvm_intel", "kvm")
				return HostProfile{}
			},
			want: false,
		},
		{
			name: "no kvm module at all",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "ext4", "nf_tables")
				return HostProfile{}
			},
			want: false,
		},
		{
			name: "kvm_intel + vhost_net loaded (live guest)",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "kvm_intel", "kvm", "vhost_net", "vhost")
				return HostProfile{}
			},
			want: true,
		},
		{
			name: "kvm_amd + libvirt management plane",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "kvm_amd", "kvm")
				return HostProfile{HasLibvirt: true}
			},
			want: true,
		},
		{
			name: "kvm_intel + Proxmox",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "kvm_intel", "kvm")
				return HostProfile{IsProxmox: true}
			},
			want: true,
		},
		{
			name: "kvm_intel + running qemu-system process",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "kvm_intel", "kvm")
				// kernel truncates comm to 15 bytes: qemu-system-x86
				writeHostProcComm(t, root, "4242", "qemu-system-x86")
				return HostProfile{}
			},
			want: true,
		},
		{
			name: "kvm_amd + legacy qemu-kvm process",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "kvm_amd", "kvm")
				writeHostProcComm(t, root, "5050", "qemu-kvm")
				return HostProfile{}
			},
			want: true,
		},
		{
			// libvirt tooling installed but the box is not a hypervisor
			// (no kvm module loaded) → must not be classified as KVM host.
			name: "libvirt present but no kvm module",
			setup: func(t *testing.T, root string) HostProfile {
				writeHostModules(t, root, "ext4")
				return HostProfile{HasLibvirt: true}
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := withHostProfileRoot(t)
			p := tc.setup(t, root)
			if got := detectKVMHost(p); got != tc.want {
				t.Errorf("detectKVMHost() = %v, want %v", got, tc.want)
			}
		})
	}
}
