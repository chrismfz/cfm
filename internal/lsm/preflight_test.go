package lsm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// writeFile is a test helper that writes data to dir/name and returns
// the full path.
func writeFile(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// stubProc rebinds the preflight path globals to point at fixtures
// under tmp/. Restores them on test cleanup.
type stubProc struct {
	procVersion string // /proc/version contents
	bootConfig  string // /boot/config-<release> contents (or empty to skip)
	configGz    []byte // /proc/config.gz contents (raw gzip; or nil to skip)
	lsmList     string // /sys/kernel/security/lsm contents
	btfPresent  bool
	procStatus  string // /proc/self/status contents
	kallsyms    string // /proc/kallsyms contents

	// bpffsMountpoint, when non-empty, is the mountpoint to inject
	// into the fake /proc/mounts with fstype "bpf". Defaults to
	// "/sys/fs/bpf" when the stub is used to model a passing host;
	// leave empty to model the "bpffs not mounted" case.
	bpffsMountpoint string

	// programTypeProbeErr is the value the stubbed
	// preflightProgramTypeProbe will return. nil models a host that
	// accepts BPF_PROG_TYPE_LSM (e.g. AlmaLinux 8.6+, EL9+,
	// Debian 12+). Set to ebpf.ErrNotSupported to model a host
	// where the kernel rejects the program type at the bpf() syscall
	// (e.g. CloudLinux 8 lve kernels).
	programTypeProbeErr error
}

func (s stubProc) install(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()

	// /proc/version
	procVerPath := writeFile(t, tmp, "proc/version", s.procVersion)

	// /sys/kernel/security/lsm
	lsmListPath := writeFile(t, tmp, "sys/kernel/security/lsm", s.lsmList)

	// /proc/self/status
	statusPath := writeFile(t, tmp, "proc/self/status", s.procStatus)

	kallsyms := s.kallsyms
	if kallsyms == "" {
		kallsyms = "0000000000000000 T commit_creds\n"
	}
	kallsymsPath := writeFile(t, tmp, "proc/kallsyms", kallsyms)

	// /proc/config.gz (optional)
	configGzPath := filepath.Join(tmp, "proc/config.gz")
	if s.configGz != nil {
		if err := os.WriteFile(configGzPath, s.configGz, 0o644); err != nil {
			t.Fatalf("write config.gz: %v", err)
		}
	} else {
		// Use a path that won't exist so readKernelConfig falls back.
		configGzPath = filepath.Join(tmp, "missing-config.gz")
	}

	// /boot/config-<release>
	bootDir := filepath.Join(tmp, "boot")
	if err := os.MkdirAll(bootDir, 0o755); err != nil {
		t.Fatalf("mkdir boot: %v", err)
	}
	if s.bootConfig != "" {
		release := extractTestRelease(s.procVersion)
		_ = writeFile(t, tmp, "boot/config-"+release, s.bootConfig)
	}

	// /sys/kernel/btf/vmlinux
	btfPath := filepath.Join(tmp, "sys/kernel/btf/vmlinux")
	if s.btfPresent {
		_ = writeFile(t, tmp, "sys/kernel/btf/vmlinux", "BTF\x9feeb")
	}

	// /proc/mounts — always write a fixture, but only include the
	// bpf line when bpffsMountpoint is non-empty. Other rows mimic a
	// realistic mounts table to make the parser do real work.
	mountsBody := "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"tmpfs /run tmpfs rw,nosuid,nodev,size=1620848k,mode=755 0 0\n"
	if s.bpffsMountpoint != "" {
		mountsBody += "bpf " + s.bpffsMountpoint + " bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0\n"
	}
	mountsPath := writeFile(t, tmp, "proc/mounts", mountsBody)

	// Swap globals.
	prevVersion := preflightProcVersionPath
	prevConfigGz := preflightProcConfigGzPath
	prevBootDir := preflightBootConfigDir
	prevLSMList := preflightLSMListPath
	prevBTF := preflightBTFPath
	prevStatus := preflightProcSelfStatus
	prevMounts := preflightProcMounts
	prevBPFFSPath := preflightBPFFSPath
	prevKallsyms := preflightProcKallsyms
	prevProbe := preflightProgramTypeProbe

	preflightProcVersionPath = procVerPath
	preflightProcConfigGzPath = configGzPath
	preflightBootConfigDir = bootDir
	preflightLSMListPath = lsmListPath
	preflightBTFPath = btfPath
	preflightProcSelfStatus = statusPath
	preflightProcMounts = mountsPath
	preflightProcKallsyms = kallsymsPath
	if s.bpffsMountpoint != "" {
		preflightBPFFSPath = s.bpffsMountpoint
	}
	probeErr := s.programTypeProbeErr
	preflightProgramTypeProbe = func() error { return probeErr }

	t.Cleanup(func() {
		preflightProcVersionPath = prevVersion
		preflightProcConfigGzPath = prevConfigGz
		preflightBootConfigDir = prevBootDir
		preflightLSMListPath = prevLSMList
		preflightBTFPath = prevBTF
		preflightProcSelfStatus = prevStatus
		preflightProcMounts = prevMounts
		preflightBPFFSPath = prevBPFFSPath
		preflightProcKallsyms = prevKallsyms
		preflightProgramTypeProbe = prevProbe
	})
}

// extractTestRelease grabs the 3rd whitespace field from a /proc/version
// fixture, matching readKernelRelease's logic.
func extractTestRelease(procVersion string) string {
	fields := splitFields(procVersion)
	if len(fields) < 3 {
		return "unknown"
	}
	return fields[2]
}

func splitFields(s string) []string {
	var out []string
	curr := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if curr != "" {
				out = append(out, curr)
				curr = ""
			}
			continue
		}
		curr += string(r)
	}
	if curr != "" {
		out = append(out, curr)
	}
	return out
}

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		in            string
		wantMaj       int
		wantMin       int
		wantRaw       string
		wantErrSubstr string
	}{
		{
			in:      "Linux version 5.15.0-78-generic (buildd@lcy02) #85-Ubuntu SMP",
			wantMaj: 5, wantMin: 15, wantRaw: "5.15.0-78-generic",
		},
		{
			in:      "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
			wantMaj: 6, wantMin: 8, wantRaw: "6.8.0-31-generic",
		},
		{
			in:      "Linux version 4.18.0-553.el8.x86_64 (mockbuild) #1 SMP",
			wantMaj: 4, wantMin: 18, wantRaw: "4.18.0-553.el8.x86_64",
		},
		{
			in:            "garbage",
			wantErrSubstr: "unexpected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			maj, min, raw, err := parseKernelVersion(tc.in)
			if tc.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKernelVersion: %v", err)
			}
			if maj != tc.wantMaj || min != tc.wantMin {
				t.Errorf("got %d.%d, want %d.%d", maj, min, tc.wantMaj, tc.wantMin)
			}
			if raw != tc.wantRaw {
				t.Errorf("raw: got %q, want %q", raw, tc.wantRaw)
			}
		})
	}
}

func TestHasLSM(t *testing.T) {
	cases := []struct {
		list string
		name string
		want bool
	}{
		{"lockdown,capability,landlock,yama,apparmor,bpf", "bpf", true},
		{"lockdown,yama,integrity", "bpf", false},
		{"bpf", "bpf", true},
		{"", "bpf", false},
		{"lockdown, capability, yama, bpf", "bpf", true}, // tolerate whitespace
	}
	for _, tc := range cases {
		if got := hasLSM(tc.list, tc.name); got != tc.want {
			t.Errorf("hasLSM(%q, %q): got %t, want %t", tc.list, tc.name, got, tc.want)
		}
	}
}

func TestExtractCapEff(t *testing.T) {
	body := `Name:	cfm
Umask:	0022
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
`
	got, ok := extractCapEff(body)
	if !ok {
		t.Fatal("CapEff not extracted")
	}
	if got != 0x1ffffffffff {
		t.Errorf("CapEff: got %x, want 1ffffffffff", got)
	}
	if !capHas(got, capSysAdmin) {
		t.Error("expected SYS_ADMIN to be set in 0x1ffffffffff")
	}
}

func TestFindKConfigValue(t *testing.T) {
	body := `# Linux kernel config
CONFIG_FOO=y
CONFIG_BAR=m
# CONFIG_BAZ is not set
CONFIG_QUX="some-string"
`
	cases := []struct {
		key string
		val string
		ok  bool
	}{
		{"CONFIG_FOO", "y", true},
		{"CONFIG_BAR", "m", true},
		{"CONFIG_QUX", `"some-string"`, true},
		{"CONFIG_BAZ", "", false},
		{"CONFIG_NOTHING", "", false},
	}
	for _, tc := range cases {
		got, ok := findKConfigValue(body, tc.key)
		if ok != tc.ok {
			t.Errorf("findKConfigValue(%q): ok=%t, want %t", tc.key, ok, tc.ok)
		}
		if got != tc.val {
			t.Errorf("findKConfigValue(%q): got %q, want %q", tc.key, got, tc.val)
		}
	}
}

func TestPreflight_AllPass(t *testing.T) {
	stub := stubProc{
		procVersion:     "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		bootConfig:      "CONFIG_BPF_LSM=y\nCONFIG_DEBUG_INFO_BTF=y\n",
		lsmList:         "lockdown,capability,landlock,yama,apparmor,bpf",
		btfPresent:      true,
		procStatus:      "Name:\tcfm\nCapEff:\t000001ffffffffff\n",
		bpffsMountpoint: "/sys/fs/bpf",
	}
	stub.install(t)

	pf := RunPreflight()
	if !pf.OK {
		t.Errorf("expected OK preflight; got: %+v", pf)
		for _, c := range pf.Checks {
			t.Logf("  %s: %s — %s — %s", c.Name, c.Status, c.Detail, c.Remediation)
		}
	}
}

func TestPreflight_OldKernelStillPassesWhenProgramTypeProbeSucceeds(t *testing.T) {
	// Models AlmaLinux 8.6+ / CloudLinux 9 vendor backport: uname says
	// 4.18 but the kernel accepts BPF_PROG_TYPE_LSM at the bpf()
	// syscall. The kernel-version check must be informational PASS
	// (not a gate), and overall preflight must succeed because the
	// authoritative bpf-lsm-program-type probe returned nil.
	stub := stubProc{
		procVersion:     "Linux version 4.18.0-553.el8.x86_64 (mockbuild) #1 SMP",
		bootConfig:      "CONFIG_BPF_LSM=y\n",
		lsmList:         "lockdown,yama,integrity,bpf",
		btfPresent:      true,
		procStatus:      "CapEff:\t000001ffffffffff\n",
		bpffsMountpoint: "/sys/fs/bpf",
	}
	stub.install(t)

	pf := RunPreflight()
	if !pf.OK {
		t.Fatalf("expected preflight to PASS on 4.18 with successful program-type probe; got: %+v", pf)
	}
	for _, c := range pf.Checks {
		if c.Name == "kernel-version" && c.Status != CheckPass {
			t.Errorf("kernel-version is informational and must always PASS when /proc/version parses; got %s", c.Status)
		}
	}
}

func TestPreflight_BPFLSMProgramTypeNotSupported(t *testing.T) {
	// Models CloudLinux 8 (lve) kernels: CONFIG_BPF_LSM=y is set,
	// `bpf` is in /sys/kernel/security/lsm, BTF is present — but the
	// bpf() syscall rejects BPF_PROG_TYPE_LSM at the dispatch layer.
	// The bpf-lsm-program-type check must FAIL with a remediation,
	// and overall preflight must be not-OK.
	stub := stubProc{
		procVersion:         "Linux version 4.18.0-553.111.1.lve.el8.x86_64 (mockbuild) #1 SMP",
		bootConfig:          "CONFIG_BPF_LSM=y\n",
		lsmList:             "capability,yama,bpf",
		btfPresent:          true,
		procStatus:          "CapEff:\t000001ffffffffff\n",
		bpffsMountpoint:     "/sys/fs/bpf",
		programTypeProbeErr: ebpf.ErrNotSupported,
	}
	stub.install(t)

	pf := RunPreflight()
	if pf.OK {
		t.Fatal("expected preflight to FAIL when BPF_PROG_TYPE_LSM is unsupported")
	}
	for _, c := range pf.Checks {
		if c.Name == "bpf-lsm-program-type" {
			if c.Status != CheckFail {
				t.Errorf("bpf-lsm-program-type: got %s, want FAIL", c.Status)
			}
			if c.Remediation == "" {
				t.Error("FAIL must carry operator-facing remediation")
			}
			return
		}
	}
	t.Error("bpf-lsm-program-type check not found in results")
}

func TestPreflight_BPFNotInLSMList(t *testing.T) {
	stub := stubProc{
		procVersion: "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		bootConfig:  "CONFIG_BPF_LSM=y\n",
		lsmList:     "lockdown,capability,landlock,yama,apparmor", // no bpf
		btfPresent:  true,
		procStatus:  "CapEff:\t000001ffffffffff\n",
	}
	stub.install(t)

	pf := RunPreflight()
	if pf.OK {
		t.Fatal("expected preflight to FAIL when bpf is absent from /sys/kernel/security/lsm")
	}
	for _, c := range pf.Checks {
		if c.Name == "bpf-in-lsm-list" {
			if c.Status != CheckFail {
				t.Errorf("bpf-in-lsm-list: got %s, want FAIL", c.Status)
			}
			if c.Remediation == "" {
				t.Error("FAIL must carry operator-facing remediation")
			}
			return
		}
	}
	t.Error("bpf-in-lsm-list check not found in results")
}

func TestPreflight_BTFMissing(t *testing.T) {
	stub := stubProc{
		procVersion: "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		bootConfig:  "CONFIG_BPF_LSM=y\n",
		lsmList:     "lockdown,capability,bpf",
		btfPresent:  false,
		procStatus:  "CapEff:\t000001ffffffffff\n",
	}
	stub.install(t)

	pf := RunPreflight()
	if pf.OK {
		t.Fatal("expected preflight to FAIL when /sys/kernel/btf/vmlinux is missing")
	}
	for _, c := range pf.Checks {
		if c.Name == "btf-available" && c.Status != CheckFail {
			t.Errorf("btf-available: got %s, want FAIL", c.Status)
		}
	}
}

func TestPreflight_NoCaps(t *testing.T) {
	stub := stubProc{
		procVersion: "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		bootConfig:  "CONFIG_BPF_LSM=y\n",
		lsmList:     "lockdown,bpf",
		btfPresent:  true,
		// CapEff zero — unprivileged process.
		procStatus: "CapEff:\t0000000000000000\n",
	}
	stub.install(t)

	pf := RunPreflight()
	if pf.OK {
		t.Fatal("expected preflight to FAIL when CapEff is zero")
	}
	for _, c := range pf.Checks {
		if c.Name == "capabilities" && c.Status != CheckFail {
			t.Errorf("capabilities: got %s, want FAIL", c.Status)
		}
	}
}

func TestPreflight_ConfigUnknownWithNoFiles(t *testing.T) {
	// /proc/config.gz absent, /boot/config-<release> absent → UNKNOWN
	stub := stubProc{
		procVersion: "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		// bootConfig empty
		lsmList:         "lockdown,bpf",
		btfPresent:      true,
		procStatus:      "CapEff:\t000001ffffffffff\n",
		bpffsMountpoint: "/sys/fs/bpf",
	}
	stub.install(t)

	pf := RunPreflight()
	// UNKNOWN counts as not-OK; we just verify the right check is the cause.
	for _, c := range pf.Checks {
		if c.Name == "kernel-config" && c.Status != CheckUnknown {
			t.Errorf("kernel-config: got %s, want UNKNOWN (no config files)", c.Status)
		}
	}
}

func TestPreflight_BPFFSMissing(t *testing.T) {
	stub := stubProc{
		procVersion: "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		bootConfig:  "CONFIG_BPF_LSM=y\n",
		lsmList:     "lockdown,bpf",
		btfPresent:  true,
		procStatus:  "CapEff:\t000001ffffffffff\n",
		// bpffsMountpoint deliberately empty → /proc/mounts will not
		// list a bpf filesystem.
	}
	stub.install(t)

	pf := RunPreflight()
	if pf.OK {
		t.Fatal("expected preflight to FAIL when /sys/fs/bpf is not mounted")
	}
	for _, c := range pf.Checks {
		if c.Name == "bpffs-mounted" {
			if c.Status != CheckFail {
				t.Errorf("bpffs-mounted: got %s, want FAIL", c.Status)
			}
			if c.Remediation == "" {
				t.Error("FAIL must carry operator-facing remediation")
			}
			return
		}
	}
	t.Error("bpffs-mounted check not found in results")
}

func TestProcMountsHasBPFFS(t *testing.T) {
	cases := []struct {
		name   string
		mounts string
		path   string
		want   bool
	}{
		{
			name:   "bpf line present at exact path",
			mounts: "proc /proc proc rw 0 0\nbpf /sys/fs/bpf bpf rw 0 0\n",
			path:   "/sys/fs/bpf",
			want:   true,
		},
		{
			name:   "different mountpoint",
			mounts: "bpf /run/bpf bpf rw 0 0\n",
			path:   "/sys/fs/bpf",
			want:   false,
		},
		{
			name:   "wrong fstype at the right path",
			mounts: "tmpfs /sys/fs/bpf tmpfs rw 0 0\n",
			path:   "/sys/fs/bpf",
			want:   false,
		},
		{
			name:   "empty mounts table",
			mounts: "",
			path:   "/sys/fs/bpf",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := procMountsHasBPFFS(tc.mounts, tc.path); got != tc.want {
				t.Errorf("procMountsHasBPFFS: got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPreflight_DirectCredPolicyUnavailableDoesNotFailComponent(t *testing.T) {
	stub := stubProc{
		procVersion:     "Linux version 6.8.0-31-generic (buildd) #32-Ubuntu SMP",
		bootConfig:      "CONFIG_BPF_LSM=y\nCONFIG_DEBUG_INFO_BTF=y\n",
		lsmList:         "lockdown,capability,landlock,yama,apparmor,bpf",
		btfPresent:      true,
		procStatus:      "Name:\tcfm\nCapEff:\t000001ffffffffff\n",
		bpffsMountpoint: "/sys/fs/bpf",
		kallsyms:        "0000000000000000 T unrelated_symbol\n",
	}
	stub.install(t)

	pf := RunPreflight()
	if !pf.OK {
		t.Fatalf("optional policy unavailability must not fail component preflight: %+v", pf)
	}
	if len(pf.PolicyAvailability) == 0 {
		t.Fatal("expected per-policy availability results")
	}
	got := pf.PolicyAvailability[0]
	if got.PolicyID != PolicyDirectCredInstall {
		t.Fatalf("availability policy = %s, want %s", got.PolicyID, PolicyDirectCredInstall)
	}
	if got.Available {
		t.Fatal("CFML-CRED-003 should be unavailable when commit_creds is absent from kallsyms")
	}
	if got.Reason == "" {
		t.Fatal("unavailable policy should include a reason")
	}
}

func TestKallsymsHasSymbol(t *testing.T) {
	body := "0000000000000000 T prepare_creds\n0000000000000000 T commit_creds\n"
	if !kallsymsHasSymbol(body, "commit_creds") {
		t.Fatal("expected commit_creds to be found")
	}
	if kallsymsHasSymbol(body, "not_commit_creds") {
		t.Fatal("unexpected symbol match")
	}
}
