package kernsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// ioUringProbe
// ---------------------------------------------------------------------

// makeFakeProcFd builds a fake /proc tree where each pid has comm and
// a set of fd-N symlinks with the supplied targets.
func makeFakeProcFd(t *testing.T, pids map[string]struct {
	comm string
	fds  []string // each entry is a symlink target
}) string {
	t.Helper()
	procDir := t.TempDir()
	mk := func(pid, comm string, fds []string) {
		fdDir := filepath.Join(procDir, pid, "fd")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(procDir, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for i, tgt := range fds {
			if err := os.Symlink(tgt, filepath.Join(fdDir, "fd-"+intStr(i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	for pid, v := range pids {
		mk(pid, v.comm, v.fds)
	}
	return procDir
}

// intStr converts a small non-negative int to its decimal string form
// without pulling in strconv at every call site.
func intStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestIoUringProbe_EmptyProc(t *testing.T) {
	procDir := t.TempDir()
	p := ioUringProbe{procDir: procDir}
	if has, note := p.detect(); has {
		t.Errorf("empty /proc — detect() = (true, %q), want false", note)
	}
}

func TestIoUringProbe_NoIoUringFds(t *testing.T) {
	procDir := makeFakeProcFd(t, map[string]struct {
		comm string
		fds  []string
	}{
		"100": {"sshd", []string{"socket:[123]", "/dev/null"}},
		"200": {"nginx", []string{"pipe:[456]"}},
	})
	p := ioUringProbe{procDir: procDir}
	if has, note := p.detect(); has {
		t.Errorf("no io_uring fds — detect() = (true, %q), want false", note)
	}
}

func TestIoUringProbe_DetectsIoUringFd(t *testing.T) {
	procDir := makeFakeProcFd(t, map[string]struct {
		comm string
		fds  []string
	}{
		"100": {"sshd", []string{"socket:[123]"}},
		"500": {"postgres", []string{"socket:[456]", "anon_inode:[io_uring]"}},
		"600": {"node", []string{"anon_inode:[io_uring]"}},
	})
	p := ioUringProbe{procDir: procDir}
	has, note := p.detect()
	if !has {
		t.Fatalf("expected detect() = true, got false (note=%q)", note)
	}
	if !strings.Contains(note, "2 process") {
		t.Errorf("note should report 2 io_uring-holding processes, got %q", note)
	}
	if !strings.Contains(note, "postgres") && !strings.Contains(note, "node") {
		t.Errorf("note should sample comm names, got %q", note)
	}
}

func TestIoUringProbe_MissingProcDir(t *testing.T) {
	p := ioUringProbe{procDir: filepath.Join(t.TempDir(), "no-such-proc")}
	if has, _ := p.detect(); has {
		t.Error("missing procDir — detect() must not report active")
	}
}

func TestDefaultIoUringProbe_ShapeOnly(t *testing.T) {
	p := defaultIoUringProbe()
	if p.procDir != "/proc" {
		t.Errorf("default procDir = %q, want /proc", p.procDir)
	}
}

// ---------------------------------------------------------------------
// legacyBinaryProbe
// ---------------------------------------------------------------------

func TestLegacyBinaryProbe_EmptyRoots(t *testing.T) {
	p := legacyBinaryProbe{
		ScanRoots: []string{filepath.Join(t.TempDir(), "no-such-dir")},
		MaxFiles:  100,
	}
	if has, note := p.detect(); has {
		t.Errorf("nonexistent ScanRoot — detect() = (true, %q), want false", note)
	}
}

func TestLegacyBinaryProbe_NonELFFilesSkipped(t *testing.T) {
	// Plain text and shell-script files in the scan path must not
	// trigger the probe. debug/elf rejects them; we additionally
	// short-circuit on common script extensions.
	root := t.TempDir()
	for _, name := range []string{"hello.sh", "foo.py", "manpage.1", "data.gz", "plain.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("not an ELF"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := legacyBinaryProbe{ScanRoots: []string{root}, MaxFiles: 100}
	if has, note := p.detect(); has {
		t.Errorf("non-ELF files in scan root — detect() = (true, %q), want false", note)
	}
}

func TestDefaultLegacyBinaryProbe_ShapeOnly(t *testing.T) {
	p := defaultLegacyBinaryProbe()
	if len(p.ScanRoots) != 2 {
		t.Errorf("default ScanRoots count = %d, want 2", len(p.ScanRoots))
	}
	if p.MaxFiles <= 0 {
		t.Errorf("default MaxFiles = %d, want > 0", p.MaxFiles)
	}
}

// ---------------------------------------------------------------------
// debugfsConsumerProbe
// ---------------------------------------------------------------------

func TestDebugfsConsumerProbe_EmptyHost(t *testing.T) {
	procDir := t.TempDir()
	p := debugfsConsumerProbe{
		procDir:     procDir,
		BinaryPaths: []string{filepath.Join(t.TempDir(), "no-such-bin")},
	}
	if has, note := p.detect(); has {
		t.Errorf("empty host — detect() = (true, %q), want false", note)
	}
}

func TestDebugfsConsumerProbe_DetectsInstalledBinary(t *testing.T) {
	// A bpftrace binary present on disk is enough — operator clearly
	// expects debugfs to remain available.
	root := t.TempDir()
	binPath := filepath.Join(root, "bpftrace")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := debugfsConsumerProbe{
		procDir:     t.TempDir(),
		BinaryPaths: []string{binPath},
	}
	has, note := p.detect()
	if !has {
		t.Fatalf("installed bpftrace — detect() = false (note=%q), want true", note)
	}
	if !strings.Contains(note, "bpftrace") {
		t.Errorf("note should mention bpftrace, got %q", note)
	}
}

func TestDebugfsConsumerProbe_DetectsActiveFd(t *testing.T) {
	procDir := makeFakeProcFd(t, map[string]struct {
		comm string
		fds  []string
	}{
		"700": {"intel_gpu_top", []string{"/sys/kernel/debug/dri/0/i915_gpu_info"}},
		"100": {"sshd", []string{"/dev/null"}},
	})
	p := debugfsConsumerProbe{
		procDir:     procDir,
		BinaryPaths: []string{filepath.Join(t.TempDir(), "no-such-bin")},
	}
	has, note := p.detect()
	if !has {
		t.Fatalf("active /sys/kernel/debug fd — detect() = false (note=%q), want true", note)
	}
	if !strings.Contains(note, "intel_gpu_top") {
		t.Errorf("note should mention intel_gpu_top, got %q", note)
	}
}

func TestDefaultDebugfsConsumerProbe_ShapeOnly(t *testing.T) {
	p := defaultDebugfsConsumerProbe()
	if p.procDir != "/proc" {
		t.Errorf("default procDir = %q, want /proc", p.procDir)
	}
	if len(p.BinaryPaths) == 0 {
		t.Errorf("default BinaryPaths is empty")
	}
}

// ---------------------------------------------------------------------
// SkipReason wiring for the three new groups
// ---------------------------------------------------------------------

func TestSkipReason_IoUringGate(t *testing.T) {
	clean := HostProfile{}
	if reason := clean.SkipReason("tier2.iouring"); reason != "" {
		t.Errorf("clean host: tier2.iouring SkipReason = %q, want \"\"", reason)
	}

	active := HostProfile{IsIoUringUser: true, IoUringUserNote: "2 process(es) (e.g. postgres, node)"}
	reason := active.SkipReason("tier2.iouring")
	if reason == "" {
		t.Fatal("active io_uring host: SkipReason returned empty")
	}
	if !strings.Contains(reason, "postgres") {
		t.Errorf("SkipReason = %q, expected to surface the probe note", reason)
	}
}

func TestSkipReason_LegacyCompatGate(t *testing.T) {
	clean := HostProfile{}
	if reason := clean.SkipReason("tier3.legacycompat"); reason != "" {
		t.Errorf("clean host: tier3.legacycompat SkipReason = %q, want \"\"", reason)
	}

	legacy := HostProfile{HasLegacyBinaries: true, LegacyBinariesNote: "e.g. /usr/bin/oldtool"}
	reason := legacy.SkipReason("tier3.legacycompat")
	if reason == "" {
		t.Fatal("host with legacy binaries: SkipReason returned empty")
	}
	if !strings.Contains(reason, "/usr/bin/oldtool") {
		t.Errorf("SkipReason = %q, expected to surface the probe note", reason)
	}
}

func TestSkipReason_ObservabilityGate(t *testing.T) {
	clean := HostProfile{}
	if reason := clean.SkipReason("tier3.observability"); reason != "" {
		t.Errorf("clean host: tier3.observability SkipReason = %q, want \"\"", reason)
	}

	consumers := HostProfile{HasDebugfsConsumers: true, DebugfsConsumersNote: "bpftrace, intel_gpu_top"}
	reason := consumers.SkipReason("tier3.observability")
	if reason == "" {
		t.Fatal("host with debugfs consumers: SkipReason returned empty")
	}
	if !strings.Contains(reason, "bpftrace") {
		t.Errorf("SkipReason = %q, expected to surface the probe note", reason)
	}
}

// ---------------------------------------------------------------------
// AcceptValues coverage for the relaxed audit rules
// ---------------------------------------------------------------------

func TestAcceptValues_PerfEventParanoid(t *testing.T) {
	var rule *SysctlRule
	for i, r := range KSPPSysctls {
		if r.ID == "KSEC-SCT-kspp.kernel-005" {
			rule = &KSPPSysctls[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("KSEC-SCT-kspp.kernel-005 (perf_event_paranoid) not found in KSPPSysctls")
	}
	if rule.Value != "3" {
		t.Errorf("canonical perf_event_paranoid value = %q, want 3", rule.Value)
	}
	wantAccept := map[string]bool{"2": false, "4": false}
	for _, v := range rule.AcceptValues {
		if _, ok := wantAccept[v]; ok {
			wantAccept[v] = true
		}
	}
	for v, found := range wantAccept {
		if !found {
			t.Errorf("AcceptValues missing %q (should be also-green)", v)
		}
	}
}

func TestAcceptValues_MmapMinAddr(t *testing.T) {
	var rule *SysctlRule
	for i, r := range KSPPSysctls {
		if r.ID == "KSEC-SCT-kspp.kernel-007" {
			rule = &KSPPSysctls[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("KSEC-SCT-kspp.kernel-007 (vm.mmap_min_addr) not found in KSPPSysctls")
	}
	if rule.Key != "vm.mmap_min_addr" {
		t.Errorf("KSEC-SCT-kspp.kernel-007 Key = %q, want vm.mmap_min_addr", rule.Key)
	}
	if rule.Value != "65536" {
		t.Errorf("canonical mmap_min_addr value = %q, want 65536", rule.Value)
	}
	wantAccept := map[string]bool{"131072": false, "262144": false}
	for _, v := range rule.AcceptValues {
		if _, ok := wantAccept[v]; ok {
			wantAccept[v] = true
		}
	}
	for v, found := range wantAccept {
		if !found {
			t.Errorf("AcceptValues missing %q (stricter live value should be also-green)", v)
		}
	}
}

func TestAcceptValues_IoUringDisabled(t *testing.T) {
	var rule *SysctlRule
	for i, r := range Tier2Sysctls {
		if r.ID == "KSEC-SCT-tier2.iouring-001" {
			rule = &Tier2Sysctls[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("KSEC-SCT-tier2.iouring-001 not found in Tier2Sysctls")
	}
	if rule.Value != "2" {
		t.Errorf("canonical io_uring_disabled value = %q, want 2", rule.Value)
	}
	found := false
	for _, v := range rule.AcceptValues {
		if v == "1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AcceptValues missing \"1\" (privileged-only mode should be also-green)")
	}
}
