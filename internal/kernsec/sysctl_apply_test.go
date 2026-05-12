package kernsec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withStubLiveSysctl swaps readLiveSysctl for a map-backed stub and
// restores the original at test end. Used to drive the sticky-lock
// advisory branch without touching /proc/sys.
func withStubLiveSysctl(t *testing.T, values map[string]string) {
	t.Helper()
	orig := readLiveSysctl
	readLiveSysctl = func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	}
	t.Cleanup(func() { readLiveSysctl = orig })
}

func TestRenderSysctlFile_Empty(t *testing.T) {
	got := string(RenderSysctlFile(nil))
	if !strings.Contains(got, "# Managed by cfm kernsec") {
		t.Errorf("missing header in:\n%s", got)
	}
	if !strings.Contains(got, "no sysctl rules selected") {
		t.Errorf("missing empty-set marker in:\n%s", got)
	}
}

func TestRenderSysctlFile_HappyPath(t *testing.T) {
	rules := []SysctlRule{
		{Key: "kernel.kptr_restrict", Value: "2"},
		{Key: "fs.protected_hardlinks", Value: "1"},
	}
	got := string(RenderSysctlFile(rules))
	for _, want := range []string{
		"# Managed by cfm kernsec",
		"# Generated from /etc/cfm/kernsec.conf",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// At least one of the rules will exist on this host (kptr_restrict
	// has been mainline since 2.6.38). The rest depends on the runtime
	// kernel — we only assert the header structure.
}

// withTempSysctlPath redirects SysctlPath to a per-test temp file.
func withTempSysctlPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := SysctlPath
	SysctlPath = filepath.Join(dir, "99-cfm-kernsec.conf")
	t.Cleanup(func() { SysctlPath = orig })
	return SysctlPath
}

// stubSysctlSetCommand records every (key, value) it's invoked with
// and returns the response from the first matching rule.
type sysctlStub struct {
	calls   []string
	failOn  map[string]error
	failOut map[string]string
}

func newSysctlStub() *sysctlStub {
	return &sysctlStub{
		failOn:  map[string]error{},
		failOut: map[string]string{},
	}
}

func (s *sysctlStub) cmd(key, value string) ([]byte, error) {
	s.calls = append(s.calls, key+"="+value)
	if err, ok := s.failOn[key]; ok {
		return []byte(s.failOut[key]), err
	}
	return []byte(key + " = " + value + "\n"), nil
}

func TestLoadSysctl_AppliesEveryNonCommentLine(t *testing.T) {
	withTempSysctlPath(t)
	content := []byte("# managed\n" +
		"kernel.kptr_restrict = 2\n" +
		"fs.protected_hardlinks = 1\n" +
		"\n" +
		"# trailing comment\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	stub := newSysctlStub()
	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	if err := LoadSysctl(); err != nil {
		t.Fatalf("expected nil error on clean apply, got %v", err)
	}
	want := []string{
		"kernel.kptr_restrict=2",
		"fs.protected_hardlinks=1",
	}
	if len(stub.calls) != len(want) {
		t.Fatalf("expected %d calls, got %d: %v", len(want), len(stub.calls), stub.calls)
	}
	for i, w := range want {
		if stub.calls[i] != w {
			t.Errorf("call %d: got %q, want %q", i, stub.calls[i], w)
		}
	}
}

func TestLoadSysctl_ContinuesOnPerKeyFailure(t *testing.T) {
	withTempSysctlPath(t)
	content := []byte("kernel.kptr_restrict = 2\n" +
		"kernel.would_be_rejected = 99\n" +
		"fs.protected_hardlinks = 1\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	stub := newSysctlStub()
	stub.failOn["kernel.would_be_rejected"] = errors.New("exit status 1")
	stub.failOut["kernel.would_be_rejected"] = "sysctl: setting key \"kernel.would_be_rejected\": Invalid argument"

	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	err := LoadSysctl()
	if err == nil {
		t.Fatal("expected aggregated error on per-key failure, got nil")
	}
	// Critical: every key was attempted, not just up to the failure.
	if len(stub.calls) != 3 {
		t.Errorf("expected all 3 keys attempted (continue-on-error), got %d: %v",
			len(stub.calls), stub.calls)
	}
	// Error names the specific key + kernel response.
	msg := err.Error()
	if !strings.Contains(msg, "kernel.would_be_rejected") {
		t.Errorf("error should name the rejected key: %v", err)
	}
	if !strings.Contains(msg, "Invalid argument") {
		t.Errorf("error should include the kernel response: %v", err)
	}
	// And the count.
	if !strings.Contains(msg, "1 key(s)") {
		t.Errorf("error should report the failure count: %v", err)
	}
}

func TestLoadSysctl_AggregatesMultipleFailures(t *testing.T) {
	withTempSysctlPath(t)
	content := []byte("a.b = 1\nc.d = 2\ne.f = 3\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	stub := newSysctlStub()
	stub.failOn["a.b"] = errors.New("exit 1")
	stub.failOn["e.f"] = errors.New("exit 1")
	stub.failOut["a.b"] = "permission denied"
	stub.failOut["e.f"] = "no such file"

	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	err := LoadSysctl()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "2 key(s)") {
		t.Errorf("error should count 2 failures: %v", err)
	}
	if !strings.Contains(msg, "a.b") || !strings.Contains(msg, "e.f") {
		t.Errorf("error should name both failed keys: %v", err)
	}
	if !strings.Contains(msg, "permission denied") || !strings.Contains(msg, "no such file") {
		t.Errorf("error should include both kernel responses: %v", err)
	}
	// c.d was applied successfully between the two failures.
	if len(stub.calls) != 3 {
		t.Errorf("expected all 3 keys attempted, got %d: %v", len(stub.calls), stub.calls)
	}
}

func TestLoadSysctl_FileMissingReturnsError(t *testing.T) {
	withTempSysctlPath(t)
	// Don't create the file.
	if err := LoadSysctl(); err == nil {
		t.Fatal("expected error reading missing file")
	}
}

func TestRenderSysctlFile_SkippedRulesAreCommented(t *testing.T) {
	rules := []SysctlRule{
		{Key: "kernel.this.does.not.exist.zzz", Value: "1"},
	}
	got := string(RenderSysctlFile(rules))
	if !strings.Contains(got, "# skipped") {
		t.Errorf("missing skip line for nonexistent key in:\n%s", got)
	}
	// No live (uncommented) line should set the key.
	for _, line := range strings.Split(got, "\n") {
		ln := strings.TrimSpace(line)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "kernel.this.does.not.exist.zzz") {
			t.Errorf("nonexistent key emitted as live rule line %q in:\n%s", ln, got)
		}
	}
}

func TestLoadSysctlTo_SkipsWriteWhenLiveInAcceptValues(t *testing.T) {
	// The kernel.unprivileged_bpf_disabled scenario from the field:
	// live=1 (CONFIG_BPF_UNPRIV_DEFAULT_OFF=y kernels boot at 1 and
	// lock the knob), target=2. AcceptValues=["1"] means 1 is already
	// the security stance we want at runtime; the loader must NOT call
	// `sysctl -w` (the kernel would EPERM) and must NOT print any
	// advisory — there is nothing to advise about. The status output
	// shows OK for live=1 separately; this test is purely about the
	// apply path being quiet for an already-fine knob.
	withTempSysctlPath(t)
	content := []byte("kernel.kptr_restrict = 2\n" +
		"kernel.unprivileged_bpf_disabled = 2\n" +
		"fs.protected_hardlinks = 1\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	stub := newSysctlStub()
	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	withStubLiveSysctl(t, map[string]string{
		"kernel.unprivileged_bpf_disabled": "1",
	})

	var buf bytes.Buffer
	err := LoadSysctlTo(&buf)
	if err != nil {
		t.Fatalf("acceptable-variant skip must not surface as a failure; got: %v", err)
	}

	for _, c := range stub.calls {
		if strings.HasPrefix(c, "kernel.unprivileged_bpf_disabled=") {
			t.Errorf("loader must NOT call `sysctl -w` for sticky knob whose live value is in AcceptValues; calls: %v", stub.calls)
		}
	}
	if len(stub.calls) != 2 {
		t.Errorf("expected the other two keys to apply normally, got calls: %v", stub.calls)
	}
	if buf.Len() != 0 {
		t.Errorf("no advisory expected for accepted-variant skip; got:\n%s", buf.String())
	}
}

func TestLoadSysctlTo_SkipsWriteWhenLiveEqualsTarget(t *testing.T) {
	// Same logic as the accept-variant path, but for live=target.
	// On locked kernels a same-value write still EPERMs because the
	// kernel rejects every write once the knob is non-zero. Skipping
	// the call is the only way to avoid noise on hosts that boot
	// straight to 2 (CONFIG_BPF_UNPRIV_DEFAULT_OFF=y variants that
	// pick 2 instead of 1).
	withTempSysctlPath(t)
	content := []byte("kernel.unprivileged_bpf_disabled = 2\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	stub := newSysctlStub()
	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	withStubLiveSysctl(t, map[string]string{
		"kernel.unprivileged_bpf_disabled": "2",
	})

	var buf bytes.Buffer
	if err := LoadSysctlTo(&buf); err != nil {
		t.Fatalf("same-value sticky knob must not error; got: %v", err)
	}
	if len(stub.calls) != 0 {
		t.Errorf("loader must skip sysctl -w when live already at target; calls: %v", stub.calls)
	}
}

func TestLoadSysctlTo_StickyEPERMWithZeroLiveIsHardFailure(t *testing.T) {
	// If the live value is still 0 the kernel hasn't locked the knob,
	// so EPERM on a write is a genuine failure (LSM block, container
	// without CAP_SYS_ADMIN, etc) — not the sticky-lock case. The
	// advisory path must NOT swallow it.
	withTempSysctlPath(t)
	content := []byte("kernel.unprivileged_bpf_disabled = 2\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	stub := newSysctlStub()
	stub.failOn["kernel.unprivileged_bpf_disabled"] = errors.New("exit status 1")
	stub.failOut["kernel.unprivileged_bpf_disabled"] = "Operation not permitted"

	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	withStubLiveSysctl(t, map[string]string{
		"kernel.unprivileged_bpf_disabled": "0",
	})

	err := LoadSysctlTo(io.Discard)
	if err == nil {
		t.Fatal("EPERM with live=0 must surface as a hard failure (no sticky lock yet)")
	}
	if !strings.Contains(err.Error(), "kernel.unprivileged_bpf_disabled") {
		t.Errorf("error should name the rejected key; got: %v", err)
	}
}

func TestLoadSysctlTo_NonStickyKeyAlwaysHardFails(t *testing.T) {
	// Plain EPERM on a non-sticky key (e.g. an LSM block) must remain
	// a hard failure even if its live value is "non-zero" — the sticky
	// advisory only applies to the documented one-way knobs.
	withTempSysctlPath(t)
	content := []byte("kernel.kptr_restrict = 2\n")
	if err := os.WriteFile(SysctlPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	stub := newSysctlStub()
	stub.failOn["kernel.kptr_restrict"] = errors.New("exit status 1")
	stub.failOut["kernel.kptr_restrict"] = "Operation not permitted"

	origCmd := sysctlSetCommand
	sysctlSetCommand = stub.cmd
	t.Cleanup(func() { sysctlSetCommand = origCmd })

	withStubLiveSysctl(t, map[string]string{"kernel.kptr_restrict": "1"})

	err := LoadSysctlTo(io.Discard)
	if err == nil {
		t.Fatal("non-sticky key EPERM must be a hard failure")
	}
}

func TestStickyMismatchNote_NextCmdlineHasArg(t *testing.T) {
	note, ok := stickyMismatchNote(
		"kernel.unprivileged_bpf_disabled", "1", "2",
		[]string{"ro", "quiet", "unprivileged_bpf_disabled=2", "tsx=off"},
	)
	if !ok {
		t.Fatal("expected sticky-mismatch note for unprivileged_bpf_disabled")
	}
	if !strings.Contains(note, "next-boot cmdline") {
		t.Errorf("note should tell operator the boot arg is staged; got: %s", note)
	}
	if !strings.Contains(note, "reboot") {
		t.Errorf("note should mention reboot; got: %s", note)
	}
}

func TestStickyMismatchNote_NextCmdlineMissingArg(t *testing.T) {
	note, ok := stickyMismatchNote(
		"kernel.unprivileged_bpf_disabled", "1", "2",
		[]string{"ro", "quiet"},
	)
	if !ok {
		t.Fatal("expected sticky-mismatch note")
	}
	if !strings.Contains(note, "add `unprivileged_bpf_disabled=2`") {
		t.Errorf("note should tell operator to add the boot arg; got: %s", note)
	}
	if !strings.Contains(note, "cfm kernsec apply") {
		t.Errorf("note should point at the apply command; got: %s", note)
	}
}

func TestStickyMismatchNote_NotASticky(t *testing.T) {
	_, ok := stickyMismatchNote("kernel.kptr_restrict", "0", "2", nil)
	if ok {
		t.Error("non-sticky key must not trigger the special-case note")
	}
}

func TestStickyMismatchNote_LiveZeroIsPlainDrift(t *testing.T) {
	_, ok := stickyMismatchNote(
		"kernel.unprivileged_bpf_disabled", "0", "2", nil,
	)
	if ok {
		t.Error("live=0 means no kernel lock yet — should be plain drift, not sticky")
	}
}

func TestApplySysctls_ReconciledDocsOnlySelection(t *testing.T) {
	rules := Resolve(&Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}, HostProfile{}).ApplySysctls()
	selected := map[string]bool{}
	for _, r := range rules {
		selected[r.Key] = true
	}
	for _, key := range []string{
		"vm.unprivileged_userfaultfd",
		"vm.mmap_rnd_bits",
		"vm.mmap_rnd_compat_bits",
		"kernel.warn_limit",
		"kernel.oops_limit",
		"fs.suid_dumpable",
		"dev.tty.ldisc_autoload",
		"kernel.sysrq",
	} {
		if !selected[key] {
			t.Errorf("tier1 ApplySysctls missing %s", key)
		}
	}
	for _, key := range []string{"kernel.core_pattern", "kernel.panic_on_oops", "kernel.panic"} {
		if selected[key] {
			t.Errorf("tier1 ApplySysctls unexpectedly selected tier2 key %s", key)
		}
	}
}
