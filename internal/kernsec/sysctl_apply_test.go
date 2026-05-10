package kernsec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
