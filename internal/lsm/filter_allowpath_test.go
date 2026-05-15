//go:build linux

package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeProcCmdline drops a fake /proc/<pid>/cmdline by overriding the
// path that cmdlineHasPathPrefix reads. We do this with a temp dir
// and a process whose /proc/self/cmdline we know — easier than mocking
// the filesystem.
func TestCmdlineHasPathPrefix_LiveSelf(t *testing.T) {
	// Read /proc/self/cmdline directly to confirm what's actually
	// there (Go test binary path). Use one of its arguments as a
	// known-good prefix.
	b, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		t.Skipf("no /proc/self/cmdline on this host: %v", err)
	}
	args := strings.Split(string(b), "\x00")
	if len(args) == 0 || args[0] == "" {
		t.Skip("empty /proc/self/cmdline")
	}
	// args[0] is the test binary; use its directory as prefix.
	prefix := filepath.Dir(args[0]) + "/"
	pid := uint32(os.Getpid())
	if !cmdlineHasPathPrefix(pid, []string{prefix}) {
		t.Errorf("expected prefix %q to match /proc/%d/cmdline (args[0]=%q)", prefix, pid, args[0])
	}
	if cmdlineHasPathPrefix(pid, []string{"/definitely/not/this/path/"}) {
		t.Errorf("unrelated prefix unexpectedly matched")
	}
}

func TestCmdlineHasPathPrefix_MissingPidIsFalseNotPanic(t *testing.T) {
	// PID 1 always exists; pick a deliberately-impossible value.
	if got := cmdlineHasPathPrefix(2_000_000_001, []string{"/anything/"}); got {
		t.Error("nonexistent pid must return false (best-effort, never panic)")
	}
}

func TestParseConf_AllowPath(t *testing.T) {
	body := `enabled = true
[allow]
allow_path = /usr/share/lve-stats/
allow_path = /opt/cloudlinux/
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"/usr/share/lve-stats/", "/opt/cloudlinux/"}
	if len(c.GlobalAllowPath) != len(want) {
		t.Fatalf("GlobalAllowPath = %v, want %v", c.GlobalAllowPath, want)
	}
	for i, w := range want {
		if c.GlobalAllowPath[i] != w {
			t.Errorf("entry %d = %q, want %q", i, c.GlobalAllowPath[i], w)
		}
	}
}

func TestParseConf_AllowPath_RejectsRelative(t *testing.T) {
	body := `[allow]
allow_path = usr/share/lve-stats/
`
	if _, err := ParseConf(strings.NewReader(body)); err == nil {
		t.Fatal("expected parse error for relative prefix")
	}
}

func TestParseConf_AllowPath_RejectsRootSlash(t *testing.T) {
	// `/` would match every absolute cmdline arg, effectively
	// turning every allow_path-consuming detector into a no-op.
	body := `[allow]
allow_path = /
`
	if _, err := ParseConf(strings.NewReader(body)); err == nil {
		t.Fatal("expected parse error for `/` as allow_path")
	}
}

func TestParseConf_AllowPath_RejectsMissingTrailingSlash(t *testing.T) {
	body := `[allow]
allow_path = /usr/share/lve-stats
`
	if _, err := ParseConf(strings.NewReader(body)); err == nil {
		t.Fatal("expected parse error for prefix without trailing slash")
	}
}

func TestEventFilter_AllowPath_RequiresPolicyOptIn(t *testing.T) {
	// EXEC-001 is not in allowPathPolicy. Even if we configure
	// a prefix at the global level, no rule should be installed for
	// EXEC-001.
	c := &Conf{
		GlobalAllowPath: []string{"/usr/share/lve-stats/"},
	}
	f := BuildEventFilter(c)
	rule, ok := f.rules[PolicyMemfdExec]
	if ok && len(rule.pathPrefixes) > 0 {
		t.Errorf("EXEC-001 must not consume allow_path; got %v", rule.pathPrefixes)
	}
	// CRED-002 IS in allowPathPolicy — must have it installed.
	rule, ok = f.rules[PolicyCredEscal]
	if !ok || len(rule.pathPrefixes) == 0 {
		t.Errorf("CRED-002 must consume allow_path; rules=%v", f.rules[PolicyCredEscal])
	}
}

func TestEventFilter_AllowPath_MatchesLiveCmdline(t *testing.T) {
	b, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		t.Skipf("no /proc/self/cmdline: %v", err)
	}
	args := strings.Split(string(b), "\x00")
	if len(args) == 0 || args[0] == "" {
		t.Skip("empty cmdline")
	}
	prefix := filepath.Dir(args[0]) + "/"

	c := &Conf{GlobalAllowPath: []string{prefix}}
	f := BuildEventFilter(c)
	ev := Event{
		PolicyID: PolicyCredEscal,
		PID:      uint32(os.Getpid()),
		Comm:     "irrelevant",
		Filename: "irrelevant",
	}
	if !f.Match(ev) {
		t.Errorf("filter should match event whose /proc/<pid>/cmdline starts with %q", prefix)
	}
}

func TestDefaultGlobalAllowPath_SeededWithCloudLinuxEntries(t *testing.T) {
	c := DefaultConf()
	if len(c.GlobalAllowPath) == 0 {
		t.Fatal("DefaultConf().GlobalAllowPath is empty — CloudLinux entries should be seeded")
	}
	want := []string{"/usr/share/lve-stats/", "/opt/cloudlinux/"}
	for _, w := range want {
		found := false
		for _, e := range c.GlobalAllowPath {
			if e == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultGlobalAllowPath missing %q", w)
		}
	}
}

func TestFormatConf_AllowPath_RoundTrip(t *testing.T) {
	original := DefaultConf()
	original.GlobalAllowPath = append(original.GlobalAllowPath, "/srv/test-only/")

	rendered := FormatConf(original)
	parsed, err := ParseConf(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ParseConf(FormatConf): %v\n--- rendered ---\n%s", err, rendered)
	}
	found := false
	for _, e := range parsed.GlobalAllowPath {
		if e == "/srv/test-only/" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("round-trip lost /srv/test-only/; rendered:\n%s", rendered)
	}
}
