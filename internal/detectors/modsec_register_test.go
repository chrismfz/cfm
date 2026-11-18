package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withModsecCandidates points the MODE=auto scan at test files.
func withModsecCandidates(t *testing.T, paths ...string) {
	t.Helper()
	old := modsecCandidates
	modsecCandidates = paths
	t.Cleanup(func() { modsecCandidates = old })
}

func TestResolveModsecLogPath(t *testing.T) {
	dir := t.TempDir()
	quiet := filepath.Join(dir, "quiet_error_log")
	busy := filepath.Join(dir, "busy_error_log")
	pinned := filepath.Join(dir, "pinned_error_log")
	missing := filepath.Join(dir, "apache2_error_log")
	deny := "[client 203.0.113.9] ModSecurity: Access denied with code 403 (phase 2).\n"
	for p, body := range map[string]string{quiet: "noise\n", busy: deny + deny, pinned: ""} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	withModsecCandidates(t, filepath.Join(dir, "absent"), quiet, busy)

	cases := []struct {
		name, mode, logPath string
		score               bool
		want                string
		warn                bool
	}{
		{"explicit existing path wins in auto", "auto", pinned, true, pinned, false},
		{"MODE=file keeps a missing pin verbatim", "file", missing, true, missing, false},
		// The stock-conf bug: an explicit path that is not there no longer
		// disables the scan.
		{"missing explicit path in auto scans", "auto", missing, true, busy, true},
		{"LOG_PATH=auto scans", "auto", "auto", true, busy, false},
		{"empty LOG_PATH scans", "auto", "", true, busy, false},
		{"MODE=file without a path scans", "file", "auto", true, busy, false},
		// Stat-only (the source probe): the first existing candidate.
		{"stat-only takes the first existing", "auto", missing, false, quiet, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var score func(string, int64) (int, error)
			if c.score {
				score = scoreFile
			}
			res := resolveModsecLogPath(c.mode, c.logPath, modsecStat, score)
			if res.Path != c.want {
				t.Fatalf("path = %q (%s), want %q", res.Path, res.Reason, c.want)
			}
			if (res.Warn != "") != c.warn {
				t.Fatalf("warn = %q, want warn=%v", res.Warn, c.warn)
			}
		})
	}
}

func TestResolveModsecLogPathQuietHostTakesFirstExisting(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("no denials\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	withModsecCandidates(t, filepath.Join(dir, "absent"), a, b)
	res := resolveModsecLogPath("auto", "auto", modsecStat, scoreFile)
	if res.Path != a {
		t.Fatalf("path = %q, want the first existing candidate %q", res.Path, a)
	}
}

func TestResolveModsecLogPathNothingAnywhere(t *testing.T) {
	dir := t.TempDir()
	withModsecCandidates(t, filepath.Join(dir, "absent"))
	// No candidate and no explicit path: no source.
	if res := resolveModsecLogPath("auto", "auto", modsecStat, scoreFile); res.Path != "" {
		t.Fatalf("path = %q, want none", res.Path)
	}
	// No candidate, explicit missing path: keep it so it self-heals.
	missing := filepath.Join(dir, "later")
	res := resolveModsecLogPath("auto", missing, modsecStat, scoreFile)
	if res.Path != missing || res.Warn == "" {
		t.Fatalf("got %+v, want the explicit path kept with a warning", res)
	}
}

func TestProbeModsecSource(t *testing.T) {
	dir := t.TempDir()
	found := filepath.Join(dir, "error_log")
	if err := os.WriteFile(found, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withModsecCandidates(t, found)
	ok, msg := probeModsecSource(KV{"MODE": "auto", "LOG_PATH": filepath.Join(dir, "gone")})
	if !ok || !strings.Contains(msg, found) || !strings.Contains(msg, "does not exist") {
		t.Fatalf("probe = %v %q, want ok on the scanned file with the warning", ok, msg)
	}
	ok, msg = probeModsecSource(KV{"MODE": "auto"})
	if !ok || !strings.Contains(msg, found) {
		t.Fatalf("probe (no LOG_PATH) = %v %q", ok, msg)
	}
	if ok, _ := probeModsecSource(KV{"MODE": "journal"}); ok {
		t.Fatal("unknown MODE probed ok")
	}
}

// resetModsecPicks isolates the package-level scored-pick cache.
func resetModsecPicks(t *testing.T) {
	t.Helper()
	modsecPicks.Lock()
	old := modsecPicks.m
	modsecPicks.m = map[string]modsecPick{}
	modsecPicks.Unlock()
	t.Cleanup(func() {
		modsecPicks.Lock()
		modsecPicks.m = old
		modsecPicks.Unlock()
	})
}

// A log that appears after the build changes modsec's part of the config
// signature, so the manager rebuilds the detector onto it.
func TestModsecSigPathFollowsALogThatAppears(t *testing.T) {
	resetModsecPicks(t)
	dir := t.TempDir()
	errLog := filepath.Join(dir, "error_log")
	withModsecCandidates(t, errLog)
	kv := KV{"MODE": "auto", "LOG_PATH": "auto"}
	before := modsecSigPath(kv, time.Now())
	if err := os.WriteFile(errLog, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := modsecSigPath(kv, time.Now())
	if before == after || !strings.Contains(after, errLog) {
		t.Fatalf("sig part did not follow the new log: before=%q after=%q", before, after)
	}
}

// A quiet pick is re-scored every modsecRescoreEvery: denials that start in
// another candidate move the signature once, and a busy pick is sticky.
func TestModsecSigPathRescoresWhileQuiet(t *testing.T) {
	resetModsecPicks(t)
	dir := t.TempDir()
	errLog := filepath.Join(dir, "error_log")
	audit := filepath.Join(dir, "modsec_audit.log")
	other := filepath.Join(dir, "other_error_log")
	for _, p := range []string{errLog, audit, other} {
		if err := os.WriteFile(p, []byte("quiet\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	withModsecCandidates(t, errLog, audit, other)
	kv := KV{"MODE": "auto"}
	t0 := time.Now()
	quiet := modsecSigPath(kv, t0)
	deny := "ModSecurity: Access denied with code 403 (phase 2).\n"
	if err := os.WriteFile(audit, []byte(deny), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := modsecSigPath(kv, t0.Add(time.Minute)); got != quiet {
		t.Fatalf("re-scored before modsecRescoreEvery: %q", got)
	}
	busy := modsecSigPath(kv, t0.Add(modsecRescoreEvery))
	if busy == quiet || !strings.HasSuffix(busy, audit) {
		t.Fatalf("quiet pick not re-scored onto the audit log: %q", busy)
	}
	// Sticky: more denials elsewhere never move a busy pick.
	if err := os.WriteFile(other, []byte(deny+deny+deny), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := modsecSigPath(kv, t0.Add(10*modsecRescoreEvery)); got != busy {
		t.Fatalf("busy pick moved: %q -> %q", busy, got)
	}
	// An explicit existing path is used as is, no scan.
	if got := modsecSigPath(KV{"MODE": "auto", "LOG_PATH": other}, t0); got != other {
		t.Fatalf("explicit path sig = %q", got)
	}
}

// Two candidates that are one file (EA4's symlinked log dirs) are scored once.
func TestResolveModsecLogPathScoresASymlinkedFileOnce(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "error_log")
	link := filepath.Join(dir, "link_error_log")
	if err := os.WriteFile(real, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	withModsecCandidates(t, real, link)
	n := 0
	resolveModsecLogPath("auto", "auto", modsecStat, func(string, int64) (int, error) { n++; return 0, nil })
	if n != 1 {
		t.Fatalf("scored %d times, want 1", n)
	}
}

func TestProbeModsecSourceWording(t *testing.T) {
	dir := t.TempDir()
	found := filepath.Join(dir, "error_log")
	if err := os.WriteFile(found, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withModsecCandidates(t, found)
	_, msg := probeModsecSource(KV{"MODE": "auto"})
	if !strings.Contains(msg, "may tail another") || strings.Contains(msg, "tails the one with the most") {
		t.Fatalf("probe msg = %q", msg)
	}
	_, msg = probeModsecSource(KV{"MODE": "auto", "LOG_PATH": found})
	if strings.Contains(msg, "candidate") {
		t.Fatalf("explicit path probe mentions candidates: %q", msg)
	}
}
