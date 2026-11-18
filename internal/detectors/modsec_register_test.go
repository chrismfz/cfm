package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
