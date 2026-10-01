package hostsecrets

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	strongA = "0123456789abcdef0123456789abcdef0123456789abcdef"
	strongB = "fedcba9876543210fedcba9876543210fedcba9876543210"
)

var hex48 = regexp.MustCompile(`^[0-9a-f]{48}$`)

// useTempDir points Dir at a fresh temp dir for one test: a test must never
// write the live /var/lib/cfm/secrets (CLAUDE.md §5).
func useTempDir(t *testing.T) string {
	t.Helper()
	old, oldDelay := Dir, readRetryDelay
	Dir = filepath.Join(t.TempDir(), "secrets")
	readRetryDelay = time.Millisecond
	forgetProcess()
	t.Cleanup(func() { Dir, readRetryDelay = old, oldDelay; forgetProcess() })
	return Dir
}

// forgetProcess drops the per-process token caches, so each test starts like
// a fresh daemon.
func forgetProcess() { forget() }

func stored(key string) string {
	v, _ := readStore(key)
	return v
}

// The migration: an empty store takes the node's detectors.conf token, so no
// visitor's challenge cookie is invalidated by the move.
func TestResolveEmptyStoreCopiesTheConfToken(t *testing.T) {
	dir := useTempDir(t)
	tok, src, err := Resolve(ChallengeToken, strongA)
	if err != nil || tok != strongA || src != SourceConf {
		t.Fatalf("Resolve = (%q, %q, %v), want (strongA, %q, nil)", tok, src, err, SourceConf)
	}
	if got := stored(ChallengeToken); got != strongA {
		t.Fatalf("store = %q, want the detectors.conf token copied", got)
	}
	for path, want := range map[string]os.FileMode{Path(ChallengeToken): 0o600, dir: 0o700} {
		if fi, err := os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		} else if fi.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
	// Setting the line back to placeholder keeps the same secret.
	if tok, src, _ := Resolve(ChallengeToken, "placeholder"); tok != strongA || src != SourceStore {
		t.Fatalf("after placeholder: Resolve = (%q, %q), want the stored strongA", tok, src)
	}
}

// Once a token is stored, detectors.conf is never consulted for it again,
// whatever it holds: an older binary after a rollback, or an operator, may
// write a different one there.
func TestResolveStoreWinsOverTheConf(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, strongB)
	if err != nil || tok != strongA || src != SourceStore || stored(ChallengeToken) != strongA {
		t.Fatalf("Resolve = (%q, %q, %v), store %q; want the stored strongA, untouched", tok, src, err, stored(ChallengeToken))
	}
}

func TestResolveGeneratesOnceThenReuses(t *testing.T) {
	useTempDir(t)
	tok, src, err := Resolve(ChallengeToken, "placeholder")
	if err != nil || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("first start: Resolve = (%q, %q, %v), want a generated 48-hex token", tok, src, err)
	}
	forgetProcess() // a restart
	again, src2, err := Resolve(ChallengeToken, "")
	if err != nil || again != tok || src2 != SourceStore {
		t.Fatalf("restart: Resolve = (%q, %q, %v), want the same token from the store", again, src2, err)
	}
	if bridge, _, _ := Resolve(BridgeToken, ""); bridge == tok {
		t.Fatal("OPENRESTY_TOKEN and CHALLENGE_TOKEN must not share a value")
	}
}

// Rotation = delete the store file: the next Resolve generates a new token
// (detectors.conf at placeholder), never brings the old one back.
func TestResolveRotationByDeletingTheFile(t *testing.T) {
	useTempDir(t)
	old, _, err := Resolve(ChallengeToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(Path(ChallengeToken)); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, "placeholder")
	if err != nil || src != SourceGenerated || tok == old {
		t.Fatalf("after rotation: Resolve = (%q, %q, %v), want a NEW generated token", tok, src, err)
	}
}

// A token file that exists but holds no usable token (an operator's token
// being written, a short or quoted one to fix, an empty file mid-write) is
// never overwritten: the process runs the conf token, or a generated one,
// unstored, and says so.
func TestResolveNeverOverwritesAnUnusableStore(t *testing.T) {
	for name, tc := range map[string]struct{ content, legacy, want string }{
		"placeholder, conf token": {"placeholder\n", strongA, strongA},
		"quoted, no conf token":   {`"` + strongA + `"` + "\n", "", ""},
		"short, conf placeholder": {"short\n", "placeholder", ""},
		"empty file, conf token":  {"", strongB, strongB},
	} {
		t.Run(name, func(t *testing.T) {
			dir := useTempDir(t)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(Path(ChallengeToken), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			tok, _, err := Resolve(ChallengeToken, tc.legacy)
			if !errors.Is(err, ErrStoreUnusable) {
				t.Fatalf("Resolve err = %v, want ErrStoreUnusable", err)
			}
			if b, _ := os.ReadFile(Path(ChallengeToken)); string(b) != tc.content {
				t.Fatalf("token file rewritten to %q, want it untouched", b)
			}
			if tc.want != "" && tok != tc.want {
				t.Fatalf("token = %q, want %q", tok, tc.want)
			}
			if tc.want == "" && !hex48.MatchString(tok) {
				t.Fatalf("token = %q, want a generated one", tok)
			}
			if got := Effective(ChallengeToken, tc.legacy); got != "" {
				t.Fatalf("Effective = %q, want \"\" (the probe flags the file)", got)
			}
		})
	}
}

// A symlink in place of a token file is never followed (the root daemon would
// read, and mirror to the edge, whatever it points at): it is replaced by a
// real file, and its target is left alone.
func TestResolveNeverFollowsASymlinkedStore(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "other-secret")
	if err := os.WriteFile(target, []byte(strongB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, Path(ChallengeToken)); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, "")
	if err != nil || tok == strongB || src != SourceGenerated {
		t.Fatalf("Resolve = (%q, %q, %v), want a generated token, not the link target", tok, src, err)
	}
	if fi, err := os.Lstat(Path(ChallengeToken)); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("token file is not a regular file after Resolve (err %v)", err)
	}
	if b, _ := os.ReadFile(target); string(b) != strongB+"\n" {
		t.Fatalf("the link target was changed: %q", b)
	}
}

// A store that exists but cannot be read (EACCES, EIO; here a directory in
// its place) must neither rotate the running token nor be overwritten.
func TestResolveUnreadableStoreKeepsTheRunningToken(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(BridgeToken, strongA); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(Path(BridgeToken)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(Path(BridgeToken), 0o700); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(BridgeToken, strongB)
	if !errors.Is(err, ErrStoreUnreadable) || tok != strongA || src != SourceRunning {
		t.Fatalf("Resolve = (%q, %q, %v), want the running strongA and ErrStoreUnreadable", tok, src, err)
	}
	if fi, err := os.Stat(Path(BridgeToken)); err != nil || !fi.IsDir() {
		t.Fatalf("the unreadable store was replaced (err %v)", err)
	}

	// A fresh process gets a token, unstored, and keeps it across reloads.
	forgetProcess()
	tok, src, err = Resolve(BridgeToken, "")
	if !errors.Is(err, ErrStoreUnreadable) || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("fresh process: Resolve = (%q, %q, %v), want a generated token and ErrStoreUnreadable", tok, src, err)
	}
	if again, _, _ := Resolve(BridgeToken, ""); again != tok {
		t.Fatalf("reload rotated the token: %q then %q", tok, again)
	}
}

// A store read failing transiently at daemon start is retried, so the process
// does not run a throwaway token and switch to the stored one on next reload.
func TestResolveRetriesATransientFirstReadError(t *testing.T) {
	dir := useTempDir(t)
	readRetryDelay = 100 * time.Millisecond
	if err := os.MkdirAll(Path(ChallengeToken), 0o700); err != nil { // EISDIR on read
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := os.Remove(Path(ChallengeToken)); err != nil {
			done <- err
			return
		}
		done <- os.WriteFile(filepath.Join(dir, "challenge_token"), []byte(strongA+"\n"), 0o600)
	}()
	tok, src, err := Resolve(ChallengeToken, "")
	if gerr := <-done; gerr != nil {
		t.Fatal(gerr)
	}
	if err != nil || tok != strongA || src != SourceStore {
		t.Fatalf("Resolve = (%q, %q, %v), want the stored token after the retry", tok, src, err)
	}
}

// An absent store that cannot be created (under /proc, where mkdir fails even
// for root) keeps one generated token for the life of the process.
func TestResolveUncreatableStoreKeepsOneGeneratedToken(t *testing.T) {
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no /proc")
	}
	useTempDir(t)
	Dir = "/proc/self/cfm-hostsecrets-test/secrets"
	first, src, err := Resolve(ChallengeToken, "")
	if err == nil || src != SourceGenerated || !hex48.MatchString(first) {
		t.Fatalf("Resolve = (%q, %q, %v), want a generated token and a store error", first, src, err)
	}
	for i := 0; i < 3; i++ {
		if again, src, _ := Resolve(ChallengeToken, ""); again != first || src != SourceGenerated {
			t.Fatalf("reload %d: Resolve = (%q, %q), want the same generated token", i, again, src)
		}
	}
	if got := Effective(ChallengeToken, ""); got != first {
		t.Fatalf("Effective = %q, want the token the daemon runs (%q)", got, first)
	}
	// The conf token is copied (and run) when nothing else applies, even if
	// it cannot be stored.
	forgetProcess()
	if tok, src, err := Resolve(BridgeToken, strongA); err == nil || tok != strongA || src != SourceConf {
		t.Fatalf("Resolve = (%q, %q, %v), want the conf token and a store error", tok, src, err)
	}
}

func TestEffective(t *testing.T) {
	useTempDir(t)
	if got := Effective(ChallengeToken, "placeholder"); got != "placeholder" {
		t.Errorf("no store, weak conf: Effective = %q, want the weak value (so a probe reports it)", got)
	}
	if got := Effective(ChallengeToken, strongB); got != strongB {
		t.Errorf("no store, usable conf: Effective = %q, want the conf value (what the daemon would copy)", got)
	}
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []string{"", "placeholder", strongB} {
		if got := Effective(ChallengeToken, legacy); got != strongA {
			t.Errorf("store + conf %q: Effective = %q, want the stored value", legacy, got)
		}
	}
}

// A store restored or copied with loose modes is tightened when it is only
// read: the secrets must never stay world-readable.
func TestResolveTightensALooseExistingStore(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte(strongA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(Path(ChallengeToken), 0o644); err != nil {
		t.Fatal(err)
	}
	if tok, src, err := Resolve(ChallengeToken, ""); err != nil || tok != strongA || src != SourceStore {
		t.Fatalf("Resolve = (%q, %q, %v), want the stored strongA", tok, src, err)
	}
	for path, want := range map[string]os.FileMode{Path(ChallengeToken): 0o600, dir: 0o700} {
		if fi, err := os.Stat(path); err != nil {
			t.Errorf("stat %s: %v", path, err)
		} else if fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
}

// A missing parent (/var/lib/cfm) is created 0701, the daemon's own mode for
// it: the edge workers traverse it to /var/lib/cfm/lua.
func TestResolveCreatesAMissingParent0701(t *testing.T) {
	useTempDir(t)
	parent := filepath.Join(t.TempDir(), "lib", "cfm")
	Dir = filepath.Join(parent, "secrets")
	if _, _, err := Resolve(ChallengeToken, ""); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(parent); err != nil {
		t.Fatalf("stat parent: %v", err)
	} else if fi.Mode().Perm() != 0o701 {
		t.Fatalf("parent mode = %v, want 0701", fi.Mode().Perm())
	}
}

func TestUsable(t *testing.T) {
	// A quote INSIDE a token (never closed, so nothing is cut) ran end to
	// end on the old daemon and keeps working.
	for _, v := range []string{strongA, "A-Za-z0-9._~+/=:" + strongA, strongA[:8] + `"` + strongA[8:], strongA[:8] + "'" + strongA[8:20] + "#" + strongA[20:], strongA + "//x"} {
		if !Usable(v) {
			t.Errorf("Usable(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "placeholder", strongA[:31], `"` + strongA + `"`, "'" + strongA, strongA + ";x", strongA + "#x", "//" + strongA, strongA + " x"} {
		if Usable(v) {
			t.Errorf("Usable(%q) = true, want false", v)
		}
	}
}

// A migrating node whose store cannot be read at start keeps running its
// detectors.conf token (unstored) instead of a throwaway one.
func TestResolveUnreadableStoreRunsTheConfToken(t *testing.T) {
	useTempDir(t)
	if err := os.MkdirAll(Path(ChallengeToken), 0o700); err != nil { // EISDIR on read
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, strongA)
	if !errors.Is(err, ErrStoreUnreadable) || tok != strongA || src != SourceConf {
		t.Fatalf("Resolve = (%q, %q, %v), want the conf token, unstored", tok, src, err)
	}
	if fi, err := os.Stat(Path(ChallengeToken)); err != nil || !fi.IsDir() {
		t.Fatalf("the unreadable store was replaced (err %v)", err)
	}
}

// A store restored as another user is taken back to root: the mode alone
// protects nothing from the file's owner.
func TestResolveTightensForeignOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte(strongA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, Path(ChallengeToken)} {
		if err := os.Lchown(p, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	if tok, _, err := Resolve(ChallengeToken, ""); err != nil || tok != strongA {
		t.Fatalf("Resolve = (%q, %v), want the stored token", tok, err)
	}
	for _, p := range []string{dir, Path(ChallengeToken)} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 {
			t.Errorf("%s owner = %d:%d, want 0:0", p, st.Uid, st.Gid)
		}
	}
}

// ResolveConfUnknown uses a stored token as usual, and never stores a
// generated one (a later Resolve may still copy the node's conf token).
func TestResolveConfUnknown(t *testing.T) {
	useTempDir(t)
	tok, src, err := ResolveConfUnknown(ChallengeToken)
	if !errors.Is(err, ErrConfUnknown) || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("empty store: ResolveConfUnknown = (%q, %q, %v), want an unstored generated token", tok, src, err)
	}
	if again, _, _ := ResolveConfUnknown(ChallengeToken); again != tok {
		t.Fatalf("reload rotated the unstored token: %q then %q", tok, again)
	}
	if got, src, err := Resolve(ChallengeToken, strongA); err != nil || got != strongA || src != SourceConf {
		t.Fatalf("conf readable again: Resolve = (%q, %q, %v), want the conf token copied", got, src, err)
	}
	if got, src, err := ResolveConfUnknown(ChallengeToken); err != nil || got != strongA || src != SourceStore {
		t.Fatalf("stored: ResolveConfUnknown = (%q, %q, %v), want the stored token", got, src, err)
	}
}

// In the daemon, Effective is the token the process runs, even while its file
// is deleted for a rotation that the next reload will perform.
func TestEffectiveIsTheRunningTokenInTheDaemon(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(Path(ChallengeToken)); err != nil {
		t.Fatal(err)
	}
	if got := Effective(ChallengeToken, "placeholder"); got != strongA {
		t.Fatalf("Effective = %q, want the running strongA until the reload", got)
	}
}

// A store that keeps failing to write fails with the same message every
// time (no random temp-file name), so the daemon logs it once.
func TestWriteErrorIsStableAcrossReloads(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A directory where the file goes: CreateTemp works, the rename fails.
	if err := os.MkdirAll(filepath.Join(Path(ChallengeToken), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	e1 := write(ChallengeToken, strongA)
	e2 := write(ChallengeToken, strongA)
	if e1 == nil || e2 == nil || e1.Error() != e2.Error() || strings.Contains(e1.Error(), ".tmp-") {
		t.Fatalf("write errors = %v / %v, want the same message without the temp file name", e1, e2)
	}
}

// The write path takes a store dir owned by another user back to root too,
// before it puts a new token in it.
func TestWriteTakesAForeignStoreDirBackToRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(ChallengeToken, ""); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("store dir owner = %d:%d, want 0:0", st.Uid, st.Gid)
	}
}
