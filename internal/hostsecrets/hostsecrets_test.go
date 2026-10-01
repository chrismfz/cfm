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
	forget()
	t.Cleanup(func() { Dir, readRetryDelay = old, oldDelay; forget() })
	return Dir
}

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
	forget() // a restart
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

// A token file that exists but holds no usable token (a short or quoted one
// to fix) is never overwritten: the process runs the conf token, or a generated one,
// unstored, and says so.
func TestResolveNeverOverwritesAnUnusableStore(t *testing.T) {
	for name, tc := range map[string]struct{ content, legacy, want string }{
		"placeholder, conf token": {"placeholder\n", strongA, strongA},
		"quoted, no conf token":   {`"` + strongA + `"` + "\n", "", ""},
		"short, conf placeholder": {"short\n", "placeholder", ""},
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

// A symlink in place of a token file is never followed (the root daemon
// would read, and mirror to the edge, whatever it points at), nor replaced
// (it may be an operator's deliberate setup): it is reported, and a token
// runs unstored until it is fixed.
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
	tok, _, err := Resolve(ChallengeToken, "")
	if !errors.Is(err, ErrStoreUnusable) || tok == strongB || tok == "" {
		t.Fatalf("Resolve = (%q, %v), want a token other than the link target and ErrStoreUnusable", tok, err)
	}
	if fi, err := os.Lstat(Path(ChallengeToken)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced (err %v)", err)
	}
	if b, _ := os.ReadFile(target); string(b) != strongB+"\n" {
		t.Fatalf("the link target was changed: %q", b)
	}
}

// A FIFO in place of a token file must not block the daemon's start (a
// blocking open waits for a writer forever).
func TestResolveDoesNotBlockOnAFIFO(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(Path(ChallengeToken), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := Resolve(ChallengeToken, "")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrStoreUnusable) {
			t.Fatalf("Resolve err = %v, want ErrStoreUnusable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve blocked on a FIFO")
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
	if got := Effective(BridgeToken, strongB); got != strongA {
		t.Fatalf("Effective = %q, want the running strongA (the daemon logs the read error)", got)
	}

	// A fresh process gets a token, unstored, and keeps it across reloads.
	forget()
	tok, src, err = Resolve(BridgeToken, "")
	if !errors.Is(err, ErrStoreUnreadable) || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("fresh process: Resolve = (%q, %q, %v), want a generated token and ErrStoreUnreadable", tok, src, err)
	}
	if again, _, _ := Resolve(BridgeToken, ""); again != tok {
		t.Fatalf("reload rotated the token: %q then %q", tok, again)
	}
}

// A token file caught mid-write at daemon start (still empty) is retried, so
// the process does not run a throwaway token; the operator's token is then
// read, and the file is never overwritten.
func TestResolveRetriesATransientFirstReadError(t *testing.T) {
	dir := useTempDir(t)
	readRetryDelay = 100 * time.Millisecond
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(Path(ChallengeToken), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, werr := f.WriteString(strongA + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		done <- werr
	}()
	tok, src, err := Resolve(ChallengeToken, "")
	if gerr := <-done; gerr != nil {
		t.Fatal(gerr)
	}
	if err != nil || tok != strongA || src != SourceStore {
		t.Fatalf("Resolve = (%q, %q, %v), want the written token after the retry", tok, src, err)
	}
}

// A permanent error (a weak value, a directory) is not retried: no sleep at
// every daemon start for nothing.
func TestTransient(t *testing.T) {
	for err, want := range map[error]bool{
		errEmpty: true, syscall.EMFILE: true, syscall.EIO: true,
		ErrStoreUnusable: false, syscall.EACCES: false, nil: false,
	} {
		if got := transient(err); got != want {
			t.Errorf("transient(%v) = %v, want %v", err, got, want)
		}
	}
}

// A token file over the size cap is unusable, never truncated into a token.
func TestReadStoreRejectsAnOversizedFile(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte(strings.Repeat("a", maxTokenFile+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStore(ChallengeToken); !errors.Is(err, ErrStoreUnusable) {
		t.Fatalf("readStore err = %v, want ErrStoreUnusable", err)
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
	forget()
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
	e1 := write(ChallengeToken, strongA, true)
	e2 := write(ChallengeToken, strongA, true)
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

// An empty token file (a truncated restore, a ">" redirect) holds no one's
// token once the mid-write retry has passed: it is treated as absent and
// replaced, so restarts do not each run a new unstored token.
func TestResolveReplacesAnEmptyFile(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Effective(ChallengeToken, strongB); got != strongB {
		t.Fatalf("Effective = %q, want the conf token that would be copied", got)
	}
	tok, src, err := Resolve(ChallengeToken, strongB)
	if err != nil || tok != strongB || src != SourceConf || stored(ChallengeToken) != strongB {
		t.Fatalf("Resolve = (%q, %q, %v), store %q; want the conf token stored", tok, src, err, stored(ChallengeToken))
	}
}

// Creating the token file never replaces one that appeared meanwhile (an
// operator writing a shared token between the read and the write).
func TestWriteNeverReplacesAFileThatAppeared(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte(strongB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(ChallengeToken, strongA, false); !errors.Is(err, ErrStoreChanged) {
		t.Fatalf("write err = %v, want ErrStoreChanged", err)
	}
	if got := stored(ChallengeToken); got != strongB {
		t.Fatalf("store = %q, want the file that appeared, untouched", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*tmp-*")); len(left) > 0 {
		t.Fatalf("temp file left behind: %v", left)
	}
}

// A device node at the token path is never opened (opening one can have side
// effects): its type is checked first.
func TestReadStoreNeverOpensADevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mknod")
	}
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// /dev/null's numbers (1,3): harmless even if it were opened.
	if err := syscall.Mknod(Path(ChallengeToken), syscall.S_IFCHR|0o600, 1<<8|3); err != nil {
		t.Skipf("mknod: %v", err)
	}
	if _, err := readStore(ChallengeToken); !errors.Is(err, ErrStoreUnusable) {
		t.Fatalf("readStore err = %v, want ErrStoreUnusable", err)
	}
}

// Replacing an empty file never replaces one that got content meanwhile (an
// operator who created it first, then wrote the token).
func TestWriteReplaceOnlyAnEmptyFile(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte(strongB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(ChallengeToken, strongA, true); !errors.Is(err, ErrStoreChanged) {
		t.Fatalf("write err = %v, want ErrStoreChanged", err)
	}
	if got := stored(ChallengeToken); got != strongB {
		t.Fatalf("store = %q, want the operator's token, untouched", got)
	}
}

func TestForgetRunning(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	if _, runs := Running(ChallengeToken); !runs {
		t.Fatal("Running = false after Resolve")
	}
	ForgetRunning()
	if _, runs := Running(ChallengeToken); runs {
		t.Fatal("Running = true after ForgetRunning")
	}
}
