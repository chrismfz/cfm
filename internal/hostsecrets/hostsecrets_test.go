package hostsecrets

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
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
	old := Dir
	Dir = filepath.Join(t.TempDir(), "secrets")
	forgetGenerated()
	t.Cleanup(func() { Dir = old; forgetGenerated() })
	return Dir
}

// forgetGenerated drops the per-process token caches, so each test starts
// like a fresh daemon.
func forgetGenerated() {
	for _, m := range []*sync.Map{&unstored, &running} {
		m.Range(func(k, _ any) bool { m.Delete(k); return true })
	}
}

func stored(t *testing.T, key string) string {
	t.Helper()
	v, _ := Read(key)
	return v
}

func TestResolveLegacyWinsAndIsCopied(t *testing.T) {
	dir := useTempDir(t)
	tok, src, err := Resolve(ChallengeToken, strongA)
	if err != nil || tok != strongA || src != SourceConf {
		t.Fatalf("Resolve = (%q, %q, %v), want (strongA, %q, nil)", tok, src, err, SourceConf)
	}
	if got := stored(t, ChallengeToken); got != strongA {
		t.Fatalf("store = %q, want the detectors.conf value copied", got)
	}
	fi, err := os.Stat(Path(ChallengeToken))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store file mode = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("store dir mode = %v (err %v), want 0700", di.Mode().Perm(), err)
	}
}

// The migration property: once the detectors.conf value has been copied,
// removing the line keeps the same secret, so no challenge cookie is
// invalidated by the move.
func TestResolveRemovingTheLineKeepsTheSecret(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(BridgeToken, strongA); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(BridgeToken, "")
	if err != nil || tok != strongA || src != SourceStore {
		t.Fatalf("after removing the line: Resolve = (%q, %q, %v), want (strongA, %q, nil)", tok, src, err, SourceStore)
	}
}

func TestResolveLegacyOverridesADifferentStore(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(ChallengeToken, strongB); err != nil {
		t.Fatal(err)
	}
	tok, src, _ := Resolve(ChallengeToken, strongA)
	if tok != strongA || src != SourceConf || stored(t, ChallengeToken) != strongA {
		t.Fatalf("a strong detectors.conf value must win and replace the store: got %q from %q, store %q", tok, src, stored(t, ChallengeToken))
	}
}

func TestResolveWeakLegacyIsIgnored(t *testing.T) {
	useTempDir(t)
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	for _, weak := range []string{"placeholder", "changeme", "short", strings.Repeat("x", 31)} {
		tok, src, _ := Resolve(ChallengeToken, weak)
		if tok != strongA || src != SourceStore {
			t.Errorf("legacy %q: Resolve = (%q, %q), want the stored strongA", weak, tok, src)
		}
	}
}

func TestResolveGeneratesOnceThenReuses(t *testing.T) {
	useTempDir(t)
	tok, src, err := Resolve(ChallengeToken, "placeholder")
	if err != nil || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("first start: Resolve = (%q, %q, %v), want a generated 48-hex token", tok, src, err)
	}
	again, src2, err := Resolve(ChallengeToken, "")
	if err != nil || again != tok || src2 != SourceStore {
		t.Fatalf("restart: Resolve = (%q, %q, %v), want the same token from the store", again, src2, err)
	}
	// The two secrets are independent.
	bridge, _, _ := Resolve(BridgeToken, "")
	if bridge == tok {
		t.Fatal("OPENRESTY_TOKEN and CHALLENGE_TOKEN must not share a value")
	}
}

func TestResolveRegeneratesAWeakStore(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte("placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, "")
	if err != nil || src != SourceGenerated || !hex48.MatchString(tok) || stored(t, ChallengeToken) != tok {
		t.Fatalf("weak store: Resolve = (%q, %q, %v), store %q; want a new stored token", tok, src, err, stored(t, ChallengeToken))
	}
}

func TestResolveTightensAnExistingDir(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(ChallengeToken, ""); err != nil {
		t.Fatal(err)
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("store dir mode = %v, want 0700", di.Mode().Perm())
	}
}

// A store that cannot be written still yields a secret (the daemon keeps
// running), with the error to log.
func TestResolveUnwritableStoreStillReturnsASecret(t *testing.T) {
	dir := useTempDir(t)
	if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, "")
	if err == nil || tok == "" || src != SourceGenerated {
		t.Fatalf("Resolve = (%q, %q, %v), want a generated token and a store error", tok, src, err)
	}
	tok, src, err = Resolve(BridgeToken, strongA)
	if err == nil || tok != strongA || src != SourceConf {
		t.Fatalf("Resolve = (%q, %q, %v), want the legacy token and a store error", tok, src, err)
	}
}

func TestEffective(t *testing.T) {
	useTempDir(t)
	if got := Effective(ChallengeToken, "placeholder"); got != "placeholder" {
		t.Errorf("no store, weak legacy: Effective = %q, want the weak value (so a probe reports it)", got)
	}
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	if got := Effective(ChallengeToken, ""); got != strongA {
		t.Errorf("store only: Effective = %q, want the stored value", got)
	}
	if got := Effective(ChallengeToken, "placeholder"); got != strongA {
		t.Errorf("weak legacy + store: Effective = %q, want the stored value (what the daemon runs)", got)
	}
	if got := Effective(ChallengeToken, strongB); got != strongB {
		t.Errorf("strong legacy: Effective = %q, want the legacy value (it wins)", got)
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
	tok, src, err := Resolve(ChallengeToken, "")
	if err != nil || tok != strongA || src != SourceStore {
		t.Fatalf("Resolve = (%q, %q, %v), want the stored strongA", tok, src, err)
	}
	if fi, _ := os.Stat(Path(ChallengeToken)); fi.Mode().Perm() != 0o600 {
		t.Errorf("store file mode = %v, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Errorf("store dir mode = %v, want 0700", di.Mode().Perm())
	}
}

// An unwritable store must not rotate the token on every Resolve (every
// reload): the generated value is kept for the life of the process.
func TestResolveUnwritableStoreKeepsOneTokenPerProcess(t *testing.T) {
	dir := useTempDir(t)
	if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := Resolve(ChallengeToken, "")
	if err == nil || first == "" {
		t.Fatalf("Resolve = (%q, %v), want a token and a store error", first, err)
	}
	for i := 0; i < 3; i++ {
		// (Dir is a file, so the store reads as unreadable: SourceRunning.)
		again, src, _ := Resolve(ChallengeToken, "")
		if again != first || src != SourceRunning {
			t.Fatalf("reload %d: Resolve = (%q, %q), want the same generated token %q", i, again, src, first)
		}
	}
	if got := Effective(ChallengeToken, ""); got != first {
		t.Fatalf("Effective = %q, want the token the daemon runs (%q)", got, first)
	}
}

// A reload between "delete the store file" and the restart of the documented
// rotation must not bring a replaced token back: the per-process cache only
// holds a token that could not be stored.
func TestResolveNeverRevivesAReplacedToken(t *testing.T) {
	useTempDir(t)
	g, _, err := Resolve(ChallengeToken, "placeholder")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(ChallengeToken, strongA); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(Path(ChallengeToken)); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, "placeholder")
	if err != nil || src != SourceGenerated || tok == g || tok == strongA {
		t.Fatalf("after rotation: Resolve = (%q, %q, %v), want a NEW generated token", tok, src, err)
	}
}

// A store that exists but cannot be read (EACCES, EIO, EMFILE; here a
// directory in its place) must neither rotate the running token nor be
// overwritten: it may hold the good secret.
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
	tok, src, err := Resolve(BridgeToken, "placeholder")
	if !errors.Is(err, ErrStoreUnreadable) || tok != strongA || src != SourceRunning {
		t.Fatalf("unreadable store: Resolve = (%q, %q, %v), want the running strongA and ErrStoreUnreadable", tok, src, err)
	}
	if fi, err := os.Stat(Path(BridgeToken)); err != nil || !fi.IsDir() {
		t.Fatalf("the unreadable store was replaced (err %v)", err)
	}

	// A fresh process (nothing running yet) still gets a token, unstored.
	forgetGenerated()
	tok, src, err = Resolve(BridgeToken, "")
	if !errors.Is(err, ErrStoreUnreadable) || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("fresh process: Resolve = (%q, %q, %v), want a generated token and ErrStoreUnreadable", tok, src, err)
	}
	if again, _, _ := Resolve(BridgeToken, ""); again != tok {
		t.Fatalf("reload rotated the token: %q then %q", tok, again)
	}
}

func TestUsable(t *testing.T) {
	for _, v := range []string{strongA, "A-Za-z0-9._~+/=:" + strongA} {
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

// A hand-written store value the config cleaner would alter is not used: it
// would run as a different secret than the one mirrored to the edge.
func TestResolveReplacesAStoreValueTheCleanerWouldAlter(t *testing.T) {
	dir := useTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(ChallengeToken), []byte(`"`+strongA+`"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, src, err := Resolve(ChallengeToken, "")
	if err != nil || src != SourceGenerated || !hex48.MatchString(tok) {
		t.Fatalf("Resolve = (%q, %q, %v), want a generated token replacing the quoted one", tok, src, err)
	}
}

// The store's parent (/var/lib/cfm) is created 0755 when missing, never 0700:
// the edge workers reach /var/lib/cfm/lua through it.
func TestResolveCreatesAMissingParentWorldTraversable(t *testing.T) {
	old := Dir
	parent := filepath.Join(t.TempDir(), "lib", "cfm")
	Dir = filepath.Join(parent, "secrets")
	forgetGenerated()
	t.Cleanup(func() { Dir = old; forgetGenerated() })
	if _, _, err := Resolve(ChallengeToken, ""); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(parent); err != nil || fi.Mode().Perm()&0o055 != 0o055 {
		t.Fatalf("parent mode = %v (err %v), want group/other r-x", fi.Mode().Perm(), err)
	}
}

// An absent store that cannot be created (here under /proc, where mkdir fails
// even for root) keeps one generated token for the life of the process.
func TestResolveUncreatableStoreKeepsOneGeneratedToken(t *testing.T) {
	old := Dir
	Dir = "/proc/self/cfm-hostsecrets-test/secrets"
	forgetGenerated()
	t.Cleanup(func() { Dir = old; forgetGenerated() })
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no /proc")
	}
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
}
