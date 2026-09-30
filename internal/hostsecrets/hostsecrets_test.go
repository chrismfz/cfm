package hostsecrets

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	t.Cleanup(func() { Dir = old })
	return Dir
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
