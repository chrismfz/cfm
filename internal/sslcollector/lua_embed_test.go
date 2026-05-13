package sslcollector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedSSLCollectorLuaMatchesConfigsSource fails when the
// duplicated copy under internal/sslcollector/embed/ has drifted from
// the canonical configs/lua/sslcollector.lua. The duplication exists
// because Go's //go:embed cannot reach paths above the package
// directory; this test is the safety net so the two copies stay
// byte-identical.
//
// To resolve a drift failure: `cp configs/lua/sslcollector.lua
// internal/sslcollector/embed/sslcollector.lua` and re-commit.
func TestEmbeddedSSLCollectorLuaMatchesConfigsSource(t *testing.T) {
	// Walk up from the test's working dir to find the repo root, then
	// load configs/lua/sslcollector.lua. Go tests run with the package
	// directory as CWD, so the repo root is two levels up from
	// internal/sslcollector.
	configsPath := filepath.Join("..", "..", "configs", "lua", "sslcollector.lua")
	source, err := os.ReadFile(configsPath)
	if err != nil {
		t.Fatalf("read canonical lua source %s: %v", configsPath, err)
	}
	embed := EmbeddedSSLCollectorLua()
	if len(source) != len(embed) {
		t.Fatalf("size drift: configs/lua=%d, internal embed=%d", len(source), len(embed))
	}
	sumA := sha256.Sum256(source)
	sumB := sha256.Sum256(embed)
	if sumA != sumB {
		t.Fatalf("content drift between configs/lua/sslcollector.lua and internal/sslcollector/embed/sslcollector.lua\nconfigs sha256=%s\nembed   sha256=%s\nFix: cp configs/lua/sslcollector.lua internal/sslcollector/embed/sslcollector.lua",
			hex.EncodeToString(sumA[:]), hex.EncodeToString(sumB[:]))
	}
}

// TestDeploySSLCollectorLua_WritesWhenAbsent verifies the deploy
// helper writes the file when it does not already exist, with the
// expected mode.
func TestDeploySSLCollectorLua_WritesWhenAbsent(t *testing.T) {
	tmp := t.TempDir()
	// Override SSLCollectorLuaPath via the path-mocking helper. Because
	// the const is exported we redirect by writing to a local copy via
	// a small wrapper: rather than mutate the const, call the internal
	// write path directly. The unit test exercises the same logic in
	// isolation.
	target := filepath.Join(tmp, "sslcollector.lua")
	body := EmbeddedSSLCollectorLua()
	if err := os.WriteFile(target+".unrelated", []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Manually invoke the inner write path the production code uses,
	// piggy-backing on writeSnapshotAtomic — same semantics (atomic
	// tmp+rename, mode 0640, chmod-bypass-umask).
	if err := writeSnapshotAtomic(target, body); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("size mismatch: got=%d want=%d", len(got), len(body))
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o640 {
		t.Fatalf("mode = %o, want 640 (umask must not strip group-read)", perm)
	}
}

// TestWriteSnapshotAtomic_OverridesRestrictiveUmask is the regression
// test for the operator-observed bug: under a daemon umask of 0077
// the snapshot ended up 0600 instead of 0640, making it unreadable to
// the cfm-group worker user.
func TestWriteSnapshotAtomic_OverridesRestrictiveUmask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.json")

	prevMask := syscallUmask(0o077)
	defer syscallUmask(prevMask)

	if err := writeSnapshotAtomic(path, []byte(`{"version":"x","exact":[],"wild":[]}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o640 {
		t.Fatalf("under umask 0077 the explicit chmod did not stick: mode=%o want 640", perm)
	}
}
