package apiserver

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The admin-cookie signing key is a random, persisted, per-node secret — never
// derived from AUTH_TOKEN — so a cfm-web DB leak cannot forge the admin cookie.

func TestEmbedAdminCookieKey_CreatesPersistsAndReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "embed-admin-cookie.key")

	k1, err := loadOrCreateEmbedAdminCookieKeyFile(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(k1) != embedAdminCookieKeyLen {
		t.Fatalf("key length = %d, want %d", len(k1), embedAdminCookieKeyLen)
	}

	// Persisted 0600, hex-encoded, decodes back to the same key.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key not persisted: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file perm = %o, want 600", perm)
	}
	raw, _ := os.ReadFile(path)
	if _, err := hex.DecodeString(string(raw[:len(raw)-1])); err != nil { // strip trailing \n
		t.Errorf("key file is not valid hex: %v", err)
	}

	// A second load reuses the SAME key (cookies survive restart).
	k2, err := loadOrCreateEmbedAdminCookieKeyFile(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if hex.EncodeToString(k1) != hex.EncodeToString(k2) {
		t.Fatalf("key not stable across loads: %x != %x", k1, k2)
	}
}

func TestEmbedAdminCookieKey_NotDerivedFromAuthToken(t *testing.T) {
	// Two independent nodes (distinct key files) get DIFFERENT keys, even though
	// they might share an AUTH_TOKEN — proving the key is random, not derived.
	dir := t.TempDir()
	ka, err := loadOrCreateEmbedAdminCookieKeyFile(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatal(err)
	}
	kb, err := loadOrCreateEmbedAdminCookieKeyFile(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ka) == hex.EncodeToString(kb) {
		t.Fatal("two nodes must get independent random keys, not an AUTH_TOKEN-derived one")
	}
}

func TestEmbedAdminCookieKey_RegeneratesOnCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "embed-admin-cookie.key")
	if err := os.WriteFile(path, []byte("not-hex-garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := loadOrCreateEmbedAdminCookieKeyFile(path)
	if err != nil {
		t.Fatalf("load over corrupt file: %v", err)
	}
	if len(k) != embedAdminCookieKeyLen {
		t.Fatalf("expected a regenerated %d-byte key, got %d", embedAdminCookieKeyLen, len(k))
	}
	// The corrupt content was replaced with a valid hex key.
	raw, _ := os.ReadFile(path)
	if _, err := hex.DecodeString(string(raw[:len(raw)-1])); err != nil {
		t.Errorf("corrupt file was not regenerated to valid hex: %v", err)
	}
}
