package panelauth

import (
	"crypto/hkdf"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerivePluginAssertionKeyDeterministic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("AUTH_TOKEN=test-token\n"), 0o600); err != nil {
		t.Fatalf("write cfm.conf: %v", err)
	}
	prev := os.Getenv("CFM_CONFIG_DIR")
	if err := os.Setenv("CFM_CONFIG_DIR", dir); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("CFM_CONFIG_DIR", prev) })

	k1, err := DerivePluginAssertionKey()
	if err != nil {
		t.Fatalf("DerivePluginAssertionKey #1: %v", err)
	}
	k2, err := DerivePluginAssertionKey()
	if err != nil {
		t.Fatalf("DerivePluginAssertionKey #2: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}
	if string(k1) != string(k2) {
		t.Fatalf("expected deterministic derived key")
	}
}

// AUTH_TOKEN is conventionally stored in the cfm.api.conf overlay (so the base
// cfm.conf can be regenerated without clobbering live tokens). The daemon and
// apiserver honor that overlay; the assertion-key derivation must too, or the
// broker derives a key from an empty token and denies every plugin request with
// secret_missing while the apiserver is happily using the overlay token.
func TestDerivePluginAssertionKeyHonorsAPIOverlay(t *testing.T) {
	dir := t.TempDir()
	// Base cfm.conf has NO AUTH_TOKEN; the token lives only in the overlay.
	if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("API_URL=https://example.test\n"), 0o600); err != nil {
		t.Fatalf("write cfm.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cfm.api.conf"), []byte("AUTH_TOKEN = \"overlay-token\"\n"), 0o600); err != nil {
		t.Fatalf("write cfm.api.conf: %v", err)
	}
	prev := os.Getenv("CFM_CONFIG_DIR")
	if err := os.Setenv("CFM_CONFIG_DIR", dir); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("CFM_CONFIG_DIR", prev) })

	got, err := DerivePluginAssertionKey()
	if err != nil {
		t.Fatalf("expected overlay AUTH_TOKEN to be honored, got error: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(got))
	}

	// The derived key must equal the one produced when the same token sits in the
	// base cfm.conf — i.e. the overlay is a true precedence source, not a separate
	// keyspace. Verify by deriving directly from the overlay token.
	want, err := hkdf.Key(sha256.New, []byte("overlay-token"), []byte(pluginAssertionHKDFSalt), pluginAssertionHKDFInfo, 32)
	if err != nil {
		t.Fatalf("reference derive: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("derived key does not match the overlay AUTH_TOKEN")
	}
}

// When both files set AUTH_TOKEN, the overlay wins (matching
// cli.LoadConfigWithAPIOverride precedence).
func TestDerivePluginAssertionKeyOverlayOverridesBase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("AUTH_TOKEN=base-token\n"), 0o600); err != nil {
		t.Fatalf("write cfm.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cfm.api.conf"), []byte("AUTH_TOKEN=overlay-token\n"), 0o600); err != nil {
		t.Fatalf("write cfm.api.conf: %v", err)
	}
	prev := os.Getenv("CFM_CONFIG_DIR")
	if err := os.Setenv("CFM_CONFIG_DIR", dir); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("CFM_CONFIG_DIR", prev) })

	got, err := DerivePluginAssertionKey()
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	want, err := hkdf.Key(sha256.New, []byte("overlay-token"), []byte(pluginAssertionHKDFSalt), pluginAssertionHKDFInfo, 32)
	if err != nil {
		t.Fatalf("reference derive: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("expected overlay AUTH_TOKEN to take precedence over base cfm.conf")
	}
}

func TestDerivePluginAssertionKeyMissingAuthToken(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("API_URL=https://example.test\n"), 0o600); err != nil {
		t.Fatalf("write cfm.conf: %v", err)
	}
	prev := os.Getenv("CFM_CONFIG_DIR")
	if err := os.Setenv("CFM_CONFIG_DIR", dir); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("CFM_CONFIG_DIR", prev) })

	_, err := DerivePluginAssertionKey()
	if err == nil {
		t.Fatalf("expected error for missing AUTH_TOKEN")
	}
	if !strings.Contains(err.Error(), "auth_token_missing") {
		t.Fatalf("expected clear auth_token_missing reason, got %v", err)
	}
}
