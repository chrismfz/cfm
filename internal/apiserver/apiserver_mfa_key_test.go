package apiserver

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
)

func TestResolveMFAEncryptionKey_UsesConfiguredKey(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.Debug.AuthMFAEncryptionKey = "my-explicit-key"
	cfg.API.AuthToken = "admin-token"

	if got := resolveMFAEncryptionKey(cfg); got != "my-explicit-key" {
		t.Fatalf("expected explicit key, got %q", got)
	}
}

func TestResolveMFAEncryptionKey_DerivesFromAuthToken(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.API.AuthToken = "admin-token"

	k1 := resolveMFAEncryptionKey(cfg)
	if strings.TrimSpace(k1) == "" {
		t.Fatal("expected derived key")
	}

	cfg2 := &cfgpkg.Config{}
	cfg2.API.AuthToken = "admin-token"
	k2 := resolveMFAEncryptionKey(cfg2)
	if k1 != k2 {
		t.Fatalf("expected stable derived key, got %q != %q", k1, k2)
	}
}

func TestResolveMFAEncryptionKey_EmptyWhenNoInputs(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "auth-mfa.key")
	prev := mfaKeyStatePath
	mfaKeyStatePath = tmp
	t.Cleanup(func() { mfaKeyStatePath = prev })

	got := resolveMFAEncryptionKey(&cfgpkg.Config{})
	if strings.TrimSpace(got) == "" {
		t.Fatal("expected generated fallback key")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("expected base64 key, got err=%v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(decoded))
	}
	raw, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("expected key file to be written: %v", err)
	}
	if strings.TrimSpace(string(raw)) != got {
		t.Fatalf("expected persisted key %q, got %q", got, strings.TrimSpace(string(raw)))
	}
}

func TestResolveMFAEncryptionKey_UsesPersistedFallbackKey(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "auth-mfa.key")
	if err := os.WriteFile(tmp, []byte("persisted-key\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	prev := mfaKeyStatePath
	mfaKeyStatePath = tmp
	t.Cleanup(func() { mfaKeyStatePath = prev })

	if got := resolveMFAEncryptionKey(&cfgpkg.Config{}); got != "persisted-key" {
		t.Fatalf("expected persisted key, got %q", got)
	}
}
