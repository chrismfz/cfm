package panelauth

import (
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
