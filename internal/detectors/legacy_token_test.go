package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/hostsecrets"
)

// legacyToken falls back to <cfgPath>.dpkg-old only while the store is empty
// and the live file has no strong token: the Debian "install the package
// maintainer's version" path, where the new stock detectors.conf carries no
// token and the old one survives only as .dpkg-old.
func TestLegacyTokenDpkgOldFallback(t *testing.T) {
	old := hostsecrets.Dir
	hostsecrets.Dir = filepath.Join(t.TempDir(), "secrets")
	t.Cleanup(func() { hostsecrets.Dir = old })

	const (
		live   = "0123456789abcdef0123456789abcdef0123456789abcdef"
		saved  = "fedcba9876543210fedcba9876543210fedcba9876543210"
		stored = "00112233445566778899aabbccddeeff0011223344556677"
	)
	cfg := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(cfg+".dpkg-old", []byte("[webdetector]\nCHALLENGE_TOKEN = "+saved+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A strong live value wins; the .dpkg-old is not consulted.
	if v, from := legacyToken(cfg, KV{"CHALLENGE_TOKEN": live}, hostsecrets.ChallengeToken); v != live || from != "detectors.conf" {
		t.Errorf("strong live value: legacyToken = (%q, %q), want the live value", v, from)
	}
	// Empty live value, empty store: the .dpkg-old token is migrated.
	if v, from := legacyToken(cfg, KV{"CHALLENGE_TOKEN": ""}, hostsecrets.ChallengeToken); v != saved || from != "detectors.conf.dpkg-old" {
		t.Errorf("empty live, empty store: legacyToken = (%q, %q), want the .dpkg-old value", v, from)
	}
	// No [webdetector] token in the .dpkg-old for this key: nothing to migrate.
	if v, _ := legacyToken(cfg, nil, hostsecrets.BridgeToken); v != "" {
		t.Errorf("key absent from .dpkg-old: legacyToken = %q, want empty", v)
	}
	// Once the store holds a value, a stale .dpkg-old is never used again.
	if _, _, err := hostsecrets.Resolve(hostsecrets.ChallengeToken, stored); err != nil {
		t.Fatal(err)
	}
	if v, from := legacyToken(cfg, KV{"CHALLENGE_TOKEN": "placeholder"}, hostsecrets.ChallengeToken); v != "placeholder" || from != "detectors.conf" {
		t.Errorf("store filled: legacyToken = (%q, %q), want the live (weak) value, so Resolve keeps the store", v, from)
	}
}
