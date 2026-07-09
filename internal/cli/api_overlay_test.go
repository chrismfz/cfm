package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigWithAPIOverride_MaxMindAndAPI verifies that cfm.api.conf overlays
// both the cfm-web API secrets and the MaxMind account credentials on top of a
// secret-free base cfm.conf — the "one api.conf holds all per-server secrets"
// design.
func TestLoadConfigWithAPIOverride_MaxMindAndAPI(t *testing.T) {
	dir := t.TempDir()

	// Base config ships secrets blank / placeholder.
	base := []byte("" +
		"API_URL = \"https://placeholder.example\"\n" +
		"AUTH_TOKEN = \"TOKEN-HERE-FROM-CFM-WEB\"\n" +
		"MAXMIND_ACCOUNT_ID=\n" +
		"MAXMIND_LICENSE_KEY=\n")

	// Overlay carries the real per-server secrets.
	overlay := "" +
		"API_URL   = \"https://cfm.myip.gr\"\n" +
		"AUTH_TOKEN = \"real-token-123\"\n" +
		"MAXMIND_ACCOUNT_ID  = 971261\n" +
		"MAXMIND_LICENSE_KEY = maxmind-key-xyz\n"
	if err := os.WriteFile(filepath.Join(dir, "cfm.api.conf"), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigWithAPIOverride(dir, base)
	if err != nil {
		t.Fatalf("LoadConfigWithAPIOverride: %v", err)
	}
	if cfg.API.URL != "https://cfm.myip.gr" {
		t.Errorf("API.URL = %q, want the overlay value", cfg.API.URL)
	}
	if cfg.API.AuthToken != "real-token-123" {
		t.Errorf("API.AuthToken = %q, want the overlay value", cfg.API.AuthToken)
	}
	if cfg.MaxMind.AccountID != "971261" {
		t.Errorf("MaxMind.AccountID = %q, want overlaid 971261", cfg.MaxMind.AccountID)
	}
	if cfg.MaxMind.LicenseKey != "maxmind-key-xyz" {
		t.Errorf("MaxMind.LicenseKey = %q, want the overlay value", cfg.MaxMind.LicenseKey)
	}
}

// TestLoadConfigWithAPIOverride_APIOnlyOverlayKeepsBaseMaxMind guards the
// "only overwrite when the overlay sets them" rule: an overlay that carries just
// API keys must not wipe MaxMind credentials configured in the base cfm.conf.
func TestLoadConfigWithAPIOverride_APIOnlyOverlayKeepsBaseMaxMind(t *testing.T) {
	dir := t.TempDir()

	base := []byte("MAXMIND_ACCOUNT_ID=111\nMAXMIND_LICENSE_KEY=base-key\n")
	overlay := "AUTH_TOKEN = \"tok\"\n"
	if err := os.WriteFile(filepath.Join(dir, "cfm.api.conf"), []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigWithAPIOverride(dir, base)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxMind.AccountID != "111" || cfg.MaxMind.LicenseKey != "base-key" {
		t.Errorf("base MaxMind creds clobbered by an API-only overlay: id=%q key=%q",
			cfg.MaxMind.AccountID, cfg.MaxMind.LicenseKey)
	}
	if cfg.API.AuthToken != "tok" {
		t.Errorf("AUTH_TOKEN overlay not applied: %q", cfg.API.AuthToken)
	}
}
