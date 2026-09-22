package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEngineFollowsCFMConf(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte("FIREWALL_ENGINE = nftlib\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadEngineConfig(dir)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("CFM_FIREWALL_ENGINE", "")
	if _, engine, source := resolveFirewallEngine(cfg); engine != "nftlib" || source != "config" {
		t.Fatalf("got engine=%q source=%q, want nftlib from config (as the daemon resolves it)", engine, source)
	}
	t.Setenv("CFM_FIREWALL_ENGINE", "nft")
	if _, engine, source := resolveFirewallEngine(cfg); engine != "nft" || source != "env" {
		t.Fatalf("got engine=%q source=%q, want the environment to win", engine, source)
	}
}

func TestLoadEngineConfig_MissingIsNotAnError(t *testing.T) {
	for _, dir := range []string{"", t.TempDir()} {
		cfg, err := loadEngineConfig(dir)
		if cfg != nil || err != nil {
			t.Fatalf("dir %q: got (%v, %v), want (nil, nil)", dir, cfg, err)
		}
	}
	t.Setenv("CFM_FIREWALL_ENGINE", "")
	if _, engine, source := resolveFirewallEngine(nil); engine != "nft" || source != "default" {
		t.Fatalf("no config: got engine=%q source=%q, want the nft default", engine, source)
	}
}

// The CLI must not build a backend from the environment alone: that is how a
// node configured for nftlib ran the daemon on nftlib and the CLI on nft.
func TestCLINeverResolvesEngineWithoutConfig(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "resolveFirewallEngine(nil)") {
		t.Fatal("main.go calls resolveFirewallEngine(nil); CLI paths must use cliFirewallEngine() so cfm.conf is honoured")
	}
}
