package sslcollector

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
	"cfm/internal/hostsecrets"
)

// The socket token lives in the per-host store (hostsecrets), like the
// [webdetector] tokens: an empty store takes the cfm.conf value (the
// migration: the edge keeps its token), after that the store wins whatever
// cfm.conf says, and what is served and mirrored to cfm_token.lua is the
// stored token. cfm.conf is never written (the lifecycle no longer knows its
// path).
func TestSockLifecycleTokenComesFromTheStore(t *testing.T) {
	t.Cleanup(hostsecrets.SetDirForTest(filepath.Join(t.TempDir(), "secrets")))
	col := newTestCollector(t)
	sock := filepath.Join(t.TempDir(), "s.sock")
	lc := newTestLifecycle(t, col)
	defer lc.Stop()
	ctx := context.Background()

	cfg := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken}
	lc.ApplyConfig(ctx, cfg)
	if b, _ := os.ReadFile(hostsecrets.Path(hostsecrets.SSLCollectorToken)); strings.TrimSpace(string(b)) != strongToken {
		t.Fatalf("store = %q, want the cfm.conf token copied", b)
	}
	luaHas := func(tok string) bool {
		b, err := os.ReadFile(lc.luaTokenPath)
		return err == nil && strings.Contains(string(b), tok)
	}
	if !luaHas(strongToken) || cfg.Token != strongToken {
		t.Fatalf("served/mirrored token is not the stored one (cfg.Token %q)", cfg.Token)
	}

	// The stock placeholder (or any other value) in cfm.conf: the store wins.
	for _, conf := range []string{"placeholder", "supersecret", strings.Repeat("z", 48)} {
		c := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: conf}
		lc.ApplyConfig(ctx, c)
		if c.Token != strongToken || !luaHas(strongToken) {
			t.Fatalf("cfm.conf %q: served %q, want the stored token", conf, c.Token)
		}
	}
	waitFor(t, "dialable", func() bool { return dialOK(sock) })
}

// A fresh node (cfm.conf at the stock placeholder, empty store) generates a
// token, stores it and serves it.
func TestSockLifecycleTokenGeneratedOnAFreshNode(t *testing.T) {
	t.Cleanup(hostsecrets.SetDirForTest(filepath.Join(t.TempDir(), "secrets")))
	col := newTestCollector(t)
	lc := newTestLifecycle(t, col)
	defer lc.Stop()
	cfg := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: filepath.Join(t.TempDir(), "s.sock"), Token: "placeholder"}
	lc.ApplyConfig(context.Background(), cfg)
	b, err := os.ReadFile(hostsecrets.Path(hostsecrets.SSLCollectorToken))
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{48}\n$`).Match(b) || strings.TrimSpace(string(b)) != cfg.Token {
		t.Fatalf("store = %q (err %v), served %q; want one generated token, stored and served", b, err, cfg.Token)
	}
}
