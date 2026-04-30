package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/firewall/setinventory"
)

func TestFirewallStatusFeeds_NoneConfigured(t *testing.T) {
	tmp := t.TempDir()
	be := mockDiagBE{dnat: true, sets: map[string][]string{
		"block_v4": {}, "block_v6": {}, "block_v4_nets": {}, "block_v6_nets": {},
		"allow_v4": {}, "allow_v6": {}, "allow_v4_nets": {}, "allow_v6_nets": {},
		"ignore_v4": {}, "ignore_v6": {}, "ignore_v4_nets": {}, "ignore_v6_nets": {},
		"allow_dyn_v4": {}, "allow_dyn_v6": {}, "challenge_v4": {}, "challenge_v6": {},
	}}
	r := collectFirewallStatus(be, tmp, "nft", "default", false)
	for _, f := range r.Findings {
		if f.Message == "no feed-derived sets expected" {
			return
		}
	}
	t.Fatalf("expected no-feed info finding, got=%+v", r.Findings)
}

func TestFirewallStatusFeeds_AllowAndBlockFeedExpected(t *testing.T) {
	tmp := t.TempDir()
	cfg := "myallow|ALLOW|3600|0|https://example/allow\nmyblock|BLOCK|3600|0|https://example/block\n"
	if err := os.WriteFile(filepath.Join(tmp, "cfm.blocklists"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	sets := map[string][]string{}
	for _, s := range setinventory.BuildSetNames(loadConfiguredFeeds(tmp)) {
		sets[s] = nil
	}
	be := mockDiagBE{dnat: true, sets: sets}
	r := collectFirewallStatus(be, tmp, "nft", "default", false)
	if _, ok := r.SetSizes["allow_ext_v4_hosts_myallow"]; !ok {
		t.Fatalf("expected myallow feed set probe in set sizes")
	}
	if _, ok := r.SetSizes["block_ext_v4_hosts_myblock"]; !ok {
		t.Fatalf("expected myblock feed set probe in set sizes")
	}
}

func TestFirewallStatusFeeds_FeedRenamedOldStaleNewExpected(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "cfm.blocklists"), []byte("newname|BLOCK|3600|0|https://example/block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sets := map[string][]string{}
	for _, s := range setinventory.BuildSetNames(loadConfiguredFeeds(tmp)) {
		sets[s] = nil
	}
	sets["block_ext_v4_hosts_oldname"] = nil // stale old set should not be required
	be := mockDiagBE{dnat: true, sets: sets}
	r := collectFirewallStatus(be, tmp, "nft", "default", false)
	if _, ok := r.SetSizes["block_ext_v4_hosts_newname"]; !ok {
		t.Fatalf("expected new feed-derived set to be probed")
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "oldname") {
			t.Fatalf("did not expect stale old set to be part of expected probes: %+v", f)
		}
	}
}
