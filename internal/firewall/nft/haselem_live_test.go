//go:build linux

package nft

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestLiveNFTHasElemLookup checks HasElem's kernel lookup against what
// `nft get element` (its fallback) answers: an exact element of a hash set,
// an address inside an interval set's range, an absent one, and an address
// of the other family (no answer from the lookup: the fallback runs). The
// set names come from `nft -t list sets` (listSetsByPrefixes), not the
// table's listing, which loads every element on EL8's nft.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run LiveNFTHasElemLookup -v
func TestLiveNFTHasElemLookup(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command("nft", "list", "table", "inet", "cfm").CombinedOutput(); err == nil {
		s := string(out)
		if strings.Contains(s, "allow_v4") || strings.Contains(s, "block_v4") || strings.Contains(s, "hook input") {
			t.Fatalf("refusing to run: a populated `inet cfm` table already exists — run this test inside an isolated netns (unshare -rn)")
		}
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`add table inet cfm
flush table inet cfm
add set inet cfm block_ext_v4_hosts_MYBLOCK { type ipv4_addr; }
add set inet cfm allow_ext_v4_nets_MYALLOW { type ipv4_addr; flags interval; }
add set inet cfm allow_ext_v6_hosts_MYALLOW { type ipv6_addr; }
add element inet cfm block_ext_v4_hosts_MYBLOCK { 192.0.2.7, 192.0.2.8 }
add element inet cfm allow_ext_v4_nets_MYALLOW { 198.51.100.0/24, 203.0.113.5 }
add table inet other
add set inet other allow_ext_v4_hosts_X { type ipv4_addr; }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", "cfm").Run()
		_ = exec.Command("nft", "delete", "table", "inet", "other").Run()
	})
	b := New()
	cases := []struct {
		set, elem string
		want      bool
	}{
		{"block_ext_v4_hosts_MYBLOCK", "192.0.2.7", true},
		{"block_ext_v4_hosts_MYBLOCK", "192.0.2.9", false},
		{"allow_ext_v4_nets_MYALLOW", "198.51.100.77", true}, // inside the range
		{"allow_ext_v4_nets_MYALLOW", "203.0.113.5", true},
		{"allow_ext_v4_nets_MYALLOW", "203.0.113.6", false},
		{"allow_ext_v6_hosts_MYALLOW", "2001:db8::1", false},
	}
	for _, c := range cases {
		fast, ok := hasAddrElem(b, c.set, c.elem)
		if !ok || fast != c.want {
			t.Errorf("lookup %s %s: %v (answered %v), want %v", c.set, c.elem, fast, ok, c.want)
		}
		got, err := b.HasElem(c.set, c.elem)
		if err != nil || got != c.want {
			t.Errorf("HasElem %s %s: %v %v, want %v", c.set, c.elem, got, err, c.want)
		}
	}
	// The other family: the lookup does not answer, nft get element does.
	if _, ok := hasAddrElem(b, "block_ext_v4_hosts_MYBLOCK", "2001:db8::7"); ok {
		t.Error("a v6 address answered from a v4 set's lookup")
	}
	names, err := b.listSetsByPrefixes("allow_ext_v4_", "block_ext_v4_hosts_")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "allow_ext_v4_nets_MYALLOW,block_ext_v4_hosts_MYBLOCK" {
		t.Errorf("set names %v (the other table's set must not be listed)", names)
	}
	if raw, err := b.ListSetsJSON(context.Background(), "inet"); err != nil || !strings.Contains(string(raw), "block_ext_v4_hosts_MYBLOCK") {
		t.Errorf("ListSetsJSON: %v %.200s", err, raw)
	}
}
