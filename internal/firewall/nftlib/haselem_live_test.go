//go:build linux

package nftlib

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cfm/internal/ipquery"
)

// TestLiveNFTLibHasElemLookup checks HasElem's kernel lookup: an exact
// element of a hash set, an address inside an interval set's range, an
// absent one (what the dump it replaced, still its fallback, answers); and that
// ListSetsJSON names the sets over netlink.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run LiveNFTLibHasElemLookup -v
func TestLiveNFTLibHasElemLookup(t *testing.T) {
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
add element inet cfm block_ext_v4_hosts_MYBLOCK { 192.0.2.7, 192.0.2.8 }
add element inet cfm allow_ext_v4_nets_MYALLOW { 198.51.100.0/24, 203.0.113.5 }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		set, elem string
		want      bool
	}{
		{"block_ext_v4_hosts_MYBLOCK", "192.0.2.7", true},
		{"block_ext_v4_hosts_MYBLOCK", "192.0.2.9", false},
		{"allow_ext_v4_nets_MYALLOW", "198.51.100.77", true},
		{"allow_ext_v4_nets_MYALLOW", "203.0.113.5", true},
		{"allow_ext_v4_nets_MYALLOW", "203.0.113.6", false},
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
	raw, err := b.ListSetsJSON(context.Background(), "inet")
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Join(ipquery.SetNames(raw), ",")
	if !strings.Contains(names, "block_ext_v4_hosts_MYBLOCK") || !strings.Contains(names, "allow_ext_v4_nets_MYALLOW") {
		t.Errorf("ListSetsJSON names %q", names)
	}
}
