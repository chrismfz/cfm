//go:build linux

package ipquery

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cfm/internal/firewall/nft"
)

// TestLiveNFTFindMany runs FindMany against a real `nft` through the exec
// backend: the sets come from `nft -j -t list sets` (another table's set of
// the same name is not cfm's), and a feed's union answers, named after the
// feed when it has one. It pins the JSON the installed nft prints, which the unit
// tests only imitate (the fleet runs nft 0.9.3 on EL8, 1.0.4 on virgo).
//
// It writes the `inet cfm` table, so it is gated like the firewall tests:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/ipquery/ -run LiveNFTFindMany -v
func TestLiveNFTFindMany(t *testing.T) {
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
add set inet cfm block_v4 { type ipv4_addr; flags timeout; }
add set inet cfm block_ext_v4_hosts { type ipv4_addr; flags timeout; }
add set inet cfm block_ext_v4_hosts_MYBLOCK { type ipv4_addr; flags timeout; }
add set inet cfm block_ext_v4_nets { type ipv4_addr; flags interval; }
add element inet cfm block_v4 { 198.51.100.9 timeout 1h }
add element inet cfm block_ext_v4_hosts { 192.0.2.7, 192.0.2.8 }
add element inet cfm block_ext_v4_hosts_MYBLOCK { 192.0.2.7 }
add element inet cfm block_ext_v4_nets { 203.0.113.0/24 }
add table inet cfm_live_other
add set inet cfm_live_other block_v4 { type ipv4_addr; }
add element inet cfm_live_other block_v4 { 10.9.9.9 }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", "cfm").Run()
		_ = exec.Command("nft", "delete", "table", "inet", "cfm_live_other").Run()
	})

	res, err := FindMany(context.Background(), nft.New(), []string{"198.51.100.9", "192.0.2.7", "192.0.2.8", "203.0.113.5", "10.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{ // query -> "set/feed"
		"198.51.100.9": "block_v4/",
		// One feed: its union is named after it, with no second dump.
		"192.0.2.7":   "block_ext_v4_hosts/MYBLOCK",
		"192.0.2.8":   "block_ext_v4_hosts/MYBLOCK",
		"203.0.113.5": "block_ext_v4_nets/",
	}
	for q, w := range want {
		h := res[q]
		if len(h) != 1 || h[0].Set+"/"+h[0].Feed != w || h[0].Action != "BLOCK" {
			t.Errorf("%s = %+v, want one BLOCK hit in %s", q, h, w)
		}
	}
	if h := res["10.9.9.9"]; len(h) != 0 {
		t.Errorf("10.9.9.9 = %+v: another table's set is not cfm's", h)
	}
}
