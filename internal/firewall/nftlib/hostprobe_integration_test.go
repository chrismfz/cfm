//go:build linux

package nftlib

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// TestLiveNFTBanPlansFromTheProbe checks, on a real kernel, that a backend
// from New plans a one-address ban from per-address gets (never a dump of
// block_v4), counts the get with its other netlink calls, and keeps a longer
// ban.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run LiveNFTBanPlansFromTheProbe -v
func TestLiveNFTBanPlansFromTheProbe(t *testing.T) {
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
add set inet cfm block_v6 { type ipv6_addr; flags timeout; }
add element inet cfm block_v4 { 192.0.2.7 timeout 7d }
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	before := firewall.HostProbeSnapshot()
	if kept, err := firewall.ExtendBlock(b, net.ParseIP("192.0.2.7"), time.Hour); err != nil || !kept {
		t.Fatalf("1h over 7d: kept=%v err=%v, want kept", kept, err)
	}
	if kept, err := firewall.ExtendBlock(b, net.ParseIP("192.0.2.8"), time.Hour); err != nil || kept {
		t.Fatalf("a new ban: kept=%v err=%v", kept, err)
	}
	after := firewall.HostProbeSnapshot()
	if after.Probed-before.Probed != 2 || after.Fallbacks != before.Fallbacks || after.Dumps != before.Dumps {
		t.Errorf("host probe %+v -> %+v: want 2 probed, no dump, no fallback", before, after)
	}
	nl := b.nl.snapshot()
	if nl.Ops == 0 || nl.Dials < nl.Ops-1 {
		t.Errorf("netlink stats ops=%d dials=%d: the probe's gets must count", nl.Ops, nl.Dials)
	}
	b.nl.mu.Lock()
	ops := b.nl.ops
	b.nl.mu.Unlock()
	if _, err := firewall.ExtendBlock(b, net.ParseIP("192.0.2.9"), time.Hour); err != nil {
		t.Fatal(err)
	}
	b.nl.mu.Lock()
	grew := b.nl.ops - ops
	b.nl.mu.Unlock()
	if grew < 2 { // the probe, and the write
		t.Errorf("one ban recorded %d netlink ops, want the probe and the write", grew)
	}
}
