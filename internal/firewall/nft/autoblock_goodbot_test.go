//go:build linux

package nft

import (
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
)

// The exec engine's copy of TestAutoBlockSkipsVerifiedGoodBot (nftlib): a
// verified Meta proxy is not banned, a spoofed fbsv.net PTR is.
func TestAutoBlockSkipsVerifiedGoodBot(t *testing.T) {
	restore := firewall.SetAutoblockGoodBotForTest(
		func(ip string) string {
			return map[string]string{
				"69.63.184.14": "fwdproxy-ncg-014.fbsv.net",
				"198.51.100.7": "fwdproxy-fake.fbsv.net",
			}[ip]
		},
		func(_, ip string) (string, bool) {
			if ip == "69.63.184.14" {
				return "meta", true
			}
			return "", true
		})
	defer restore()

	log := fakeNFTAutoblock(t, setJSON("block_v4", ""))
	rep := &recReporter{}
	b := New()
	b.SetReporter(rep)
	b.cfg = &cfgpkg.Config{API: cfgpkg.APIConfig{AutoBlockSend: true}}
	tc := cfgpkg.ThrottleConfig{Mode: "permanent", Hits: 5, WindowSec: 60}

	if err := b.autoBlockAction("69.63.184.14", "v4", "portflood_443_tcp", tc); err != nil {
		t.Fatalf("autoBlockAction(verified Meta): %v", err)
	}
	if got := readFile(t, log); strings.Contains(got, "add element inet cfm block_v4 { 69.63.184.14") || strings.Contains(got, "create element inet cfm block_v4 { 69.63.184.14") || len(rep.blocks) != 0 {
		t.Fatalf("verified Meta proxy blocked (reports %v):\n%s", rep.blocks, got)
	}
	if err := b.autoBlockAction("198.51.100.7", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction(spoofed PTR): %v", err)
	}
	if got := readFile(t, log); !strings.Contains(got, "add element inet cfm block_v4 { 198.51.100.7 }") || len(rep.blocks) != 1 {
		t.Errorf("spoofed fbsv.net PTR not blocked permanently (reports %v):\n%s", rep.blocks, got)
	}
}
