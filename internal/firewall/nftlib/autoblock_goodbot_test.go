//go:build linux

package nftlib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
)

// Meta's link-preview proxies (fwdproxy-*.fbsv.net) tripped portflood_443_tcp
// and SYN flood and were banned permanently into cfm.deny on mars and titan
// (2026). An FCrDNS-verified good bot is not banned, written to cfm.deny or
// reported; a PTR that does not forward-confirm still is.
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

	f := &batchFake{dump: map[string][]wireElem{}}
	b := f.backend(t)
	for _, name := range []string{"ignore_v4", "allow_v4", "allow_dyn_v4", "ignore_v4_nets", "allow_v4_nets", "allow_ext_v4_hosts", "allow_ext_v4_nets"} {
		b.namedSets[name] = &nftables.Set{Name: name, KeyType: nftables.TypeIPAddr,
			Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
	}
	b.lastAutoBlockAt, b.lastIgnoredAt = map[string]time.Time{}, map[string]time.Time{}
	rep := &recReporter{}
	b.reporter = rep
	b.cfgDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(b.cfgDir, "cfm.conf"), []byte("AUTOBLOCK_SEND_TO_API=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tc := cfgpkg.ThrottleConfig{Mode: "permanent", Hits: 5, WindowSec: 60}
	deny := filepath.Join(b.cfgDir, "cfm.deny")

	if err := b.autoBlockAction("69.63.184.14", "v4", "portflood_443_tcp", tc); err != nil {
		t.Fatalf("autoBlockAction(verified Meta): %v", err)
	}
	if len(f.batches) != 0 || len(rep.blocks) != 0 {
		t.Fatalf("verified Meta proxy blocked: %d writes, reports %v", len(f.batches), rep.blocks)
	}
	if _, err := os.Stat(deny); !os.IsNotExist(err) {
		t.Fatalf("cfm.deny written for a verified good bot (stat err %v)", err)
	}

	if err := b.autoBlockAction("198.51.100.7", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction(spoofed PTR): %v", err)
	}
	if len(f.batches) != 1 || len(rep.blocks) != 1 {
		t.Fatalf("spoofed fbsv.net PTR: %d writes, reports %v; want it blocked and reported", len(f.batches), rep.blocks)
	}
	if data, _ := os.ReadFile(deny); !strings.Contains(string(data), "198.51.100.7 ") {
		t.Errorf("cfm.deny = %q, want the spoofed address", data)
	}

	// THROTTLE_GOODBOT_EXEMPT = 0: the operator's choice wins.
	tc.GoodBotExemptOff = true
	if err := b.autoBlockAction("69.63.184.14", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction(exempt off): %v", err)
	}
	if len(f.batches) != 2 {
		t.Errorf("exemption off: %d writes, want the Meta address blocked", len(f.batches))
	}
}
