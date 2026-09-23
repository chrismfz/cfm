//go:build linux

package nftlib

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/nftables"

	cfgpkg "cfm/internal/config"
)

type recReporter struct{ blocks []string }

func (r *recReporter) ReportBlock(ip, _, source, mode string, ttl int) error {
	r.blocks = append(r.blocks, fmt.Sprintf("%s %s %s %d", ip, source, mode, ttl))
	return nil
}
func (r *recReporter) ReportLenient(string, string, string, string, int) error { return nil }
func (r *recReporter) ReportUnblock(string, string, string) error               { return nil }

// A ttl autoblock never shortens a block: AddBlock replaced the element, so
// over an address already blocked permanently (cfm.deny, a port-scan or
// manual block) the permanent block ended after THROTTLE_TTL. It is kept, and
// not reported again.
func TestAutoBlockTTL_KeepsPermanentBlock(t *testing.T) {
	f := &batchFake{dump: map[string][]wireElem{setBlockV4: {{key: net.ParseIP("198.51.100.8")}}}}
	b := f.backend(t)
	// The allow/ignore sets exist and are empty.
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
	tc := cfgpkg.ThrottleConfig{Mode: "ttl", TTLSeconds: 86400, Hits: 3, WindowSec: 60}

	if err := b.autoBlockAction("198.51.100.8", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction over a permanent block: %v", err)
	}
	if len(f.batches) != 0 {
		t.Errorf("%d write transactions over a permanent block, want none", len(f.batches))
	}
	if len(rep.blocks) != 0 {
		t.Errorf("reported a block that was kept: %v", rep.blocks)
	}

	if err := b.autoBlockAction("198.51.100.9", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction: %v", err)
	}
	if len(f.batches) != 1 {
		t.Fatalf("%d write transactions, want one for the new address", len(f.batches))
	}
	_, adds, _ := elemsOf(t, f.batches[0])
	if a := adds[setBlockV4]; len(a) != 1 || !a[0].key.Equal(net.ParseIP("198.51.100.9")) || !a[0].hasTimeout || a[0].timeout != 24*time.Hour {
		t.Errorf("adds = %+v, want 198.51.100.9 for 24h", adds)
	}
	if len(rep.blocks) != 1 || rep.blocks[0] != "198.51.100.9 autoblock ttl 86400" {
		t.Errorf("reports = %v, want one ttl report for the new block", rep.blocks)
	}
}
