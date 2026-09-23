//go:build linux

package nft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
)

type recReporter struct{ blocks []string }

func (r *recReporter) ReportBlock(ip, _, source, mode string, ttl int) error {
	r.blocks = append(r.blocks, fmt.Sprintf("%s %s %s %d", ip, source, mode, ttl))
	return nil
}
func (r *recReporter) ReportLenient(string, string, string, string, int) error { return nil }
func (r *recReporter) ReportUnblock(string, string, string) error              { return nil }

// fakeNFTAutoblock is an `nft` that holds no allow/ignore entries and
// answers `-j list set inet cfm block_v4` from v4JSON, logging every call.
func fakeNFTAutoblock(t *testing.T, v4JSON string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	if err := os.WriteFile(filepath.Join(dir, "v4.json"), []byte(v4JSON), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
d=%[1]q
echo "ARGS $*" >> "$d/nft.log"
case "$*" in
"get element"*) echo "Error: Could not get element" >&2; exit 1;;
"-j list set inet cfm block_v4") cat "$d/v4.json"; exit 0;;
"-f -") cat >> "$d/nft.log"; exit 0;;
esac
exit 0
`, dir)
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// A ttl autoblock never shortens a block: `add element … timeout` over an
// address already blocked permanently (cfm.deny, a port-scan or manual block)
// made the kernel take the new timeout, so the permanent block ended after
// THROTTLE_TTL. It is kept, and not reported again.
func TestAutoBlockTTL_KeepsPermanentBlock(t *testing.T) {
	log := fakeNFTAutoblock(t, setJSON("block_v4", `"198.51.100.8"`))
	rep := &recReporter{}
	b := New()
	b.SetReporter(rep)
	b.cfg = &cfgpkg.Config{API: cfgpkg.APIConfig{AutoBlockSend: true}}
	tc := cfgpkg.ThrottleConfig{Mode: "ttl", TTLSeconds: 86400, Hits: 3, WindowSec: 60}

	if err := b.autoBlockAction("198.51.100.8", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction over a permanent block: %v", err)
	}
	got := readFile(t, log)
	if strings.Contains(got, "ARGS -f -") || strings.Contains(got, "add element") {
		t.Errorf("rewrote a permanent block:\n%s", got)
	}
	if len(rep.blocks) != 0 {
		t.Errorf("reported a block that was kept: %v", rep.blocks)
	}

	if err := b.autoBlockAction("198.51.100.9", "v4", "SYN flood", tc); err != nil {
		t.Fatalf("autoBlockAction: %v", err)
	}
	got = readFile(t, log)
	if !strings.Contains(got, "create element inet cfm block_v4 { 198.51.100.9 timeout 1d }") {
		t.Errorf("new address not blocked for the TTL:\n%s", got)
	}
	if len(rep.blocks) != 1 || rep.blocks[0] != "198.51.100.9 autoblock ttl 86400" {
		t.Errorf("reports = %v, want one ttl report for the new block", rep.blocks)
	}

	// An unspecified source (a DHCP discover flood is 0.0.0.0) is not
	// blockable: nothing written, nothing reported.
	before := strings.Count(readFile(t, log), "ARGS -f -")
	if err := b.autoBlockAction("0.0.0.0", "v4", "Packet flood (pps)", tc); err != nil {
		t.Fatalf("autoBlockAction(0.0.0.0): %v", err)
	}
	if strings.Count(readFile(t, log), "ARGS -f -") != before || len(rep.blocks) != 1 {
		t.Errorf("blocked or reported 0.0.0.0: reports %v", rep.blocks)
	}
}
