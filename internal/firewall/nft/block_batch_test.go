//go:build linux

package nft

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// fakeNFTSets puts an `nft` script first in PATH that answers
// `-j list set inet cfm block_v4|block_v6` from the given JSON, logs every
// invocation (and any script fed on stdin), and fails the first failWrites
// `nft -f -` runs.
func fakeNFTSets(t *testing.T, v4JSON, v6JSON string, failWrites int) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	for name, body := range map[string]string{"v4.json": v4JSON, "v6.json": v6JSON, "fails": fmt.Sprint(failWrites)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := fmt.Sprintf(`#!/bin/sh
d=%[1]q
echo "ARGS $*" >> "$d/nft.log"
case "$*" in
"-j list set inet cfm block_v4") cat "$d/v4.json"; exit 0;;
"-j list set inet cfm block_v6") cat "$d/v6.json"; exit 0;;
"-f -")
	cat >> "$d/nft.log"
	n=$(cat "$d/fails")
	if [ "$n" -gt 0 ]; then echo $((n-1)) > "$d/fails"; echo "Error: Could not process rule: No such file or directory" >&2; exit 1; fi
	exit 0;;
esac
exit 0
`, dir)
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func setJSON(name string, elems ...string) string {
	return fmt.Sprintf(`{"nftables":[{"metainfo":{"json_schema_version":1}},{"set":{"family":"inet","name":%q,"table":"cfm","type":"ipv4_addr","flags":["timeout"],"elem":[%s]}}]}`,
		name, strings.Join(elems, ","))
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A batch of any size costs one listing per family and ONE `nft -f -` run —
// never a process per address, which is what AddBlock would cost.
func TestAddBlockBatch_OneTransactionForAnyBatchSize(t *testing.T) {
	log := fakeNFTSets(t,
		setJSON("block_v4",
			`{"elem":{"val":"198.51.100.7","timeout":120,"expires":60}}`, // 1m left: extend
			`"198.51.100.8"`), // permanent: keep
		setJSON("block_v6"), 0)
	var entries []firewall.BlockEntry
	for i := 0; i < 2500; i++ {
		entries = append(entries, firewall.BlockEntry{IP: net.IPv4(10, 1, byte(i/250), byte(i%250+1)), TTL: 6 * time.Hour})
	}
	entries = append(entries,
		firewall.BlockEntry{IP: net.ParseIP("198.51.100.7"), TTL: time.Hour},
		firewall.BlockEntry{IP: net.ParseIP("198.51.100.8"), TTL: time.Hour},
		firewall.BlockEntry{IP: net.ParseIP("2001:db8::1"), Permanent: true})

	res, err := New().AddBlockBatch(entries)
	if err != nil {
		t.Fatalf("AddBlockBatch: %v", err)
	}
	if res != (firewall.BlockBatchResult{Added: 2501, Extended: 1, Kept: 1}) {
		t.Errorf("result = %+v", res)
	}
	got := readFile(t, log)
	if n := strings.Count(got, "ARGS "); n != 3 {
		t.Fatalf("%d nft processes, want 3 (list v4, list v6, one -f):\n%.600s", n, got)
	}
	del := strings.Index(got, "delete element inet cfm block_v4 { 198.51.100.7 }")
	add := strings.Index(got, "create element inet cfm block_v4 {")
	if del < 0 || add < 0 || del > add {
		t.Errorf("want the replaced address deleted before the creates, in the same script:\n%.600s", got)
	}
	for _, want := range []string{"198.51.100.7 timeout 1h", "10.1.0.1 timeout 6h", "create element inet cfm block_v6 { 2001:db8::1 }"} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(got, "198.51.100.8 ") {
		t.Errorf("rewrote a permanent block")
	}
	// Plain `add element` would rewrite the timeout of an element another
	// writer added after the read (a permanent block would take this TTL);
	// `create` aborts the transaction instead, and the retry re-plans.
	if strings.Contains(got, "add element") {
		t.Errorf("script uses a plain add; every add must be an exclusive create")
	}
	if n := strings.Count(got, "create element inet cfm block_v4 {"); n != 3 {
		t.Errorf("%d v4 create statements, want 3 (2501 elements in chunks of %d)", n, blockBatchStmtElems)
	}
}

// A failed write (e.g. an element that expired between the read and the
// write) is retried from a fresh read, then reported with nft's own error
// line — never turned into one nft process per address.
func TestAddBlockBatch_RetriesNeverPerAddress(t *testing.T) {
	entries := []firewall.BlockEntry{{IP: net.ParseIP("198.51.100.1"), TTL: time.Hour}, {IP: net.ParseIP("198.51.100.2"), Permanent: true}}

	log := fakeNFTSets(t, setJSON("block_v4"), setJSON("block_v6"), 1)
	if res, err := New().AddBlockBatch(entries); err != nil || res.Added != 2 {
		t.Fatalf("one failed write must be retried: res=%+v err=%v", res, err)
	}
	if n := strings.Count(readFile(t, log), "ARGS -f -"); n != 2 {
		t.Errorf("%d writes, want 2", n)
	}

	log = fakeNFTSets(t, setJSON("block_v4"), setJSON("block_v6"), 99)
	_, err := New().AddBlockBatch(entries)
	if err == nil {
		t.Fatal("want an error once every attempt fails")
	}
	if !strings.Contains(err.Error(), "Error: Could not process rule") || len(err.Error()) > 400 {
		t.Errorf("error = %q, want nft's own error line, trimmed", err)
	}
	got := readFile(t, log)
	if n := strings.Count(got, "ARGS "); n != 2*blockBatchAttempts {
		t.Errorf("%d nft processes, want %d (list + write per attempt) — no per-address fallback:\n%s", n, 2*blockBatchAttempts, got)
	}
}

// nft prints expires in whole seconds: an element in its last second shows
// "expires": 0. That must read as about to expire, not permanent — else the
// batch keeps it and the address is unblocked a moment later.
func TestAddBlockBatch_LastSecondIsNotPermanent(t *testing.T) {
	log := fakeNFTSets(t,
		setJSON("block_v4", `{"elem":{"val":"198.51.100.9","timeout":1,"expires":0}}`),
		setJSON("block_v6"), 0)
	res, err := New().AddBlockBatch([]firewall.BlockEntry{{IP: net.ParseIP("198.51.100.9"), TTL: 6 * time.Hour}})
	if err != nil || res.Extended != 1 {
		t.Fatalf("res=%+v err=%v, want the expiring block extended", res, err)
	}
	if got := readFile(t, log); !strings.Contains(got, "198.51.100.9 timeout 6h") {
		t.Errorf("the block was not rewritten:\n%s", got)
	}
}
