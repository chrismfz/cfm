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
	in=$(cat); printf '%%s\n' "$in" >> "$d/nft.log"
	n=$(cat "$d/fails")
	if [ "$n" -gt 0 ]; then
		echo $((n-1)) > "$d/fails"
		# nft's real shape: location, the failing statement, a caret line
		# (the tests' first statement names its first address at columns 36-47).
		echo "/dev/stdin:1:36-47: Error: Could not process rule: No such file or directory" >&2
		printf '%%s\n' "$in" | head -1 >&2
		echo "                                   ^^^^^^^^^^^^" >&2
		exit 1
	fi
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
	if !strings.Contains(err.Error(), "Error: Could not process rule: No such file or directory (at 198.51.100.1)") || len(err.Error()) > 400 {
		t.Errorf("error = %q, want nft's own error line naming the element, trimmed", err)
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

// nft prefixes its error with the input location and follows it with the
// whole statement and a caret line; the error must be the "Error:" text plus
// the element the columns point at — never the caret line. (Captured from nft
// 1.0.9.)
func TestNFTFirstError(t *testing.T) {
	exists := "/dev/stdin:1:57-64: Error: Could not process rule: File exists\n" +
		"create element inet cfm block_v4 { 10.0.0.1 timeout 1h, 10.0.0.7 timeout 1h }\n" +
		"                                                        ^^^^^^^^\n"
	missing := "/dev/stdin:1:36-43: Error: Could not process rule: No such file or directory\n" +
		"delete element inet cfm block_v4 { 10.0.0.9 }\n" +
		"                                   ^^^^^^^^\n"
	fallback := fmt.Errorf("exit status 2")
	for _, tc := range []struct{ out, want string }{
		{exists, "Error: Could not process rule: File exists (at 10.0.0.7)"},
		{missing, "Error: Could not process rule: No such file or directory (at 10.0.0.9)"},
		{"/dev/stdin:1:900-910: Error: odd\nshort\n", "Error: odd"}, // columns out of range
		{"Error: no location\n", "Error: no location"},
		{"nothing useful\n   ^^^\n", "exit status 2"},
	} {
		if got := nftFirstError(tc.out, fallback); got != tc.want {
			t.Errorf("nftFirstError(%q) = %q, want %q", tc.out, got, tc.want)
		}
	}
}

// RemoveBlockBatch reads each block set once and deletes, in ONE `nft -f -`
// run, just the addresses the sets hold. A delete of an absent address aborts
// the whole transaction, which used to send every address through RemoveBlock
// (one nft process each).
func TestRemoveBlockBatch_OneTransactionPresentOnly(t *testing.T) {
	log := fakeNFTSets(t,
		setJSON("block_v4", `"198.51.100.1"`, `{"elem":{"val":"198.51.100.2","timeout":3600,"expires":60}}`),
		setJSON("block_v6", `"2001:db8::1"`), 0)
	ips := []net.IP{net.ParseIP("198.51.100.9"), net.ParseIP("198.51.100.2"), net.ParseIP("198.51.100.1"),
		net.ParseIP("2001:db8::7"), net.ParseIP("2001:db8::1")}
	for i := 0; i < 300; i++ { // many absent addresses: still no per-address process
		ips = append(ips, net.IPv4(10, 3, byte(i/250), byte(i%250+1)))
	}
	if err := New().RemoveBlockBatch(ips); err != nil {
		t.Fatalf("RemoveBlockBatch: %v", err)
	}
	got := readFile(t, log)
	if n := strings.Count(got, "ARGS "); n != 3 {
		t.Fatalf("%d nft processes, want 3 (list v4, list v6, one -f):\n%.600s", n, got)
	}
	for _, want := range []string{
		"delete element inet cfm block_v4 { 198.51.100.2, 198.51.100.1 }",
		"delete element inet cfm block_v6 { 2001:db8::1 }",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q:\n%.600s", want, got)
		}
	}
	if strings.Contains(got, "198.51.100.9") || strings.Contains(got, "10.3.") || strings.Contains(got, "2001:db8::7") {
		t.Errorf("deleted an address the sets don't hold:\n%.600s", got)
	}

	// Nothing blocked here: two reads, no write.
	log = fakeNFTSets(t, setJSON("block_v4"), setJSON("block_v6"), 0)
	if err := New().RemoveBlockBatch(ips); err != nil {
		t.Fatalf("RemoveBlockBatch: %v", err)
	}
	if got := readFile(t, log); strings.Count(got, "ARGS ") != 2 || strings.Contains(got, "ARGS -f -") {
		t.Errorf("want the two reads and no write:\n%s", got)
	}
}

// A failed delete (an address that expired between the read and the write)
// is retried from a fresh read, then reported with nft's own error line.
func TestRemoveBlockBatch_RetriesNeverPerAddress(t *testing.T) {
	ips := []net.IP{net.ParseIP("198.51.100.1"), net.ParseIP("198.51.100.2")}
	v4 := setJSON("block_v4", `"198.51.100.1"`, `"198.51.100.2"`)

	log := fakeNFTSets(t, v4, setJSON("block_v6"), 1)
	if err := New().RemoveBlockBatch(ips); err != nil {
		t.Fatalf("one failed write must be retried: %v", err)
	}
	if n := strings.Count(readFile(t, log), "ARGS -f -"); n != 2 {
		t.Errorf("%d writes, want 2", n)
	}

	log = fakeNFTSets(t, v4, setJSON("block_v6"), 99)
	err := New().RemoveBlockBatch(ips)
	if err == nil || !strings.Contains(err.Error(), "No such file or directory (at 198.51.100.1)") {
		t.Fatalf("error = %v, want nft's own error line naming the element", err)
	}
	if n := strings.Count(readFile(t, log), "ARGS "); n != 2*blockBatchAttempts {
		t.Errorf("%d nft processes, want %d (list + write per attempt) — no per-address fallback", n, 2*blockBatchAttempts)
	}
}
