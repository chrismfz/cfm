//go:build linux

package nft

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/firewall/selfip"
)

// EnsureBase gates the daemon's startup: the edge's bridge and ingest sockets
// bind only after it returns. On a node with large feed / TTL-ban sets, any nft
// run that makes the CLI load the table's set elements costs ~2 s (`list
// tables`, `list table`, any `add element`), and the old EnsureBase ran one per
// self-set statement: 28.9 s on virgo's 2026.11.22 upgrade, the edge's bridge
// unreachable the whole time. A mid-life `list tables` past its 5 s timeout
// also read as "no table" and re-ran EnsureBase from the tick loop every
// minute or two. These tests pin the cost profile on an existing table:
// nothing that loads the element cache when the self sets already hold their
// content, and one transaction (not one run per element) when they do not.

// fakeNFTEnsureBase is an nft stand-in for EnsureBase. It logs every call
// ("ARGS …", then a `-f -` script), lists table inet cfm for `list chains
// inet`, and answers `-j list set inet cfm self_v4|self_v6` with the given
// elements (nil = the set read fails).
func fakeNFTEnsureBase(t *testing.T, chainsOK bool, self4, self6 []string) (logPath string) {
	t.Helper()
	mode := "ok"
	if !chainsOK {
		mode = "fail"
	}
	return fakeNFTOpts(t, fakeOpts{chains: mode, self4: self4, self6: self6})
}

// fakeOpts shapes fakeNFTOpts: chains is how `list chains inet` answers
// ("ok" lists table inet cfm, "empty" lists nothing, "fail" exits 1, "slow"
// outsleeps the probe deadline); a `-f -` script matching refuseScript (an
// extended regex over the whole script, flattened to one line) exits 1.
type fakeOpts struct {
	chains       string
	self4, self6 []string
	refuseScript string
}

func fakeNFTOpts(t *testing.T, o fakeOpts) (logPath string) {
	t.Helper()
	self4, self6 := o.self4, o.self6
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	setJSON := func(name string, elems []string) string {
		p := filepath.Join(dir, name+".json")
		if elems == nil {
			return p // absent: cat fails, the fake exits 1
		}
		arr := make([]any, 0, len(elems))
		for _, e := range elems {
			if addr, ln, ok := strings.Cut(e, "/"); ok {
				var n int
				fmt.Sscanf(ln, "%d", &n)
				arr = append(arr, map[string]any{"prefix": map[string]any{"addr": addr, "len": n}})
			} else {
				arr = append(arr, e)
			}
		}
		b, _ := json.Marshal(map[string]any{"nftables": []any{
			map[string]any{"metainfo": map[string]any{"version": "1.0.9"}},
			map[string]any{"set": map[string]any{"family": "inet", "table": "cfm", "name": name, "elem": arr}},
		}})
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	chains := filepath.Join(dir, "chains")
	if err := os.WriteFile(chains, []byte("table inet cfm {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chainsCmd := map[string]string{
		"ok":    fmt.Sprintf("cat %q; exit 0", chains),
		"empty": "exit 0",
		"fail":  "exit 1",
		"slow":  "exec sleep 2",
	}[o.chains]
	if chainsCmd == "" {
		t.Fatalf("fakeOpts.chains %q", o.chains)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %[1]q
if [ "$1" = "-f" ]; then
	in=$(cat); printf '%%s\n' "$in" >> %[1]q
	if [ -n %[5]q ] && printf '%%s' "$in" | tr '\n' ' ' | grep -qE %[5]q; then exit 1; fi
	exit 0
fi
case "$*" in
"list chains inet") %[4]s ;;
"list tables") echo "table inet cfm"; exit 0 ;;
"-j list set inet cfm self_v4") cat %[2]q || exit 1; exit 0 ;;
"-j list set inet cfm self_v6") cat %[3]q || exit 1; exit 0 ;;
esac
exit 0
`, logPath, setJSON("self_v4", self4), setJSON("self_v6", self6), chainsCmd, o.refuseScript)
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// elementCacheLoads lists the nft runs in the log that make the CLI load the
// table's set elements.
func elementCacheLoads(log string) []string {
	var out []string
	for _, ln := range strings.Split(log, "\n") {
		switch {
		case ln == "ARGS list tables", strings.HasPrefix(ln, "ARGS list table "),
			strings.HasPrefix(ln, "ARGS list ruleset"), strings.HasPrefix(ln, "add element "):
			out = append(out, ln)
		}
	}
	return out
}

func wantSelfSets() (v4, v6 []string) {
	return firewall.SelfSetElems(selfip.New().LocalIPs())
}

func TestEnsureBase_UnchangedSelfSetsLoadNoElementCache(t *testing.T) {
	v4, v6 := wantSelfSets()
	log := fakeNFTEnsureBase(t, true, v4, v6)
	if err := New().EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	got := readFile(t, log)
	if loads := elementCacheLoads(got); len(loads) > 0 {
		t.Errorf("EnsureBase with unchanged self sets ran nft commands that load every set element (~2 s each on a busy node):\n%s",
			strings.Join(loads, "\n"))
	}
	if strings.Contains(got, "flush set inet cfm self_") {
		t.Errorf("rewrote self sets that already hold their content:\n%s", got)
	}
}

func TestEnsureBase_ChangedSelfSetsAreOneTransaction(t *testing.T) {
	_, v6 := wantSelfSets()
	log := fakeNFTEnsureBase(t, true, []string{"127.0.0.0/8", "203.0.113.250"}, v6) // a stale address
	if err := New().EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	got := readFile(t, log)
	// One script holds both flushes and every add, in order.
	var scripts int
	for _, block := range strings.Split(got, "ARGS ") {
		if strings.HasPrefix(block, "-f -") && (strings.Contains(block, "flush set inet cfm self_") || strings.Contains(block, "add element inet cfm self_")) {
			scripts++
			i4, i6 := strings.Index(block, "flush set inet cfm self_v4"), strings.Index(block, "flush set inet cfm self_v6")
			a4, a6 := strings.Index(block, "add element inet cfm self_v4"), strings.Index(block, "add element inet cfm self_v6")
			if i4 < 0 || i6 < 0 || a4 < i4 || a6 < i6 {
				t.Errorf("self-set script lacks a flush+add pair:\n%s", block)
			}
		}
	}
	if scripts != 1 {
		t.Errorf("want ONE nft run writing the self sets, got %d:\n%s", scripts, got)
	}
	if loads := elementCacheLoads(got); len(loads) > 2 { // the script's two add statements
		t.Errorf("element-cache loads beyond the one self-set transaction:\n%s", strings.Join(loads, "\n"))
	}
}

// A self set that cannot be read is not taken for "already right".
func TestEnsureBase_UnreadableSelfSetIsRewritten(t *testing.T) {
	v4, _ := wantSelfSets()
	log := fakeNFTEnsureBase(t, true, v4, nil)
	if err := New().EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if got := readFile(t, log); !strings.Contains(got, "flush set inet cfm self_v6") {
		t.Errorf("an unreadable self_v6 must be rewritten:\n%s", got)
	}
}

func TestTableExists_CheapListingThenFallback(t *testing.T) {
	log := fakeNFTEnsureBase(t, true, nil, nil)
	if !New().tableExists() {
		t.Fatal("table inet cfm in `list chains inet` must read as present")
	}
	if got := readFile(t, log); strings.Contains(got, "ARGS list tables") {
		t.Errorf("the cheap listing answered, `list tables` (loads every element) must not run:\n%s", got)
	}

	log = fakeNFTEnsureBase(t, false, nil, nil)
	if !New().tableExists() {
		t.Fatal("a failed cheap listing must fall back to `list tables`")
	}
	if got := readFile(t, log); !strings.Contains(got, "ARGS list tables") {
		t.Errorf("no fallback to `list tables`:\n%s", got)
	}
}

func TestListingHasCFMTable(t *testing.T) {
	for in, want := range map[string]bool{
		"table inet cfm {\n}\n":                                      true,
		"table inet cfm\ntable ip filter\n":                          true,
		"table inet other {\n}\ntable inet cfm {\n\tchain input {\n": true,
		"table inet cfm_redirect {\n}\n":                             false,
		"table ip cfm {\n}\n":                                        false,
		"":                                                           false,
	} {
		if got := listingHasCFMTable(in); got != want {
			t.Errorf("listingHasCFMTable(%q) = %v, want %v", in, got, want)
		}
	}
}

// Against a real nft: after EnsureBase the kernel's self sets read back as the
// wanted content (nft's own spelling of the elements), so the next EnsureBase
// — every restart — writes nothing to them.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run LiveNFTSelfSets -v
func TestLiveNFTSelfSetsReadBackUnchanged(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// It deletes the PRODUCTION table name: refuse a populated one (a real
	// firewall, CFM_NFT_INTEGRATION=1 set on the wrong host), as the DNAT live
	// test does.
	if out, err := exec.Command("nft", "list", "chains", "inet").CombinedOutput(); err == nil && listingHasCFMTable(string(out)) {
		t.Fatalf("refusing to run: an `inet cfm` table already exists — run this test inside an isolated netns (unshare -rn)")
	}
	// A netns has no local address: add some, so more than the static ranges
	// round-trip (two adjacent /32s, which nft must keep apart, and a /128
	// where the netns has IPv6).
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Skipf("ip link set lo up: %v %s", err, out)
	}
	for _, a := range []string{"192.0.2.10/32", "192.0.2.11/32", "2001:db8::10/128"} {
		if out, err := exec.Command("ip", "addr", "add", a, "dev", "lo").CombinedOutput(); err != nil {
			t.Logf("ip addr add %s: %v %s (left out)", a, err, out)
		}
	}
	b := New()
	_ = b.DropEverything()
	t.Cleanup(func() { _ = b.DropEverything() })
	if err := b.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	v4, v6 := firewall.SelfSetElems(b.selfResolver.LocalIPs())
	if len(v4) < 3 {
		t.Fatalf("local IPv4 addresses missing from the wanted self_v4: %v", v4)
	}
	t.Logf("self_v4=%v self_v6=%v", v4, v6)
	if !b.setHolds("self_v4", v4) || !b.setHolds("self_v6", v6) {
		h4, _ := b.ListSetElementsRaw("self_v4")
		h6, _ := b.ListSetElementsRaw("self_v6")
		t.Fatalf("self sets after EnsureBase: v4=%v v6=%v; want v4=%v v6=%v", h4, h6, v4, v6)
	}
	if !b.tableExists() {
		t.Fatal("tableExists after EnsureBase = false")
	}
	// A second EnsureBase (every restart) leaves them alone.
	if !b.setHolds("self_v4", v4) || !b.setHolds("self_v6", v6) {
		t.Fatal("self sets no longer read back as wanted")
	}
}

// A probe that outlives its deadline is "unknown", not "absent": it neither
// falls back to the element-loading `list tables` nor starts a repair. That
// is the per-tick EnsureBase loop loaded nodes ran all day.
func TestProbeTable_TimeoutIsUnknownAndRepairsNothing(t *testing.T) {
	old := tableProbeTimeout
	tableProbeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tableProbeTimeout = old })

	log := fakeNFTOpts(t, fakeOpts{chains: "slow"})
	b := New()
	if st := b.probeTable(); st != tableUnknown {
		t.Fatalf("probeTable after a timed-out listing = %v, want unknown", st)
	}
	b.loadPortScannerOnce()
	_ = b.ResetTable()
	got := readFile(t, log)
	if strings.Contains(got, "ARGS list tables") {
		t.Errorf("a timed-out cheap probe must not fall back to `list tables`:\n%s", got)
	}
	if strings.Contains(got, "add table inet cfm") {
		t.Errorf("an unknown probe started EnsureBase:\n%s", got)
	}
	if !strings.Contains(got, "flush table inet cfm") {
		t.Errorf("ResetTable on an unknown probe must still try the flush, not report a silent success:\n%s", got)
	}
}

func TestProbeTable_EmptyListingIsAbsent(t *testing.T) {
	log := fakeNFTOpts(t, fakeOpts{chains: "empty"})
	b := New()
	if st := b.probeTable(); st != tableAbsent {
		t.Fatalf("probeTable with no inet cfm in the listing = %v, want absent", st)
	}
	if err := b.DropEverything(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, log); strings.Contains(got, "delete table") {
		t.Errorf("DropEverything on a definitely absent table deleted something:\n%s", got)
	}
}

// One element nft refuses fails the one-transaction self-set write; after a
// reboot the sets are empty, so each set is retried on its own, and a set that
// still refuses gets loopback and link-local alone.
func TestEnsureBase_RefusedSelfSetWriteFallsBack(t *testing.T) {
	v4, _ := wantSelfSets()
	s4, _ := firewall.SelfSetElems(nil)
	// Refuse the combined script (it holds both sets) and, if this host has a
	// local IPv4 address, any self_v4 write carrying it.
	refuse := "self_v4.*self_v6"
	if len(v4) > len(s4) {
		local := ""
		for _, e := range v4 {
			if e != "127.0.0.0/8" {
				local = strings.ReplaceAll(e, ".", "[.]")
				break
			}
		}
		refuse += "|add element inet cfm self_v4 .*" + local
	}
	log := fakeNFTOpts(t, fakeOpts{chains: "ok", self4: []string{}, self6: []string{}, refuseScript: refuse})
	if err := New().EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	got := readFile(t, log)
	// self_v6 lands in a script of its own.
	if !regexp.MustCompile(`ARGS -f -\nflush set inet cfm self_v6\n`).MatchString(got) {
		t.Errorf("no self_v6-only write after the combined one was refused:\n%s", got)
	}
	if len(v4) > len(s4) {
		if !strings.Contains(got, "ARGS -f -\nflush set inet cfm self_v4\nadd element inet cfm self_v4 { 127.0.0.0/8 }") {
			t.Errorf("a refused self_v4 must still get loopback alone:\n%s", got)
		}
	} else if !regexp.MustCompile(`ARGS -f -\nflush set inet cfm self_v4\n`).MatchString(got) {
		t.Errorf("no self_v4-only write after the combined one was refused:\n%s", got)
	}
}

// An element of a shape the reader does not know must not be dropped before
// the comparison: the kernel would hold an extra self source while the set
// read as "already right". Here self_v4 holds the wanted content plus one
// element in an unknown shape; it must be rewritten.
func TestEnsureBase_UnknownElementShapeIsRewritten(t *testing.T) {
	v4, v6 := wantSelfSets()
	log := fakeNFTOpts(t, fakeOpts{chains: "ok", self4: v4, self6: v6})
	// Append an element shape rawElemString does not know to self_v4's JSON.
	p := filepath.Join(filepath.Dir(log), "self_v4.json")
	b, err := os.ReadFile(p) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"elem":[`, `"elem":[{"set":["203.0.113.0/24"]},`, 1))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New().EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if got := readFile(t, log); !strings.Contains(got, "flush set inet cfm self_v4") {
		t.Errorf("a self set holding an unreadable element must be rewritten:\n%s", got)
	}
}
