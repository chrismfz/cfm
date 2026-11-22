//go:build linux

package nft

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
	chainsRC := 0
	if !chainsOK {
		chainsRC = 1
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %[1]q
if [ "$1" = "-f" ]; then in=$(cat); printf '%%s\n' "$in" >> %[1]q; exit 0; fi
case "$*" in
"list chains inet") [ %[5]d = 0 ] && cat %[4]q; exit %[5]d ;;
"list tables") echo "table inet cfm"; exit 0 ;;
"-j list set inet cfm self_v4") cat %[2]q || exit 1; exit 0 ;;
"-j list set inet cfm self_v6") cat %[3]q || exit 1; exit 0 ;;
esac
exit 0
`, logPath, setJSON("self_v4", self4), setJSON("self_v6", self6), chains, chainsRC)
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
	b := New()
	_ = b.DropEverything()
	t.Cleanup(func() { _ = b.DropEverything() })
	if err := b.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	v4, v6 := firewall.SelfSetElems(b.selfResolver.LocalIPs())
	if !b.setHolds("self_v4", v4) || !b.setHolds("self_v6", v6) {
		h4, _ := b.ListSetElementsRaw("self_v4")
		h6, _ := b.ListSetElementsRaw("self_v6")
		t.Fatalf("self sets after EnsureBase: v4=%v v6=%v; want v4=%v v6=%v", h4, h6, v4, v6)
	}
	if !b.tableExists() {
		t.Fatal("tableExists after EnsureBase = false")
	}
}
