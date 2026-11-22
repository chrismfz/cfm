//go:build linux

package nftlib

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"cfm/internal/firewall"
	"cfm/internal/firewall/bantest"
)

// fakeNFTChain puts an `nft` script first in PATH that prints chain for
// `-a list chain inet cfm input`, logs every invocation and every script fed on
// stdin, and fails the first failScripts `nft -f -` runs.
func fakeNFTChain(t *testing.T, chain string, failScripts int) (logPath string) {
	return fakeNFTChainOpts(t, chain, failScripts, "")
}

// fakeNFTChainOpts is fakeNFTChain with a mode: "readfail" fails every chain
// read, "rereadfail" every read after the first; "commitfail" makes a failing
// -f run still commit its rules to the chain first (as nft killed at its
// timeout after the kernel committed).
func fakeNFTChainOpts(t *testing.T, chain string, failScripts int, mode string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	for name, body := range map[string]string{"chain": chain, "fails": fmt.Sprint(failScripts), "mode": mode} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := fmt.Sprintf(`#!/bin/sh
d=%[1]q
echo "ARGS $*" >> "$d/nft.log"
mode=$(cat "$d/mode")
case "$*" in
"-a list chain inet cfm input")
	if [ "$mode" = readfail ]; then echo "Error: timed out" >&2; exit 1; fi
	if [ "$mode" = rereadfail ] && [ -e "$d/read1" ]; then echo "Error: timed out" >&2; exit 1; fi
	touch "$d/read1"; cat "$d/chain"; exit 0;;
"-f -")
	in=$(cat); printf 'SCRIPT %%s\n' "$in" >> "$d/nft.log"
	n=$(cat "$d/fails")
	if [ "$n" -gt 0 ]; then
		echo $((n-1)) > "$d/fails"
		if [ "$mode" = commitfail ]; then
			printf '%%s\n' "$in" | sed -e 's/;$//' -e 's/^insert rule inet cfm input position 0 //' -e 's/^add rule inet cfm input //' >> "$d/chain"
		fi
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

func readNFTLog(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- test temp file
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// The base input rules cost one read of the chain and at most one nft run,
// however many are missing. They cost one nft process each (plus a chain
// read each): ~50 processes per EnsureBase, and over a second apiece on a
// node with large feed sets — ~70s per EnsureBase in production.
func TestApplyBaseInputRules_OneReadOneWrite(t *testing.T) {
	log := fakeNFTChain(t, "table inet cfm {\n\tchain input {\n\t\ttype filter hook input priority -50; policy accept;\n\t}\n}\n", 0)
	_ = (&Backend{}).applyBaseInputRules(false)
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS "); n != 2 {
		t.Fatalf("%d nft processes, want 2 (one read, one write):\n%s", n, got)
	}
	first := strings.Index(got, `insert rule inet cfm input position 0 ip6 saddr @block_v6_clients drop`)
	last := strings.Index(got, `insert rule inet cfm input position 0 iif lo accept`)
	flood := strings.Index(got, "add rule inet cfm input jump flood")
	if first < 0 || last < 0 || first > last || flood < last {
		t.Errorf("want the early rules inserted bottom-up (so iif lo ends on top), then the adds, jump flood last:\n%s", got)
	}
	if n := strings.Count(got, "\ninsert rule") + strings.Count(got, "SCRIPT insert rule"); n != 22 {
		t.Errorf("%d inserts, want the 22 early rules", n)
	}
	// The appended allow/block copies read as present once the early rules
	// are queued, exactly as the per-rule version found them in the chain.
	if n := strings.Count(got, "add rule"); n != 11 {
		t.Errorf("%d adds, want 10 established/related rules + jump flood:\n%s", n, got)
	}

	// Everything present: one read, no write.
	full := "table inet cfm {\n\tchain input {\n"
	for _, st := range baseRulesScript("", nil, allBaseRules(t)) {
		full += "\t\t" + strings.TrimPrefix(st, "add rule inet cfm input ") + "\n"
	}
	log = fakeNFTChain(t, full+"\t}\n}\n", 0)
	_ = (&Backend{}).applyBaseInputRules(false)
	if got := readNFTLog(t, log); strings.Count(got, "ARGS ") != 1 || strings.Contains(got, "ARGS -f -") {
		t.Errorf("want the one read and no write when every rule is present:\n%s", got)
	}
}

// allBaseRules is every rule applyBaseInputRules installs, as expressions.
func allBaseRules(t *testing.T) []string {
	t.Helper()
	log := fakeNFTChain(t, "", 0)
	_ = (&Backend{}).applyBaseInputRules(false)
	var out []string
	for _, line := range strings.Split(readNFTLog(t, log), "\n") {
		line = strings.TrimSuffix(strings.TrimPrefix(line, "SCRIPT "), ";") // nftExec ends the script with ";"
		for _, p := range []string{"insert rule inet cfm input position 0 ", "add rule inet cfm input "} {
			if strings.HasPrefix(line, p) {
				out = append(out, strings.TrimPrefix(line, p))
			}
		}
	}
	return out
}

// A script nft refuses falls back to one statement per run, so one bad rule
// can't keep the others out (as before, each rule was its own run).
func TestApplyBaseInputRules_FallsBackPerStatement(t *testing.T) {
	log := fakeNFTChain(t, "", 1)
	_ = (&Backend{}).applyBaseInputRules(false)
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS -f -"); n != 1+33 {
		t.Errorf("%d nft -f runs, want the failed script + 33 single statements", n)
	}
}

func TestBaseRulesScript(t *testing.T) {
	chain := "chain input {\n\tct state established,related ip saddr @block_v4 drop\n\tiif \"lo\" accept\n}"
	got := baseRulesScript(chain,
		[]string{`ip saddr @block_v4 drop`, `iif "lo" accept`, `ip saddr @self_v4 accept`},
		[]string{`ip saddr @self_v4 accept`, `jump flood`, `jump flood`})
	want := []string{
		// `ip saddr @block_v4 drop` is inside the established/related rule's
		// text: present, as the substring check always had it.
		"insert rule inet cfm input position 0 ip saddr @self_v4 accept",
		"add rule inet cfm input jump flood",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("baseRulesScript =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Rules are only ever added, so a chain that can't be read must not be taken
// for an empty one — that would add every rule a second time.
func TestApplyBaseInputRules_UnreadChainWritesNothing(t *testing.T) {
	log := fakeNFTChainOpts(t, "", 0, "readfail")
	err := (&Backend{}).applyBaseInputRules(false)
	if got := readNFTLog(t, log); strings.Contains(got, "ARGS -f -") || err == nil {
		t.Errorf("err=%v; want an error and no write without knowing the chain:\n%s", err, got)
	}

	// Unless EnsureBase just created the chain: it is empty, and leaving it so
	// would leave the node without its allow/block rules.
	log = fakeNFTChainOpts(t, "", 0, "readfail")
	if err := (&Backend{}).applyBaseInputRules(true); err != nil {
		t.Fatalf("applyBaseInputRules on a new chain: %v", err)
	}
	if got := readNFTLog(t, log); strings.Count(got, "ARGS -f -") != 1 || !strings.Contains(got, `iif lo accept`) {
		t.Errorf("want the rules written to the new chain in one run:\n%.300s", got)
	}
}

// A failed run whose chain can't be re-read is reported, not retried blind.
func TestApplyBaseInputRules_FailedRunUnreadChainReports(t *testing.T) {
	log := fakeNFTChainOpts(t, "", 1, "rereadfail")
	err := (&Backend{}).applyBaseInputRules(false)
	if err == nil || !strings.Contains(err.Error(), "can't re-read") {
		t.Errorf("err = %v, want the failed run and the failed re-read reported", err)
	}
	if n := strings.Count(readNFTLog(t, log), "ARGS -f -"); n != 1 {
		t.Errorf("%d nft -f runs, want just the failed one", n)
	}
}

// A run that committed before failing (e.g. killed at its timeout) is not
// replayed statement by statement: the fallback re-reads the chain first.
func TestApplyBaseInputRules_FallbackRereadsTheChain(t *testing.T) {
	log := fakeNFTChainOpts(t, "", 1, "commitfail")
	_ = (&Backend{}).applyBaseInputRules(false)
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS -f -"); n != 1 {
		t.Errorf("%d nft -f runs, want just the one that committed (no replay):\n%.300s", n, got)
	}
	if n := strings.Count(got, "ARGS -a list chain"); n != 2 {
		t.Errorf("%d chain reads, want 2 (before the run, and before any fallback)", n)
	}
}

// With ICMP rate limiting on, the plain `jump flood` is added even though the
// ICMP jumps already end in "jump flood" — as a substring, they kept it out,
// and TCP/UDP never went through the flood chain. Extra copies of the base
// rules the old check missed are deleted, top-most kept.
func TestBaseRulesScript_JumpFloodAndDuplicates(t *testing.T) {
	chain := "table inet cfm {\n\tchain input { # handle 1\n" +
		"\t\tiif \"lo\" accept # handle 7\n" +
		"\t\tip protocol icmp icmp type echo-request jump flood # handle 8\n" +
		"\t\tip protocol icmp icmp type echo-request jump flood # handle 9\n" +
		"\t\tiif \"lo\" accept # handle 10\n" +
		"\t}\n}\n"
	got := baseRulesScript(chain, []string{`iif "lo" accept`, firewall.ICMPFloodJumps[0]}, []string{"jump flood"})
	want := []string{
		"delete rule inet cfm input handle 10",
		"delete rule inet cfm input handle 9",
		"add rule inet cfm input jump flood",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("baseRulesScript =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// On a chain from before block_v6_clients, its drops go right after their
// block_v6_nets anchors (add … position <handle>), never at position 0 above
// the self / allow accepts; on a new chain the ordinary order places them.
func TestBaseRulesScriptAnchorsTheClientDrops(t *testing.T) {
	old := "chain input {\n" +
		"\tiif \"lo\" accept # handle 3\n" +
		"\tip6 saddr @self_v6 accept # handle 5\n" +
		"\tip6 saddr @block_v6_nets drop # handle 26\n" +
		"\tct state established,related ip6 saddr @block_v6_nets drop # handle 40\n" +
		"}"
	got := baseRulesScript(old,
		[]string{`iif "lo" accept`, `ip6 saddr @self_v6 accept`, `ip6 saddr @block_v6_nets drop`, `ip6 saddr @block_v6_clients drop`},
		[]string{`ct state established,related ip6 saddr @block_v6_nets drop`, `ct state established,related ip6 saddr @block_v6_clients drop`})
	want := []string{
		"add rule inet cfm input position 26 ip6 saddr @block_v6_clients drop",
		"add rule inet cfm input position 40 ct state established,related ip6 saddr @block_v6_clients drop",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("script:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	fresh := baseRulesScript("", []string{`ip6 saddr @block_v6_clients drop`}, nil)
	if len(fresh) != 1 || fresh[0] != "insert rule inet cfm input position 0 ip6 saddr @block_v6_clients drop" {
		t.Fatalf("a new chain: %v", fresh)
	}
}

// Engine parity: on the chain one blind re-add of the base layer leaves,
// nftlib deletes exactly the handles the nft backend does (the same fixture
// and answer, bantest.DuplicatedBaseChain; nft's twin is
// TestEnsureBase_DedupeParity), every one in the run that adds nothing, and
// the established accept the ports policy positions is never touched.
func TestApplyBaseInputRules_DedupeParity(t *testing.T) {
	chain, want := bantest.DuplicatedBaseChain()
	log := fakeNFTChain(t, chain, 0)
	if err := (&Backend{}).applyBaseInputRules(false); err != nil {
		t.Fatalf("applyBaseInputRules: %v", err)
	}
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS -f -"); n != 1 {
		t.Errorf("%d nft -f runs, want the deletes in ONE transaction:\n%s", n, got)
	}
	if strings.Contains(got, "insert rule") || strings.Contains(got, "add rule") {
		t.Errorf("re-added a rule the chain already holds:\n%s", got)
	}
	sort.Strings(want)
	if d := bantest.DeletedHandles(got); strings.Join(d, " ") != strings.Join(want, " ") {
		t.Errorf("deleted handles\n%v\nwant\n%v", d, want)
	}
}

// A failed run's fallback keeps the deletes in one transaction (a node can
// hold thousands; one nft run each costs seconds on EL8) and runs only the
// rules to add one by one.
func TestApplyBaseInputRules_FallbackKeepsDeletesInOneRun(t *testing.T) {
	chain, _ := bantest.DuplicatedBaseChain()
	// Drop the flood jumps so the script also adds one rule.
	chain = strings.NewReplacer("\t\tjump flood # handle", "\t\tudp dport 9 drop # handle").Replace(chain)
	log := fakeNFTChain(t, chain, 1)
	_ = (&Backend{}).applyBaseInputRules(false)
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS -f -"); n != 3 {
		t.Errorf("%d nft -f runs, want the failed script, the deletes, the one add:\n%s", n, got)
	}
	last := got[strings.LastIndex(got, "SCRIPT "):]
	if !strings.HasPrefix(last, "SCRIPT add rule inet cfm input jump flood") {
		t.Errorf("last run %q, want the flood jump alone", last)
	}
}

// When the fallback's delete run fails too, the error says so in its own
// words, not as one statement among the rest.
func TestApplyBaseInputRules_FallbackReportsFailedDeletes(t *testing.T) {
	chain, want := bantest.DuplicatedBaseChain()
	fakeNFTChain(t, chain, 2) // the whole script, then the delete run
	err := (&Backend{}).applyBaseInputRules(false)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the run deleting %d duplicate base rules failed too", len(want))) {
		t.Errorf("err = %v, want the failed delete run named with its %d deletes", err, len(want))
	}
}
