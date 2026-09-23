//go:build linux

package nftlib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNFTChain puts an `nft` script first in PATH that prints chain for
// `list chain inet cfm input`, logs every invocation and every script fed on
// stdin, and fails the first failScripts `nft -f -` runs.
func fakeNFTChain(t *testing.T, chain string, failScripts int) (logPath string) {
	return fakeNFTChainOpts(t, chain, failScripts, "")
}

// fakeNFTChainOpts is fakeNFTChain with a mode: "readfail" fails every chain
// read; "commitfail" makes a failing -f run still commit its rules to the
// chain first (as nft killed at its timeout after the kernel committed).
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
"list chain inet cfm input")
	if [ "$mode" = readfail ]; then echo "Error: timed out" >&2; exit 1; fi
	cat "$d/chain"; exit 0;;
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
	(&Backend{}).applyBaseInputRules()
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS "); n != 2 {
		t.Fatalf("%d nft processes, want 2 (one read, one write):\n%s", n, got)
	}
	first := strings.Index(got, `insert rule inet cfm input position 0 ip6 saddr @block_v6_nets drop`)
	last := strings.Index(got, `insert rule inet cfm input position 0 iif "lo" accept`)
	flood := strings.Index(got, "add rule inet cfm input jump flood")
	if first < 0 || last < 0 || first > last || flood < last {
		t.Errorf("want the early rules inserted bottom-up (so iif lo ends on top), then the adds, jump flood last:\n%s", got)
	}
	if n := strings.Count(got, "\ninsert rule") + strings.Count(got, "SCRIPT insert rule"); n != 21 {
		t.Errorf("%d inserts, want the 21 early rules", n)
	}
	// The appended allow/block copies read as present once the early rules
	// are queued, exactly as the per-rule version found them in the chain.
	if n := strings.Count(got, "add rule"); n != 10 {
		t.Errorf("%d adds, want 9 established/related rules + jump flood:\n%s", n, got)
	}

	// Everything present: one read, no write.
	full := "table inet cfm {\n\tchain input {\n"
	for _, st := range baseRulesScript("", nil, allBaseRules(t)) {
		full += "\t\t" + strings.TrimPrefix(st, "add rule inet cfm input ") + "\n"
	}
	log = fakeNFTChain(t, full+"\t}\n}\n", 0)
	(&Backend{}).applyBaseInputRules()
	if got := readNFTLog(t, log); strings.Count(got, "ARGS ") != 1 || strings.Contains(got, "ARGS -f -") {
		t.Errorf("want the one read and no write when every rule is present:\n%s", got)
	}
}

// allBaseRules is every rule applyBaseInputRules installs, as expressions.
func allBaseRules(t *testing.T) []string {
	t.Helper()
	log := fakeNFTChain(t, "", 0)
	(&Backend{}).applyBaseInputRules()
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
	(&Backend{}).applyBaseInputRules()
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS -f -"); n != 1+31 {
		t.Errorf("%d nft -f runs, want the failed script + 31 single statements", n)
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

func TestSelfSetElems(t *testing.T) {
	v4, v6 := selfSetElems([]string{"192.0.2.10", "fe80::1234", "2001:db8::5", "192.0.2.10", "::ffff:198.51.100.7", "junk"})
	if got := strings.Join(v4, " "); got != "127.0.0.0/8 192.0.2.10/32 198.51.100.7/32" {
		t.Errorf("v4 = %s", got)
	}
	// fe80::1234 lies inside fe80::/10: an interval set refuses the overlap.
	if got := strings.Join(v6, " "); got != "::1/128 2001:db8::5/128 fe80::/10" {
		t.Errorf("v6 = %s", got)
	}
}

// Rules are only ever added, so a chain that can't be read must not be taken
// for an empty one — that would add every rule a second time.
func TestApplyBaseInputRules_UnreadChainWritesNothing(t *testing.T) {
	log := fakeNFTChainOpts(t, "", 0, "readfail")
	(&Backend{}).applyBaseInputRules()
	if got := readNFTLog(t, log); strings.Contains(got, "ARGS -f -") {
		t.Errorf("wrote rules without knowing the chain:\n%s", got)
	}
}

// A run that committed before failing (e.g. killed at its timeout) is not
// replayed statement by statement: the fallback re-reads the chain first.
func TestApplyBaseInputRules_FallbackRereadsTheChain(t *testing.T) {
	log := fakeNFTChainOpts(t, "", 1, "commitfail")
	(&Backend{}).applyBaseInputRules()
	got := readNFTLog(t, log)
	if n := strings.Count(got, "ARGS -f -"); n != 1 {
		t.Errorf("%d nft -f runs, want just the one that committed (no replay):\n%.300s", n, got)
	}
	if n := strings.Count(got, "ARGS list chain"); n != 2 {
		t.Errorf("%d chain reads, want 2 (before the run, and before any fallback)", n)
	}
}
