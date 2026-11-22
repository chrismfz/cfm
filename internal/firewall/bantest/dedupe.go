//go:build linux

package bantest

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// DuplicatedBaseChain is an `nft -a list chain inet cfm input` listing that
// holds every base rule twice, the way one blind re-add of the base layer
// left it (the early group again on top, the late group appended again, the
// ICMP jumps and the flood jump twice), plus a rule that is not a base rule
// (twice). want is the handles both engines' EnsureBase must delete: the
// second copy of every base rule but the ports policy's established accept.
// It is built from the rules, not from ChainRules.DuplicateHandles, so each
// engine's test checks what it deletes against the same independent answer.
func DuplicatedBaseChain() (listing string, want []string) {
	var sb strings.Builder
	sb.WriteString("table inet cfm {\n\tchain input { # handle 1\n\t\ttype filter hook input priority -50; policy accept;\n")
	h := 100
	seen := map[string]bool{}
	rule := func(r string) {
		h++
		// nft prints the loopback match quoted.
		fmt.Fprintf(&sb, "\t\t%s # handle %d\n", strings.ReplaceAll(r, "iif lo", `iif "lo"`), h)
		if seen[r] && r != firewall.BaseEstablishedAccept && r != notBase {
			want = append(want, fmt.Sprint(h))
		}
		seen[r] = true
	}
	early := firewall.BaseEarlyRules(true)
	for pass := 0; pass < 2; pass++ {
		for _, r := range early {
			rule(r)
		}
	}
	for pass := 0; pass < 2; pass++ {
		for _, r := range firewall.BaseLateRules() {
			if seen[r] && pass == 0 {
				continue // the late copy of an early rule: the early group holds it
			}
			rule(r)
		}
	}
	rule(firewall.BaseFloodJump)
	rule(firewall.BaseFloodJump)
	rule(notBase)
	rule(notBase)
	sb.WriteString("\t}\n}\n")
	return sb.String(), want
}

// notBase is a rule EnsureBase does not own: its copies are left alone.
const notBase = `tcp dport 22 accept`

// DeletedHandles is the handles of the `delete rule inet cfm input handle N`
// statements in s, sorted.
func DeletedHandles(s string) []string {
	var out []string
	for _, f := range strings.Split(s, "delete rule inet cfm input handle ")[1:] {
		n := strings.FieldsFunc(f, func(r rune) bool { return r < '0' || r > '9' })
		if len(n) > 0 && strings.HasPrefix(f, n[0]) {
			out = append(out, n[0])
		}
	}
	sort.Strings(out)
	return out
}

// RunDedupeBaseRules drives an engine's EnsureBase against a live nft: a
// chain holding 50 copies of the base layer (what the old blind re-add left,
// ~268 on mars) is brought back to one copy of each base rule, the ICMP jumps
// included with ICMP rate limiting off, the ports policy's established accept
// kept, the base order intact; a second EnsureBase deletes nothing more.
//
// Gated like RunTTLBansSurviveRestart; it refuses to run outside an empty
// network namespace.
func RunDedupeBaseRules(t *testing.T, newBackend func() firewall.Backend) {
	t.Helper()
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "" {
		t.Fatalf("refusing to run: this namespace already has tables (not an isolated netns?):\n%s", out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	b := newBackend()
	if err := b.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	// Re-add the whole base layer 49 times, as a blind EnsureBase did, with
	// the ICMP jumps (left from when ICMP rate limiting was on).
	var sb strings.Builder
	early := firewall.BaseEarlyRules(true)
	for i := 0; i < 49; i++ {
		for j := len(early) - 1; j >= 0; j-- {
			fmt.Fprintf(&sb, "insert rule inet cfm input position 0 %s\n", early[j])
		}
		for _, r := range firewall.BaseLateRules() {
			fmt.Fprintf(&sb, "add rule inet cfm input %s\n", r)
		}
		fmt.Fprintf(&sb, "add rule inet cfm input %s\n", firewall.BaseFloodJump)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(sb.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seeding copies: %v %s", err, out)
	}
	listing := func() string {
		out, err := exec.Command("nft", "list", "chain", "inet", "cfm", "input").Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	// Counted by ChainRules' key (quotes dropped, ICMP protocol matches
	// folded), so an nft version printing a rule differently still counts.
	count := func(l string) map[string]int {
		n := map[string]int{}
		rules := firewall.ParseChainRules(l)
		for _, e := range append(firewall.BaseDedupeExprs(), firewall.BaseEstablishedAccept) {
			n[e] = rules.Count(e)
		}
		return n
	}
	if c := count(listing())["ip saddr @block_v4 drop"]; c < 50 {
		t.Fatalf("seeding left %d copies of ip saddr @block_v4 drop, want >= 50", c)
	}
	if err := b.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase after seeding: %v", err)
	}
	after := listing()
	n := count(after)
	for _, e := range firewall.BaseDedupeExprs() {
		if n[e] != 1 {
			t.Errorf("%q: %d copies after EnsureBase, want 1", e, n[e])
		}
	}
	if n[firewall.BaseEstablishedAccept] < 1 {
		t.Errorf("the established accept is gone")
	}
	// The order the base layer wants: loopback first, the self accept above
	// every block, the block drops above the established accept, the flood
	// jump below it.
	lo, self := strings.Index(after, `iif "lo" accept`), strings.Index(after, "ip saddr @self_v4 accept")
	blk, est := strings.Index(after, "ip saddr @block_v4 drop"), strings.Index(after, firewall.BaseEstablishedAccept)
	flood := strings.Index(after, "\t"+firewall.BaseFloodJump+"\n")
	if !(lo >= 0 && lo < self && self < blk && blk < est && est < flood) {
		t.Errorf("base order broken after dedupe:\n%s", after)
	}
	// Nothing more to delete, nothing to add.
	if err := b.EnsureBase(); err != nil {
		t.Fatalf("second EnsureBase: %v", err)
	}
	if again := listing(); again != after {
		t.Errorf("a second EnsureBase changed the chain:\nbefore:\n%s\nafter:\n%s", after, again)
	}
}
