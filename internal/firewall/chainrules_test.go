package firewall

import (
	"strings"
	"testing"
)

// An `nft -a list chain` listing: quoted interface, the ICMP jumps (one in
// the form an nft version might print it, without its protocol match), an
// established/related block copy, no plain `jump flood`, and the `iif lo
// accept` copies the old check piled up.
const listing = `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		iif "lo" accept # handle 40
		iif "lo" accept # handle 41
		ip protocol icmp icmp type echo-request jump flood # handle 42
		icmpv6 type echo-request jump flood # handle 43
		iif "lo" accept # handle 44
		ct state established,related ip saddr @block_v4 drop # handle 50
	}
}
`

func TestChainRules_Has(t *testing.T) {
	c := ParseChainRules(listing)
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`iif lo accept`, true},   // nft prints it quoted
		{`iif "lo" accept`, true}, // either spelling
		{`ip protocol icmp icmp type echo-request jump flood`, true},
		{`ip6 nexthdr ipv6-icmp icmpv6 type echo-request jump flood`, true}, // printed without its protocol match
		{`ip saddr @block_v4 drop`, true},                                   // inside the established/related copy, as always
		{`jump flood`, false},                                               // a bare verdict must be a whole rule
		{`ip saddr @allow_v4 accept`, false},
		{`type filter hook input priority -50`, false}, // the hook line is not a rule
	} {
		if got := c.Has(tc.expr); got != tc.want {
			t.Errorf("Has(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
	c.Add("jump flood")
	if !c.Has("jump flood") {
		t.Error("a queued jump flood must read as present")
	}
}

func TestChainRules_DuplicateHandles(t *testing.T) {
	c := ParseChainRules(listing)
	c.Add(`iif lo accept`) // queued rules have no handle and are never deleted
	got := c.DuplicateHandles(`iif lo accept`, `jump flood`, `ip protocol icmp icmp type echo-request jump flood`)
	if strings.Join(got, ",") != "41,44" {
		t.Errorf("DuplicateHandles = %v, want [41 44] (all but the top-most iif lo)", got)
	}
}

// BaseDedupeExprs covers every base rule each engine writes, ICMP jumps
// always (a copy left from ICMP rate limiting is still a copy) and the flood
// jump, once each, but never the ports policy's established accept.
func TestBaseDedupeExprs(t *testing.T) {
	got := map[string]int{}
	for _, e := range BaseDedupeExprs() {
		got[e]++
	}
	if got[BaseEstablishedAccept] != 0 {
		t.Errorf("the established accept is the ports policy's to position")
	}
	for _, e := range append(append(BaseEarlyRules(true), BaseLateRules()...), BaseFloodJump) {
		if e != BaseEstablishedAccept && got[e] != 1 {
			t.Errorf("%q listed %d times, want once", e, got[e])
		}
	}
	if c := ParseChainRules("iif \"lo\" accept # handle 3\niif lo accept\nip protocol icmp icmp type echo-request jump flood\n").Count; c(`iif lo accept`) != 2 || c(`icmp type echo-request jump flood`) != 1 || c(`jump flood`) != 0 {
		t.Errorf("Count must match the printed key exactly, not a substring")
	}
}

// A plain base rule inside its `ct state established,related …` twin is NOT
// present: the twin matches only connections already open, so with the plain
// drop missing, new connections from banned addresses were let through, and
// EnsureBase never added it back (only the block_v6_clients drops were
// checked as themselves). A rule inside a NON-base rule still counts (an nft
// that prints a rule with more around it), and a whole rule always does.
func TestChainRules_PresentNeverTakesATwinForTheRule(t *testing.T) {
	listing := `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		iif "lo" accept # handle 2
		ct state established,related ip saddr @block_v4 drop # handle 3
		ct state established,related ip6 saddr @block_v6_clients drop # handle 4
		ct state established,related accept # handle 5
		ip saddr @allow_v4 counter packets 1 bytes 60 accept # handle 6
	}
}
`
	c := ParseChainRules(listing)
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`ip saddr @block_v4 drop`, false},          // only its established twin is there
		{`ip6 saddr @block_v6_clients drop`, false}, // anchored: as itself
		{`ct state established,related ip saddr @block_v4 drop`, true},
		{`iif lo accept`, true}, // quotes dropped
		{`ct state established,related accept`, true},
		{`ip saddr @allow_v4 accept`, false}, // "counter … accept" does not contain it as written
		{`jump flood`, false},                // bare verdict: a whole rule only
	} {
		if got := c.Present(tc.expr); got != tc.want {
			t.Errorf("Present(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}

	// Inside a rule that is not a base rule, a base rule still reads present.
	c = ParseChainRules("table inet cfm {\n\tchain input {\n\t\tmeta mark 0x1 ip saddr @block_v4 drop # handle 9\n\t}\n}\n")
	if !c.Present(`ip saddr @block_v4 drop`) {
		t.Errorf("a base rule inside a non-base rule must still read present (Has's tolerance)")
	}
	// Has itself is unchanged: the twin still contains the plain drop.
	if !ParseChainRules(listing).Has(`ip saddr @block_v4 drop`) {
		t.Errorf("Has changed: it must still match a rule inside a longer one")
	}
}

// A missing early rule on a chain that holds the rest goes after the nearest
// early rule above it, never at the top: an insert at 0 would put a re-added
// drop above the allow accepts, and an allowlisted address in a block set
// would be dropped.
func TestChainRules_EarlyAnchorHandle(t *testing.T) {
	early := BaseEarlyRules(false)
	listing := "table inet cfm {\n\tchain input { # handle 1\n" +
		"\t\tiif \"lo\" accept # handle 2\n" +
		"\t\tip saddr @self_v4 accept # handle 3\n" +
		"\t\tip6 saddr @allow_v6_nets accept # handle 14\n" +
		"\t\tip6 saddr @block_v6 drop # handle 16\n" +
		"\t}\n}\n"
	c := ParseChainRules(listing)
	for _, tc := range []struct{ expr, want string }{
		{`ip saddr @block_v4 drop`, "14"},           // after the last allow listed
		{`ip saddr @block_ext_v4_hosts drop`, "16"}, // after block_v6, its nearest listed predecessor
		{`ip6 saddr @self_v6 accept`, "3"},
		{`iif lo accept`, ""}, // nothing above it: the insert at 0 is right
	} {
		if got := c.EarlyAnchorHandle(tc.expr, early); got != tc.want {
			t.Errorf("EarlyAnchorHandle(%q) = %q, want %q", tc.expr, got, tc.want)
		}
	}
	// A new chain lists nothing: every early rule is inserted at 0.
	if got := ParseChainRules("").EarlyAnchorHandle(`ip saddr @block_v4 drop`, early); got != "" {
		t.Errorf("empty chain: got %q, want \"\"", got)
	}
}
