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
