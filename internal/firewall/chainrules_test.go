package firewall

import (
	"strings"
	"testing"
)

// An `nft -a list chain` listing as nft prints it: quoted interface, ICMP
// jumps, an established/related block copy, no plain `jump flood`, and the
// `iif lo accept` copies the old check piled up.
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
