package firewall

import (
	"strings"
	"testing"
)

func TestSelfSetElems(t *testing.T) {
	v4, v6 := SelfSetElems([]string{"192.0.2.10", "fe80::1234", "2001:db8::5", "192.0.2.10", "::ffff:198.51.100.7", "junk"})
	if got := strings.Join(v4, " "); got != "127.0.0.0/8 192.0.2.10/32 198.51.100.7/32" {
		t.Errorf("v4 = %s", got)
	}
	// fe80::1234 lies inside fe80::/10: an interval set refuses the overlap.
	if got := strings.Join(v6, " "); got != "::1/128 2001:db8::5/128 fe80::/10" {
		t.Errorf("v6 = %s", got)
	}
}

func TestSameSetElems(t *testing.T) {
	want := []string{"127.0.0.0/8", "192.0.2.10/32"}
	cases := []struct {
		have []string
		same bool
	}{
		{[]string{"192.0.2.10", "127.0.0.0/8"}, true}, // nft's spelling and order
		{[]string{"127.0.0.0/8", "192.0.2.10/32", "192.0.2.10"}, true},
		{[]string{"127.0.0.0/8"}, false},
		{[]string{"127.0.0.0/8", "192.0.2.11"}, false},
		{[]string{"127.0.0.0/8", "192.0.2.10", "198.51.100.1"}, false},
		{[]string{"127.0.0.0-127.255.255.255", "192.0.2.10"}, false}, // unparsed never matches
		{nil, false},
	}
	for _, c := range cases {
		if got := SameSetElems(c.have, want); got != c.same {
			t.Errorf("SameSetElems(%q) = %v, want %v", c.have, got, c.same)
		}
	}
	if !SameSetElems([]string{"::1", "fe80::/10"}, []string{"::1/128", "fe80::/10"}) {
		t.Error("v6 spelling")
	}
	if !SameSetElems([]string{"::ffff:192.0.2.10"}, []string{"192.0.2.10/32"}) {
		t.Error("an IPv4-mapped address is its IPv4 address")
	}
	if SameSetElems([]string{"::ffff:0:0/80"}, []string{"::/0"}) {
		t.Error("a mapped prefix shorter than /96 must not collapse into something else")
	}
}
