//go:build linux

package nftlib

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
)

func v4key(s string) []byte { return net.ParseIP(s).To4() }

// An interval set's elements become ranges whatever the dump order, a range
// reaching the top of the address space has no end element, and a range that
// isn't one prefix is written "first-last". Pairing by index read
// {1.0.0.0/8, 192.0.2.0/24, 240.0.0.0/4} as three /32s.
func TestElemsToStrings_Intervals(t *testing.T) {
	start := func(s string) nftables.SetElement { return nftables.SetElement{Key: v4key(s)} }
	end := func(s string) nftables.SetElement { return nftables.SetElement{Key: v4key(s), IntervalEnd: true} }
	elems := []nftables.SetElement{ // descending, as the kernel dumps
		start("240.0.0.0"),
		end("203.0.113.21"), start("203.0.113.10"),
		end("192.0.3.0"), start("192.0.2.0"),
		end("2.0.0.0"), start("1.0.0.0"),
	}
	want := []string{"1.0.0.0/8", "192.0.2.0/24", "203.0.113.10-203.0.113.20", "240.0.0.0/4"}
	if got := elemsToStrings(elems, true); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// Adjacent ranges share a key; a lone range to the top is not a host.
	adj := []nftables.SetElement{start("10.0.0.0"), end("10.0.1.0"), start("10.0.1.0"), end("10.0.2.0")}
	if got := elemsToStrings(adj, true); !reflect.DeepEqual(got, []string{"10.0.0.0/24", "10.0.1.0/24"}) {
		t.Errorf("adjacent: %q", got)
	}
	if got := elemsToStrings([]nftables.SetElement{start("0.0.0.0")}, true); !reflect.DeepEqual(got, []string{"0.0.0.0/0"}) {
		t.Errorf("0.0.0.0/0: %q", got)
	}
	six := []nftables.SetElement{{Key: net.ParseIP("ff00::")}, {Key: net.ParseIP("2001:db8::")}, {Key: net.ParseIP("2001:db9::"), IntervalEnd: true}}
	if got := elemsToStrings(six, true); !reflect.DeepEqual(got, []string{"2001:db8::/32", "ff00::/8"}) {
		t.Errorf("v6: %q", got)
	}
	// A plain set is addresses, whatever its keys.
	if got := elemsToStrings([]nftables.SetElement{start("198.51.100.8"), start("0.0.0.0")}, false); !reflect.DeepEqual(got, []string{"198.51.100.8", "0.0.0.0"}) {
		t.Errorf("hosts: %q", got)
	}
	// The timeout is the start element's.
	timed := elemsToTimed([]nftables.SetElement{{Key: v4key("10.0.0.0"), Timeout: time.Hour, Expires: time.Minute}, end("10.1.0.0")}, true)
	if len(timed) != 1 || timed[0].Elem != "10.0.0.0/16" || timed[0].Expires != time.Minute {
		t.Errorf("timed: %+v", timed)
	}
}

func TestRangeString(t *testing.T) {
	for _, c := range []struct{ first, last, want string }{
		{"10.0.0.0", "10.0.0.255", "10.0.0.0/24"},
		{"10.0.0.1", "10.0.0.1", "10.0.0.1/32"},
		{"10.0.0.1", "10.0.0.2", "10.0.0.1-10.0.0.2"},
		{"10.0.0.0", "10.0.1.255", "10.0.0.0/23"},
		{"10.0.1.0", "10.0.2.255", "10.0.1.0-10.0.2.255"}, // two /24s, not one prefix
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
	} {
		if got := rangeString(v4key(c.first), v4key(c.last)); got != c.want {
			t.Errorf("rangeString(%s, %s) = %q, want %q", c.first, c.last, got, c.want)
		}
	}
	if got := rangeString(net.ParseIP("::"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")); got != "::/0" {
		t.Errorf("v6 all = %q", got)
	}
	if got := rangeString(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")); got != "2001:db8::1-2001:db8::2" {
		t.Errorf("v6 range = %q", got)
	}
}
