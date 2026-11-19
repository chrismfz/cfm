package ipkey

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// scripts/tests/fixtures/ipkey.txt is shared with cfm_ipkey_test.lua: the edge
// and the daemon key a client the same way.
func TestClientFixture(t *testing.T) {
	f, err := os.Open("../../scripts/tests/fixtures/ipkey.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		in, want, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("bad fixture line %q", line)
		}
		if got := Client(in); got != want {
			t.Errorf("Client(%q) = %q, want %q", in, got, want)
		}
		n++
	}
	if n < 25 {
		t.Fatalf("only %d fixture cases", n)
	}
}

func TestPrefix(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    string
		grouped bool
	}{
		{"1.2.3.4", "1.2.3.4/32", false},
		{"::ffff:1.2.3.4", "1.2.3.4/32", false},
		{"2001:db8:1:2:a:b:c:d", "2001:db8:1:2::/64", true},
		{"::1", "::1/128", false},
		{"fe80::1", "fe80::1/128", false},
		{"fe80::1%eth0", "fe80::1/128", false}, // PrefixFrom drops the zone
		{"::", "::/128", false},
		{"::2", "::2/128", false},
		{"::1.2.3.4", "::102:304/128", false},
		{"ff02::1", "ff02::1/128", false},
		{"64:ff9b::1.2.3.4", "64:ff9b::102:304/128", false},
	} {
		p, g := Prefix(netip.MustParseAddr(c.in))
		if p.String() != c.want || g != c.grouped {
			t.Errorf("Prefix(%s) = %s, %v; want %s, %v", c.in, p, g, c.want, c.grouped)
		}
	}
	if p, g := Prefix(netip.Addr{}); p.IsValid() || g {
		t.Errorf("Prefix(invalid) = %v, %v; want the zero Prefix, false", p, g)
	}
	// Every address of a /64 maps to the same key; the next /64 does not.
	if Client("2001:db8:1:2::1") != Client("2001:db8:1:2:ffff:ffff:ffff:ffff") {
		t.Error("two addresses of one /64 keyed apart")
	}
	if Client("2001:db8:1:2::1") == Client("2001:db8:1:3::1") {
		t.Error("two /64s keyed together")
	}
}
