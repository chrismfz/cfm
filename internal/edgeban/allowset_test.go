package edgeban

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

// benchStore: n bans and an allow set of nets CIDRs and hosts host
// addresses (mars, 2026-11-10: 23 000 bans).
func benchStore(b *testing.B, n, nets, hosts int) *Store {
	b.Helper()
	s := New("")
	var allows []string
	for i := 0; i < nets; i++ {
		allows = append(allows, fmt.Sprintf("100.%d.%d.0/24", 64+i/256%64, i%256))
	}
	for i := 0; i < hosts; i++ {
		allows = append(allows, fmt.Sprintf("198.18.%d.%d", i/256%256, i%256))
	}
	s.Reconcile(Snapshot{Allows: allows})
	ttl := 6 * time.Hour
	for i := 0; i < n; i++ {
		s.m[key(net.IPv4(byte(1+i/65536), byte(i/256), byte(i), 7))] = Entry{Expires: time.Now().Add(ttl), Source: "waf_security"}
	}
	return s
}

func BenchmarkList(b *testing.B) {
	for _, c := range []struct{ n, nets, hosts int }{{23000, 0, 0}, {23000, 100, 1000}, {23000, 1000, 5000}} {
		b.Run(fmt.Sprintf("bans=%d/nets=%d", c.n, c.nets), func(b *testing.B) {
			s := benchStore(b, c.n, c.nets, c.hosts)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.List()
			}
		})
	}
}

// The interval allow set answers exactly what the old linear one did:
// IPNet.Contains for CIDRs, a same-family first-last compare for ranges.
func TestAllowSetMatchesLinear(t *testing.T) {
	elems := []string{
		"10.0.0.0/8", "10.1.0.0/16", "192.0.2.0/25", "192.0.2.128/25", "203.0.113.7",
		"198.51.100.10-198.51.100.20", "198.51.100.21-198.51.100.30", "198.51.100.50-198.51.100.40",
		"2001:db8::/32", "2001:db8:1::/48", "2a09:bac0::/29", "2001:db8:ffff::1-2001:db8:ffff::9",
		"::ffff:100.64.0.0/120", "1.2.3.4-2001:db8::1", "0.0.0.0/0x", "255.255.255.255/32",
	}
	a := parseAllowSet(elems)
	linear := func(ip net.IP) bool {
		for _, e := range elems {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(ip) {
				return true
			}
			if lo, hi, ok := strings.Cut(e, "-"); ok {
				l, h := norm(net.ParseIP(lo)), norm(net.ParseIP(hi))
				n := norm(ip)
				if l != nil && h != nil && len(l) == len(n) && len(h) == len(n) &&
					bytes.Compare(l, n) <= 0 && bytes.Compare(n, h) <= 0 {
					return true
				}
			}
			if p := net.ParseIP(e); p != nil && p.Equal(ip) {
				return true
			}
		}
		return false
	}
	probes := []string{
		"10.0.0.0", "10.255.255.255", "11.0.0.0", "9.255.255.255", "192.0.2.0", "192.0.2.127", "192.0.2.128",
		"192.0.2.255", "192.0.3.0", "203.0.113.7", "203.0.113.8", "198.51.100.10", "198.51.100.25",
		"198.51.100.30", "198.51.100.31", "198.51.100.45", "2001:db8::", "2001:db8:ffff:ffff::1", "2001:db9::",
		"2a09:bac7:ffff::1", "2a09:bac8::", "2001:db8:ffff::5", "100.64.0.9", "::ffff:100.64.0.9",
		"::ffff:10.1.2.3", "255.255.255.255", "0.0.0.0", "::", "::1",
	}
	for _, p := range probes {
		ip := net.ParseIP(p)
		if got, want := a.contains(ip), linear(ip); got != want {
			t.Errorf("%s: %v, linear %v", p, got, want)
		}
	}
}

// Random CIDRs (overlapping, nested, adjacent, both families) against
// net.IPNet.Contains.
func TestAllowSetMatchesIPNetRandom(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for round := 0; round < 50; round++ {
		var elems []string
		var nets []*net.IPNet
		for i := 0; i < 40; i++ {
			var cidr string
			if r.Intn(2) == 0 {
				cidr = fmt.Sprintf("%d.%d.%d.%d/%d", 10+r.Intn(3), r.Intn(4), r.Intn(256), r.Intn(256), 8+r.Intn(25))
			} else {
				cidr = fmt.Sprintf("2001:db8:%x:%x::/%d", r.Intn(4), r.Intn(65536), 30+r.Intn(70))
			}
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			elems, nets = append(elems, cidr), append(nets, n)
		}
		a := parseAllowSet(elems)
		for i := 0; i < 2000; i++ {
			var ip net.IP
			if r.Intn(2) == 0 {
				ip = net.IPv4(byte(10+r.Intn(3)), byte(r.Intn(4)), byte(r.Intn(256)), byte(r.Intn(256)))
			} else {
				ip = net.ParseIP(fmt.Sprintf("2001:db8:%x:%x:%x::%x", r.Intn(4), r.Intn(65536), r.Intn(65536), r.Intn(65536)))
			}
			want := false
			for _, n := range nets {
				if n.Contains(ip) {
					want = true
					break
				}
			}
			if got := a.contains(ip); got != want {
				t.Fatalf("round %d: %s: %v, IPNet %v (%v)", round, ip, got, want, elems)
			}
		}
	}
}
