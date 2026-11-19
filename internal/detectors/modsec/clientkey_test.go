package modsec

import (
	"testing"
	"time"
)

// ModSecurity 403s of an IPv6 client count on its /64; the pending entry
// keeps the busiest address, its meta stays per address.
func TestModsecCountsAnIPv6ClientsSlash64(t *testing.T) {
	d := New(Config{})
	now := time.Now()
	d.bump(now, "2001:db8:1:2::1", "l1")
	d.bump(now, "2001:db8:1:2::2", "l2")
	d.bump(now, "2001:db8:1:2::2", "l2b")
	d.bump(now, "203.0.113.7", "l3")
	if n := d.counts.Count("ip:2001:db8:1:2::/64", now); n != 3 {
		t.Fatalf("the /64's window: %d, want 3", n)
	}
	if p := d.pending["2001:db8:1:2::/64"]; p.key != "2001:db8:1:2::2" {
		t.Fatalf("pending keeps %q", p.key)
	}
	if n := d.counts.Count("ip:203.0.113.7", now); n != 1 {
		t.Fatalf("IPv4: %d", n)
	}
}
