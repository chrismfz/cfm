package exim

import (
	"testing"
	"time"
)

// A per-IP tag counts an IPv6 client on its /64; a user key never groups,
// even a username spelled like an IPv6 address.
func TestSecurityWindowKeys(t *testing.T) {
	d := NewSecurity(SecConfig{})
	now := time.Now()
	d.bump(now, "AUTHFAIL|ip", "2001:db8:1:2::1", "l1")
	d.bump(now, "AUTHFAIL|ip", "2001:db8:1:2::2", "l2")
	d.bump(now, "AUTHFAIL|ip", "2001:db8:1:2::2", "l2b")
	d.bump(now, "RBL_HIT", "2001:db8:1:2::3", "l3")
	d.bump(now, "AUTHFAIL|user", "2001:db8:1:2::1", "l4")
	d.bump(now, "AUTHFAIL|user", "2001:db8:1:2::2", "l5")
	if n := d.counts.Count("AUTHFAIL|ip:2001:db8:1:2::/64", now); n != 3 {
		t.Fatalf("per-IP tag: %d in the /64's window, want 3", n)
	}
	if n := d.counts.Count("RBL_HIT:2001:db8:1:2::/64", now); n != 1 {
		t.Fatalf("an address-keyed rule tag: %d, want 1 in the /64's window", n)
	}
	if n := d.counts.Count("AUTHFAIL|user:2001:db8:1:2::1", now); n != 1 {
		t.Fatalf("a user key grouped: %d, want 1", n)
	}
	if p := d.pending["AUTHFAIL|ip:2001:db8:1:2::/64"]; p.key != "2001:db8:1:2::2" {
		t.Fatalf("pending keeps %q, want the busiest address", p.key)
	}
}
