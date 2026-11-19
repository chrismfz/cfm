package ssh

import (
	"cfm/internal/firewall"
	"net/netip"
	"testing"
	"time"

	"cfm/internal/detectors/core"
)

// An IPv6 client counts as its /64: addresses rotating inside it fill one
// window; the alert names its busiest address (the sink's input, core.TopAddr)
// and its /64. Another /64 counts on its own, IPv4 is unchanged.
func TestIPv6ClientCountsAsItsSlash64(t *testing.T) {
	a := NewAuth(AuthConfig{Window: time.Minute, Cooldown: time.Minute, DDOSPerIP: 3})
	a.pending = map[string]pend{}
	now := time.Now()
	a.bump(now, "DDOS|ip", "2001:db8:1:2::c", "l1")
	a.bump(now, "DDOS|ip", "2001:db8:1:2::b", "l2")
	a.bump(now, "DDOS|ip", "2001:db8:1:3::a", "l3")
	a.bump(now, "DDOS|ip", "203.0.113.7", "l4")
	a.bump(now, "DDOS|ip", "203.0.113.8", "l5")
	a.bump(now, "DDOS|ip", "2001:db8:1:2::c", "l6")
	out := make(chan core.Alert, 8)
	a.flush(now, out)
	close(out)
	var got []core.Alert
	for al := range out {
		got = append(got, al)
	}
	if len(got) != 1 {
		t.Fatalf("want one alert (the /64's third address), got %+v", got)
	}
	if g := got[0]; g.Extra["ip"] != "2001:db8:1:2::c" || g.Extra["client"] != "2001:db8:1:2::/64" || g.Count != 3 || len(g.Samples) != 3 {
		t.Fatalf("alert: %+v", g)
	}
}

// A guarded /64 counts per address: the attacker's own failures reach the
// threshold under its own address, never a neighbour's.
func TestGuardedSlash64CountsPerAddress(t *testing.T) {
	firewall.SetClientNetExempt("ssh-test", func(p netip.Prefix) bool { return p.String() == "2001:db8:1:2::/64" })
	firewall.ResetCountKeyCache()
	t.Cleanup(func() { firewall.SetClientNetExempt("ssh-test", nil); firewall.ResetCountKeyCache() })
	a := NewAuth(AuthConfig{Window: time.Minute, Cooldown: time.Minute, DDOSPerIP: 3})
	a.pending = map[string]pend{}
	now := time.Now()
	a.bump(now, "DDOS|ip", "2001:db8:1:2::bad", "l1")
	a.bump(now, "DDOS|ip", "2001:db8:1:2::bad", "l2")
	a.bump(now, "DDOS|ip", "2001:db8:1:2::1", "l3")
	a.bump(now, "DDOS|ip", "2001:db8:1:2::bad", "l4")
	out := make(chan core.Alert, 8)
	a.flush(now, out)
	close(out)
	var got []core.Alert
	for al := range out {
		got = append(got, al)
	}
	if len(got) != 1 || got[0].Extra["ip"] != "2001:db8:1:2::bad" || got[0].Count != 3 {
		t.Fatalf("want one alert for the attacking address, got %+v", got)
	}
}

// The alert names the address that failed most, never the neighbour whose
// one failure came last (it goes to the fleet report and the leniency /
// exclude checks).
func TestSlash64AlertNamesTheBusiestAddress(t *testing.T) {
	a := NewAuth(AuthConfig{Window: time.Minute, Cooldown: time.Minute, AuthFailPerIP: 10})
	a.pending = map[string]pend{}
	now := time.Now()
	for i := 0; i < 9; i++ {
		a.bump(now, "AUTHFAIL|ip", "2001:db8:7:7::bad", "x")
	}
	a.bump(now, "AUTHFAIL|ip", "2001:db8:7:7::1", "y")
	out := make(chan core.Alert, 2)
	a.flush(now, out)
	close(out)
	al := <-out
	if al.Extra["ip"] != "2001:db8:7:7::bad" || al.Count != 10 {
		t.Fatalf("alert names %q (count %d), want the busiest 2001:db8:7:7::bad", al.Extra["ip"], al.Count)
	}
}
