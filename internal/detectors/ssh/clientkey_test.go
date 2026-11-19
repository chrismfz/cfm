package ssh

import (
	"testing"
	"time"

	"cfm/internal/detectors/core"
)

// An IPv6 client counts as its /64: addresses rotating inside it fill one
// window; the alert names the address seen last (the sink's input) and its
// /64. Another /64 counts on its own, IPv4 is unchanged.
func TestIPv6ClientCountsAsItsSlash64(t *testing.T) {
	a := NewAuth(AuthConfig{Window: time.Minute, Cooldown: time.Minute, DDOSPerIP: 3})
	a.pending = map[string]pend{}
	now := time.Now()
	a.bump(now, "DDOS|ip", "2001:db8:1:2::a", "l1")
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
