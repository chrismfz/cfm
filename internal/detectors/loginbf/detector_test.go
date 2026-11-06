package loginbf

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/edgeban"
	"cfm/internal/enrich"
)

var t0 = time.Unix(1_793_900_000, 0)

func newTest(cfg Config) *Detector {
	if cfg.SiteFails == 0 && cfg.Sites == 0 {
		cfg.SiteFails, cfg.Sites = 5, 5
	}
	d := New(cfg)
	// Far ahead: every failure is past Grace when a test runs.
	d.now = func() time.Time { return t0.Add(24 * time.Hour) }
	d.setGeo(fakeGeo{})
	return d
}

// fakeGeo: every address is in the US on AS64500, but 203.0.113.250 is on
// Sucuri's AS30148 and 203.0.113.251 has no record.
type fakeGeo struct{}

func (fakeGeo) LookupGeoFast(ip string) enrich.Result {
	switch ip {
	case "203.0.113.250":
		return enrich.Result{CountryISO: "US", ASN: 30148, ASNName: "Sucuri"}
	case "203.0.113.251":
		return enrich.Result{}
	}
	return enrich.Result{CountryISO: "US", ASN: 64500}
}

func run(t *testing.T, d *Detector) []core.Alert {
	t.Helper()
	out := make(chan core.Alert, 64)
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var got []core.Alert
	for a := range out {
		got = append(got, a)
	}
	return got
}

func failAt(ip, site string, at time.Time) Event {
	return Event{When: at, IP: ip, Host: "www." + site, Site: site, Tag: "WP_LOGIN"}
}

func TestSiteFailsRule(t *testing.T) {
	d := newTest(Config{})
	for i := 0; i < 4; i++ {
		d.Enqueue(failAt("203.0.113.1", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("4 failures on one site: %+v", got)
	}
	d.Enqueue(failAt("203.0.113.1", "a.gr", t0.Add(5*time.Minute)))
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["rule"] != "site" || got[0].Extra["site_fails"] != "5" || got[0].Kind != Kind {
		t.Fatalf("5th failure on one site: %+v", got)
	}
	if got[0].Key != "203.0.113.1" || got[0].Extra["ip"] != "203.0.113.1" {
		t.Fatalf("ban key: %+v", got[0])
	}
}

func TestSitesRule(t *testing.T) {
	d := newTest(Config{})
	for i := 0; i < 4; i++ {
		d.Enqueue(failAt("203.0.113.2", "s"+strconv.Itoa(i)+".gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("one failure on 4 sites: %+v", got)
	}
	d.Enqueue(failAt("203.0.113.2", "s4.gr", t0.Add(30*time.Minute)))
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["rule"] != "sites" || got[0].Extra["sites_failed"] != "5" {
		t.Fatalf("one failure on 5 sites: %+v", got)
	}
}

func TestWindow(t *testing.T) {
	// 5 failures on one site spread over more than the window: never 5 in it.
	d := newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.3", "a.gr", t0.Add(time.Duration(i)*16*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("5 failures over 64 min: %+v", got)
	}
	// 5 sites over more than an hour: never 5 in it either.
	d = newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.4", "s"+strconv.Itoa(i)+".gr", t0.Add(time.Duration(i)*16*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("5 sites over 64 min: %+v", got)
	}
}

func TestOwnerAndAllowNeverCount(t *testing.T) {
	d := newTest(Config{AllowIPs: []string{"198.51.100.9"}, AllowNets: []string{"192.0.2.0/24"}})
	for i := 0; i < 10; i++ {
		ev := failAt("203.0.113.5", "a.gr", t0.Add(time.Duration(i)*time.Minute))
		ev.Owner = true
		d.Enqueue(ev)
		d.Enqueue(failAt("198.51.100.9", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
		d.Enqueue(failAt("192.0.2.77", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("owner / allowed clients: %+v", got)
	}
}

func TestOneAlertThenOnlyNewFailures(t *testing.T) {
	// A lenient client (a 10 minute ban) that keeps failing is banned again,
	// but only after another full set of failures, not on every one.
	d := newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.6", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("first alert: %d", len(got))
	}
	for i := 0; i < 4; i++ {
		d.Enqueue(failAt("203.0.113.6", "a.gr", t0.Add(time.Duration(20+i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("4 failures after the alert: %+v", got)
	}
	d.Enqueue(failAt("203.0.113.6", "a.gr", t0.Add(30*time.Minute)))
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("5 new failures after the alert: %d", len(got))
	}
}

func TestRulesOffAndDryRun(t *testing.T) {
	d := newTest(Config{SiteFails: 0, Sites: 3, DryRun: true})
	for i := 0; i < 20; i++ {
		d.Enqueue(failAt("203.0.113.7", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("SITE_FAILS = 0 must not fire: %+v", got)
	}
	d.Enqueue(failAt("203.0.113.7", "b.gr", t0.Add(25*time.Minute)))
	d.Enqueue(failAt("203.0.113.7", "c.gr", t0.Add(26*time.Minute)))
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["enforcement"] != "dryrun" {
		t.Fatalf("dry run on SITES = 3: %+v", got)
	}
}

func TestPruneAndBound(t *testing.T) {
	d := newTest(Config{MaxClients: 20})
	for i := 0; i < 50; i++ {
		d.Enqueue(failAt("203.0.113."+strconv.Itoa(i), "a.gr", t0.Add(time.Duration(i)*time.Second)))
	}
	run(t, d)
	if n := len(d.clients); n > 20 {
		t.Fatalf("clients past the bound: %d", n)
	}
	// A failure two hours on: every other client's last failure left the
	// window (the clock is the newest failure, not the wall).
	d.Enqueue(failAt("203.0.113.200", "a.gr", t0.Add(2*time.Hour)))
	run(t, d)
	if n := len(d.clients); n != 1 {
		t.Fatalf("stale clients kept: %d", n)
	}
}

func TestNeverBanned(t *testing.T) {
	d := newTest(Config{AllowASNs: []string{"AS30148"}})
	for i := 0; i < 6; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		for _, ip := range []string{"203.0.113.250", "10.0.0.5", "192.168.1.9", "100.64.3.3", "127.0.0.1", "fe80::1", "::1"} {
			d.Enqueue(failAt(ip, "a.gr", at))
		}
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("a proxy ASN / non-public address was alerted: %+v", got)
	}
}

func TestNoGeoIsADryRun(t *testing.T) {
	d := newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.251", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["enforcement"] != "dryrun" || got[0].Extra["geo"] != "unknown" {
		t.Fatalf("no geo record must not ban: %+v", got)
	}
	// And with no database at all.
	d = New(Config{SiteFails: 5, Sites: 5})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.30", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 1 || got[0].Extra["enforcement"] != "dryrun" {
		t.Fatalf("no enricher must not ban: %+v", got)
	}
	// A record with a country bans.
	d = newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.31", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 1 || got[0].Extra["enforcement"] != "" {
		t.Fatalf("a geo record must ban: %+v", got)
	}
}

func TestIPv6CountsPer64AndBansTheAddress(t *testing.T) {
	d := newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("2001:db8:1:2::"+strconv.Itoa(i+1), "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["ip"] != "2001:db8:1:2::5" || got[0].Extra["client"] != "2001:db8:1:2::/64" {
		t.Fatalf("rotation inside one /64: %+v", got)
	}
}

func TestAddressesAreNormalised(t *testing.T) {
	d := newTest(Config{AllowIPs: []string{"2001:DB8::1"}})
	for i := 0; i < 6; i++ {
		d.Enqueue(failAt("2001:db8::1", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("ALLOW_IPS in another spelling: %+v", got)
	}
	// A mapped address is the IPv4 one, in one count.
	d = newTest(Config{})
	for i := 0; i < 5; i++ {
		ip := "203.0.113.40"
		if i%2 == 1 {
			ip = "::ffff:203.0.113.40"
		}
		d.Enqueue(failAt(ip, "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 1 || got[0].Extra["ip"] != "203.0.113.40" {
		t.Fatalf("mapped and plain forms: %+v", got)
	}
}

func TestOutOfOrderLines(t *testing.T) {
	// 4 failures now and one stamped 67 minutes earlier, arriving last: not
	// 5 within an hour.
	d := newTest(Config{})
	for i := 0; i < 4; i++ {
		d.Enqueue(failAt("203.0.113.50", "a.gr", t0.Add(time.Duration(70+i)*time.Minute)))
	}
	d.Enqueue(failAt("203.0.113.50", "a.gr", t0.Add(3*time.Minute)))
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("a late line outside the window counted: %+v", got)
	}
	// A late line inside the window counts.
	d.Enqueue(failAt("203.0.113.50", "a.gr", t0.Add(60*time.Minute)))
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("a late line inside the window: %d", len(got))
	}
}

func TestBacklogIsPrunedOnItsOwnClock(t *testing.T) {
	// A backlog two hours old, read in two batches: the wall clock must not
	// drop the first batch's failures before the second.
	d := newTest(Config{})
	d.now = func() time.Time { return t0.Add(3 * time.Hour) }
	for i := 0; i < 3; i++ {
		d.Enqueue(failAt("203.0.113.60", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	run(t, d)
	for i := 3; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.60", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("backlog across two runs: %d", len(got))
	}
}

func TestIPv6BansTheWorstAddressOfThe64(t *testing.T) {
	// ::1 sprays 4 times, a colleague at ::2 mistypes once: the ban is ::1's.
	d := newTest(Config{})
	for i := 0; i < 4; i++ {
		d.Enqueue(failAt("2001:db8:7:7::1", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	d.Enqueue(failAt("2001:db8:7:7::2", "a.gr", t0.Add(5*time.Minute)))
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["ip"] != "2001:db8:7:7::1" || got[0].Key != "2001:db8:7:7::1" {
		t.Fatalf("the colleague took the ban: %+v", got)
	}
}

func TestTrustedProxyAddressesAreNeverBanned(t *testing.T) {
	_, n, _ := net.ParseCIDR("104.16.0.0/13")
	edgeban.SetTrustedProxies([]*net.IPNet{n})
	defer edgeban.SetTrustedProxies(nil)
	d := newTest(Config{})
	for i := 0; i < 6; i++ {
		d.Enqueue(failAt("104.16.1.1", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("a Cloudflare proxy address was alerted: %+v", got)
	}
}

func TestAllowASNsAcceptsSpaces(t *testing.T) {
	d := New(Config{AllowASNs: []string{"AS13335  30148;54113\t20940"}})
	for _, n := range []uint{13335, 30148, 54113, 20940} {
		if _, ok := d.allowASNs[n]; !ok {
			t.Fatalf("AS%d not parsed: %v", n, d.allowASNs)
		}
	}
}

func okAt(ip, site string, at time.Time) Event {
	ev := failAt(ip, site, at)
	ev.OK = true
	return ev
}

func TestSuccessTakesBackTheFailureBeforeIt(t *testing.T) {
	// Two Factor 0.8+: the password step reads as a failure, the 2FA step
	// is the success. An agency logging into 5 client sites in an hour,
	// and one admin logging in 6 times on one site, are not brute force.
	d := newTest(Config{})
	for i := 0; i < 6; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		d.Enqueue(failAt("203.0.113.70", "s"+strconv.Itoa(i)+".gr", at))
		d.Enqueue(okAt("203.0.113.70", "s"+strconv.Itoa(i)+".gr", at.Add(20*time.Second)))
		d.Enqueue(failAt("203.0.113.71", "a.gr", at))
		d.Enqueue(okAt("203.0.113.71", "a.gr", at.Add(20*time.Second)))
	}
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("2FA logins banned: %+v", got)
	}
	// One success takes back one failure only, on its own site, from its
	// own address, and not one older than RetractWindow.
	d = newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.72", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	d.Enqueue(okAt("203.0.113.72", "b.gr", t0.Add(5*time.Minute)))
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("a success elsewhere took back a failure: %d", len(got))
	}
	d = newTest(Config{})
	for i := 0; i < 4; i++ {
		d.Enqueue(failAt("203.0.113.73", "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	d.Enqueue(okAt("203.0.113.73", "a.gr", t0.Add(20*time.Minute)))
	d.Enqueue(failAt("203.0.113.73", "a.gr", t0.Add(21*time.Minute)))
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("a success past RetractWindow took back a failure: %d", len(got))
	}
}

func TestGraceLetsTheSuccessArriveFirst(t *testing.T) {
	// An agency opens 5 Two Factor sites in parallel tabs: the 5 password
	// steps (failures) inside 30 s, the codes a minute later. Runs follow
	// the real clock.
	d := newTest(Config{})
	now := t0
	d.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.80", "s"+strconv.Itoa(i)+".gr", t0.Add(time.Duration(i)*5*time.Second)))
	}
	now = t0.Add(30 * time.Second)
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("banned inside Grace: %+v", got)
	}
	for i := 0; i < 5; i++ {
		d.Enqueue(okAt("203.0.113.80", "s"+strconv.Itoa(i)+".gr", t0.Add(70*time.Second+time.Duration(i)*5*time.Second)))
	}
	now = t0.Add(10 * time.Minute)
	if got := run(t, d); len(got) != 0 {
		t.Fatalf("parallel 2FA logins banned: %+v", got)
	}

	// One admin who mistypes the code each time: password step, wrong code,
	// right code. One success takes back both failures.
	d = newTest(Config{})
	now = t0
	d.now = func() time.Time { return now }
	for i := 0; i < 6; i++ {
		at := t0.Add(time.Duration(i) * 5 * time.Minute)
		d.Enqueue(failAt("203.0.113.81", "a.gr", at))
		d.Enqueue(failAt("203.0.113.81", "a.gr", at.Add(20*time.Second)))
		d.Enqueue(okAt("203.0.113.81", "a.gr", at.Add(40*time.Second)))
		now = at.Add(time.Minute)
		if got := run(t, d); len(got) != 0 {
			t.Fatalf("round %d: a 2FA user with a mistyped code banned: %+v", i, got)
		}
	}

	// A brute forcer is still banned, Grace later.
	d = newTest(Config{})
	now = t0
	d.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("203.0.113.82", "a.gr", t0.Add(time.Duration(i)*time.Second)))
	}
	now = t0.Add(10 * time.Second)
	if got := run(t, d); len(got) != 0 {
		t.Fatal("decided inside Grace")
	}
	now = t0.Add(Grace + 10*time.Second)
	if got := run(t, d); len(got) != 1 {
		t.Fatalf("brute force after Grace: %d", len(got))
	}
}

func TestAmbiguousIPv6IsADryRun(t *testing.T) {
	// A shared /64 (a VPS provider's): five addresses with one failure
	// each, nobody to blame.
	d := newTest(Config{})
	for i := 0; i < 5; i++ {
		d.Enqueue(failAt("2001:db8:9:9::"+strconv.Itoa(i+1), "a.gr", t0.Add(time.Duration(i)*time.Minute)))
	}
	got := run(t, d)
	if len(got) != 1 || got[0].Extra["enforcement"] != "dryrun" || got[0].Extra["ipv6_ambiguous"] != "1" {
		t.Fatalf("an ambiguous /64 must not ban: %+v", got)
	}
}
