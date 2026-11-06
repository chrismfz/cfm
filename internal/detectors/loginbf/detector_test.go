package loginbf

import (
	"context"
	"strconv"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

var t0 = time.Unix(1_793_900_000, 0)

func newTest(cfg Config) *Detector {
	if cfg.SiteFails == 0 && cfg.Sites == 0 {
		cfg.SiteFails, cfg.Sites = 5, 5
	}
	d := New(cfg)
	d.now = func() time.Time { return t0.Add(10 * time.Minute) }
	return d
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
	// Two hours on: every client's last failure left the window.
	d.now = func() time.Time { return t0.Add(2 * time.Hour) }
	d.Enqueue(failAt("203.0.113.200", "a.gr", t0))
	run(t, d)
	if n := len(d.clients); n != 0 {
		t.Fatalf("stale clients kept: %d", n)
	}
}
