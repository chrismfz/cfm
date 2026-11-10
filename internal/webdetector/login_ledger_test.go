package webdetector

import (
	"strconv"
	"strings"
	"testing"
)

type rowSink struct{ rows []HistoryEvent }

func (r *rowSink) emit(ev HistoryEvent) { r.rows = append(r.rows, ev) }

func (r *rowSink) of(typ string) []HistoryEvent {
	var out []HistoryEvent
	for _, ev := range r.rows {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

func loginRec(ip string, ts int64) LogRec { return LogRec{IP: ip, TS: float64(ts)} }

const t0 = int64(1_790_000_000)

func TestLoginLedgerSlowCrossSiteSprayer(t *testing.T) {
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	// The vol2.gr shape: a few tries per site, minutes apart, many sites.
	for i := 0; i < 9; i++ {
		l.observe(loginRec("217.60.196.2", t0+int64(i)*600), "site"+strconv.Itoa(i%4)+".gr", "WP_LOGIN", "fail")
	}
	if n := len(sink.of("login_spray")); n != 0 {
		t.Fatalf("9 failures: %d rows", n)
	}
	l.observe(loginRec("217.60.196.2", t0+5400), "site0.gr", "WP_LOGIN", "fail")
	rows := sink.of("login_spray")
	if len(rows) != 1 {
		t.Fatalf("10 failures on 4 sites: %d rows", len(rows))
	}
	r := rows[0]
	if r.IP != "217.60.196.2" || r.Host != "" || r.Mode != "shadow" || r.Payload["sites"] != 4 || r.Payload["fails_24h"] != uint32(10) {
		t.Fatalf("row: %+v", r)
	}
	// Tenant privacy: no site name anywhere in a spray row.
	if strings.Contains(r.Reason, ".gr") {
		t.Fatalf("spray row names a site: %q", r.Reason)
	}
	for k, v := range r.Payload {
		if s, ok := v.(string); ok && strings.Contains(s, ".gr") {
			t.Fatalf("payload %s names a site: %q", k, s)
		}
	}
	// Throttled: one row per IP per 6 h.
	for i := 0; i < 20; i++ {
		l.observe(loginRec("217.60.196.2", t0+6000+int64(i)), "site9.gr", "WP_LOGIN", "fail")
	}
	if n := len(sink.of("login_spray")); n != 1 {
		t.Fatalf("throttle: %d rows", n)
	}
	l.observe(loginRec("217.60.196.2", t0+5400+6*3600), "site9.gr", "WP_LOGIN", "fail")
	if n := len(sink.of("login_spray")); n != 2 {
		t.Fatalf("after 6 h: %d rows", n)
	}
}

func TestLoginLedgerThresholds(t *testing.T) {
	cases := []struct {
		name   string
		fails  int
		sites  int
		gap    int64 // seconds between tries
		rowsIP int
	}{
		{"an owner who mistyped, one site", 5, 1, 60, 0},
		{"two sites, 15 tries spread out", 15, 2, 1800, 0},
		{"a fast single-site burst", 20, 1, 30, 1},
		{"a heavy single-site day", 50, 1, 1500, 1},
		{"three sites, 10 tries", 10, 3, 900, 1},
	}
	for _, c := range cases {
		sink := &rowSink{}
		l := newLoginLedger(sink.emit)
		for i := 0; i < c.fails; i++ {
			l.observe(loginRec("198.51.100.7", t0+int64(i)*c.gap), "s"+strconv.Itoa(i%c.sites)+".gr", "WP_LOGIN", "fail")
		}
		if n := len(sink.of("login_spray")); n != c.rowsIP {
			t.Errorf("%s: %d login_spray rows, want %d", c.name, n, c.rowsIP)
		}
	}
}

func TestLoginLedgerOnlyFailAndOKCount(t *testing.T) {
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < 100; i++ {
		l.observe(loginRec("198.51.100.8", t0+int64(i)), "a.gr", "WP_LOGIN", "?")
		l.observe(loginRec("198.51.100.8", t0+int64(i)), "a.gr", "WP_LOGIN", "na")
	}
	if len(sink.rows) != 0 || len(l.ips) != 0 {
		t.Fatalf("? and na counted: %d rows, %d ips", len(sink.rows), len(l.ips))
	}
}

func TestLoginLedgerNetPools(t *testing.T) {
	// A proxy pool: many IPs of one /24, a few tries each, never one IP over
	// the L1 thresholds.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < 30; i++ {
		ip := "104.234.53." + strconv.Itoa(10+i%6)
		l.observe(loginRec(ip, t0+int64(i)*400), "s"+strconv.Itoa(i%2)+".gr", "WP_LOGIN", "fail")
	}
	if n := len(sink.of("login_spray")); n != 0 {
		t.Fatalf("no single IP should be flagged: %d", n)
	}
	nets := sink.of("login_spray_net")
	if len(nets) != 1 || nets[0].Payload["net"] != "104.234.53.0/24" || nets[0].Payload["clients"] != 6 || nets[0].IP != "" || nets[0].Host != "" {
		t.Fatalf("pool row: %+v", nets)
	}

	// Five flagged IPs of one /24 make a net row as well.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	for n := 0; n < 5; n++ {
		for i := 0; i < 20; i++ {
			l.observe(loginRec("155.2.215."+strconv.Itoa(80+n), t0+int64(n*100+i)), "x.gr", "WP_LOGIN", "fail")
		}
	}
	if n := sink.of("login_spray_net"); len(n) == 1 && !strings.Contains(n[0].Reason, "from 5 clients") {
		t.Fatalf("net reason: %q", n[0].Reason)
	}
	if len(sink.of("login_spray")) != 5 || len(sink.of("login_spray_net")) != 1 {
		t.Fatalf("flagged IPs: %d spray, %d net", len(sink.of("login_spray")), len(sink.of("login_spray_net")))
	}

	// IPv6: addresses of one /64 are one client.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	for i := 0; i < 30; i++ {
		l.observe(loginRec("2001:db8:1:2::"+strconv.FormatInt(int64(i+1), 16), t0+int64(i)*60), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	if sp := sink.of("login_spray"); len(sp) != 1 || sp[0].Payload["client"] != "2001:db8:1:2::/64" {
		t.Fatalf("v6 /64 as one client: %+v", sp)
	}

	// The adversarial review's evasion: one /48, one try per /64, many
	// sites. Now one network, flagged by its failure count.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	for i := 0; i < 2000; i++ {
		ip := "2001:db8:abcd:" + strconv.FormatInt(int64(i+1), 16) + "::1"
		l.observe(loginRec(ip, t0+int64(i)), "s"+strconv.Itoa(i%50)+".gr", "WP_LOGIN", "fail")
	}
	if nets := sink.of("login_spray_net"); len(nets) != 1 || nets[0].Payload["net"] != "2001:db8:abcd::/48" {
		t.Fatalf("v6 /48 spread: %+v", nets)
	}
}

func TestLoginLedgerDirtySuccess(t *testing.T) {
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	// A clean success: nothing.
	l.observe(loginRec("203.0.113.1", t0), "shop.gr", "WP_LOGIN", "ok")
	if len(sink.rows) != 0 {
		t.Fatalf("clean success: %+v", sink.rows)
	}
	// An owner after a few typos: nothing.
	for i := 0; i < 3; i++ {
		l.observe(loginRec("203.0.113.2", t0+int64(i)), "shop.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("203.0.113.2", t0+10), "shop.gr", "WP_LOGIN", "ok")
	if len(sink.of("login_dirty_success")) != 0 {
		t.Fatalf("owner after typos: %+v", sink.rows)
	}

	// A sprayer that gets in.
	for i := 0; i < 12; i++ {
		l.observe(loginRec("217.60.196.2", t0+int64(i)*600), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("217.60.196.2", t0+8000), "victim.gr", "WP_LOGIN", "ok")
	d := sink.of("login_dirty_success")
	if len(d) != 1 || d[0].Host != "victim.gr" || d[0].IP != "217.60.196.2" || d[0].Payload["flagged_by"] != "ip" || d[0].Payload["sites_failed_24h"] != 3 {
		t.Fatalf("sprayer success: %+v", d)
	}
	// Throttled per (ip, host) per hour.
	l.observe(loginRec("217.60.196.2", t0+8100), "victim.gr", "WP_LOGIN", "ok")
	if len(sink.of("login_dirty_success")) != 1 {
		t.Fatal("throttle")
	}

	// Brute force on one site, then in: own_fails.
	for i := 0; i < 12; i++ {
		l.observe(loginRec("192.0.2.9", t0+int64(i)*400), "one.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("192.0.2.9", t0+6000), "one.gr", "WP_LOGIN", "ok")
	if d = sink.of("login_dirty_success"); len(d) != 2 || d[1].Payload["flagged_by"] != "own_fails" {
		t.Fatalf("own fails: %+v", d)
	}

	// A never-seen IP of a flagged net (no IP state of its own): net, no panic.
	for i := 0; i < 30; i++ {
		l.observe(loginRec("104.234.53."+strconv.Itoa(10+i%6), t0+int64(i)*400), "s.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("104.234.53.200", t0+13000), "shop2.gr", "WP_LOGIN", "ok")
	if d = sink.of("login_dirty_success"); len(d) != 3 || d[2].Payload["flagged_by"] != "net" {
		t.Fatalf("net-flagged newcomer: %+v", d)
	}
}

func TestLoginLedgerKillSwitch(t *testing.T) {
	ConfigureLoginSignals(false)
	defer ConfigureLoginSignals(true)
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < 60; i++ {
		l.observe(loginRec("198.51.100.9", t0+int64(i)), "a.gr", "WP_LOGIN", "fail")
	}
	if len(sink.rows) != 0 || len(l.ips) != 0 {
		t.Fatal("LOGIN_SIGNALS=0 still counted")
	}
}

func TestLoginLedgerHourEstimateSlides(t *testing.T) {
	var w loginWin
	h := t0 - t0%3600
	for i := 0; i < 10; i++ {
		w.add(h + 3000 + int64(i))
	}
	w.roll(h + 3600 + 1800) // half way through the next hour
	if got := w.hourEst(h + 3600 + 1800); got < 4.9 || got > 5.1 {
		t.Fatalf("half the previous hour: %.2f", got)
	}
	w.roll(h + 3*3600)
	if got := w.hourEst(h + 3*3600); got != 0 {
		t.Fatalf("two hours later: %.2f", got)
	}
}

func TestLoginLedgerBounded(t *testing.T) {
	type ent struct {
		last    int64
		flagged bool
	}
	st := func(v ent) (int64, bool) { return v.last, v.flagged }
	m := map[string]ent{}
	for i := 0; i < 3000; i++ {
		m["k"+strconv.Itoa(i)] = ent{last: t0, flagged: i < 2500}
	}
	evictLogin(m, t0+10, st)
	if len(m) != 3000-loginEvictBatch {
		t.Fatalf("batch eviction: %d left", len(m))
	}
	flagged := 0
	for _, v := range m {
		if v.flagged {
			flagged++
		}
	}
	if flagged != 2000 {
		t.Fatalf("unflagged first: 500 unflagged go, then 500 flagged; %d flagged left", flagged)
	}
	evictLogin(m, t0+86400, st)
	if len(m) != 0 {
		t.Fatalf("idle-for-a-day eviction: %d left", len(m))
	}
	// Per-client sites and per-net client sets are capped.
	l := newLoginLedger(nil)
	for i := 0; i < 100; i++ {
		l.observe(loginRec("198.51.100.10", t0+int64(i)), "h"+strconv.Itoa(i)+".gr", "WP_LOGIN", "fail")
		l.observe(loginRec("10.9.8."+strconv.Itoa(i), t0+int64(i)), "x.gr", "WP_LOGIN", "fail")
	}
	if c := l.ips["198.51.100.10"]; c.nsites != loginMaxSites || !c.full {
		t.Fatalf("sites cap: %d full=%v", c.nsites, c.full)
	}
	if siteCount(8, true) != "8+" || siteCount(3, false) != "3" {
		t.Fatal("siteCount")
	}
	// A capped network reads 16+ in its row.
	sink := &rowSink{}
	l2 := newLoginLedger(sink.emit)
	for i := 0; i < 40; i++ {
		l2.observe(loginRec("10.7.7."+strconv.Itoa(i+1), t0+int64(i)), "x.gr", "WP_LOGIN", "fail")
	}
	if n := sink.of("login_spray_net"); len(n) != 1 || !strings.Contains(n[0].Reason, "from 16+ clients") {
		t.Fatalf("capped net reason: %+v", n)
	}
	if n := l.nets["10.9.8.0/24"].nips; n != loginMaxNetIPs {
		t.Fatalf("net clients cap: %d", n)
	}
}

// The adversarial review's flood: a flagged sprayer must survive a flood of
// new addresses filling the map, so its later success is still caught.
func TestLoginLedgerFloodKeepsFlagged(t *testing.T) {
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	l.maxIPs, l.maxNets = 3000, 3000
	for i := 0; i < 12; i++ {
		l.observe(loginRec("217.60.196.2", t0+int64(i)*60), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	for i := 0; i < 20000; i++ {
		l.observe(loginRec("10."+strconv.Itoa(i>>16&255)+"."+strconv.Itoa(i>>8&255)+"."+strconv.Itoa(i&255), t0+1000+int64(i%100)), "x.gr", "WP_LOGIN", "fail")
	}
	if len(l.ips) > 3000 || len(l.nets) > 3000 {
		t.Fatalf("caps: %d ips %d nets", len(l.ips), len(l.nets))
	}
	l.observe(loginRec("217.60.196.2", t0+2000), "victim.gr", "WP_LOGIN", "ok")
	if d := sink.of("login_dirty_success"); len(d) != 1 || d[0].Payload["flagged_by"] != "ip" {
		t.Fatalf("flagged sprayer evicted by the flood: %+v", d)
	}
}

func TestLoginLedgerOutOfOrderAndSkew(t *testing.T) {
	// 19 tries of a burst, then a batched line from two hours earlier, then
	// the 20th: still a burst.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	h := t0 - t0%3600 + 3600
	for i := 0; i < 19; i++ {
		l.observe(loginRec("198.51.100.20", h+int64(i)), "one.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("198.51.100.20", h-7200), "one.gr", "WP_LOGIN", "fail")
	if len(sink.of("login_spray")) != 1 {
		t.Fatalf("an old line wiped the hour: %d rows, hour=%d", len(sink.of("login_spray")), l.ips["198.51.100.20"].win.hour)
	}
	// A line stamped a day ahead (edge clock skew) is counted at wall time
	// and does not move the day window ahead.
	l = newLoginLedger(nil)
	l.wall = func() int64 { return t0 }
	l.observe(loginRec("198.51.100.21", t0+86400), "one.gr", "WP_LOGIN", "fail")
	if ds := l.ips["198.51.100.21"].win.dayStart; ds != t0 {
		t.Fatalf("future line moved the window: dayStart=%d", ds)
	}
	var w loginWin
	w.add(h)
	w.add(h + 3600) // prevHour 1, hour 1
	if got := w.hourEst(h + 3600 - 10); got != 2 {
		t.Fatalf("hourEst before the window counts prevHour at most whole: %.4f", got)
	}
}

func TestLoginLedgerSitesAreRegistrableDomains(t *testing.T) {
	// The owner who mistyped on example.gr, www. and staging.: one site.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i, h := range []string{"example.gr", "www.example.gr", "staging.example.gr", "example.gr", "www.example.gr",
		"staging.example.gr", "example.gr", "www.example.gr", "staging.example.gr", "example.gr"} {
		l.observe(loginRec("198.51.100.30", t0+int64(i)*600), h, "WP_LOGIN", "fail")
	}
	if n := len(sink.of("login_spray")); n != 0 {
		t.Fatalf("one owner's hostnames counted as sites: %d rows", n)
	}
	if c := l.ips["198.51.100.30"]; c.nsites != 1 {
		t.Fatalf("sites: %d", c.nsites)
	}
	if loginSiteKey("shop.example.com.gr") != "example.com.gr" || loginSiteKey("a.b.gr") != "b.gr" {
		t.Fatalf("public-suffix aware: %q %q", loginSiteKey("shop.example.com.gr"), loginSiteKey("a.b.gr"))
	}
}

func TestLoginLedgerBoundaries(t *testing.T) {
	type tc struct {
		name  string
		n     int
		sites int
		gap   int64
		want  int
	}
	for _, c := range []tc{
		{"19 in an hour", 19, 1, 60, 0}, {"20 in an hour", 20, 1, 60, 1},
		{"49 in a day", 49, 1, 1700, 0}, {"50 in a day", 50, 1, 1700, 1},
		{"9 on 3 sites", 9, 3, 1700, 0}, {"10 on 3 sites", 10, 3, 1700, 1},
		{"10 on 2 sites", 10, 2, 1700, 0},
	} {
		sink := &rowSink{}
		l := newLoginLedger(sink.emit)
		for i := 0; i < c.n; i++ {
			l.observe(loginRec("198.51.100.40", t0+int64(i)*c.gap), "s"+strconv.Itoa(i%c.sites)+".gr", "WP_LOGIN", "fail")
		}
		rows := sink.of("login_spray")
		if len(rows) != c.want {
			t.Errorf("%s: %d rows, want %d", c.name, len(rows), c.want)
		}
		if len(rows) == 1 && rows[0].Payload["single_site"] != (c.sites == 1) {
			t.Errorf("%s: single_site=%v", c.name, rows[0].Payload["single_site"])
		}
	}
	// 9 own failures, then a success: nothing; 10: own_fails.
	for _, n := range []int{9, 10} {
		sink := &rowSink{}
		l := newLoginLedger(sink.emit)
		for i := 0; i < n; i++ {
			l.observe(loginRec("198.51.100.41", t0+int64(i)*1700), "one.gr", "WP_LOGIN", "fail")
		}
		l.observe(loginRec("198.51.100.41", t0+int64(n)*1700), "one.gr", "WP_LOGIN", "ok")
		if got := len(sink.of("login_dirty_success")); got != n-9 {
			t.Errorf("%d own failures: %d dirty rows", n, got)
		}
	}
	// A single IP with 50 failures is not a pool: no net row.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < 50; i++ {
		l.observe(loginRec("198.51.100.42", t0+int64(i)), "one.gr", "WP_LOGIN", "fail")
	}
	if n := len(sink.of("login_spray_net")); n != 0 {
		t.Fatalf("one IP made a net row: %d", n)
	}
}

func TestLoginLedgerDayRolls(t *testing.T) {
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	// 9 failures on 3 sites, then a day later 1 more on a 4th: the day reset
	// clears the sites, so no spray.
	for i := 0; i < 9; i++ {
		l.observe(loginRec("198.51.100.50", t0+int64(i)*60), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("198.51.100.50", t0+86400+10), "s9.gr", "WP_LOGIN", "fail")
	if c := l.ips["198.51.100.50"]; c.nsites != 1 || c.win.day != 1 || len(sink.rows) != 0 {
		t.Fatalf("day roll: sites=%d day=%d rows=%d", c.nsites, c.win.day, len(sink.rows))
	}
	// 12 own failures, then a success more than a day after the window began:
	// the old failures no longer count.
	for i := 0; i < 12; i++ {
		l.observe(loginRec("198.51.100.51", t0+int64(i)*60), "one.gr", "WP_LOGIN", "fail")
	}
	l.ips["198.51.100.51"].flagged = 0 // only own_fails could match
	l.observe(loginRec("198.51.100.51", t0+86400+100), "one.gr", "WP_LOGIN", "ok")
	if n := len(sink.of("login_dirty_success")); n != 0 {
		t.Fatalf("stale own failures counted: %d", n)
	}
}

func TestLoginLedgerDirtyThrottleAndBudget(t *testing.T) {
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < 12; i++ {
		l.observe(loginRec("217.60.196.3", t0+int64(i)*60), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	// Alternating two victims for 17 minutes: one row each per hour.
	for i := 0; i < 1000; i++ {
		l.observe(loginRec("217.60.196.3", t0+1000+int64(i)), []string{"a.gr", "b.gr"}[i%2], "WP_LOGIN", "ok")
	}
	if n := len(sink.of("login_dirty_success")); n != 2 {
		t.Fatalf("alternating victims: %d rows", n)
	}
	// Round-robin over many sites: at most loginOKRows per client per hour.
	for i := 0; i < 50; i++ {
		l.observe(loginRec("217.60.196.3", t0+1000+int64(i)), "v"+strconv.Itoa(i)+".gr", "WP_LOGIN", "ok")
	}
	if n := len(sink.of("login_dirty_success")); n != loginOKRows {
		t.Fatalf("round-robin: %d rows", n)
	}

	// A row budget per type: a botnet flagging 5 000 clients at once writes a
	// burst of loginRowsBurst rows, then loginRowsPerMin a minute, and the
	// next row carries the count it held back.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	wall := t0
	l.wall = func() int64 { return wall }
	for n := 0; n < 5000; n++ {
		ip := "10." + strconv.Itoa(n>>8&255) + "." + strconv.Itoa(n&255) + ".1"
		for i := 0; i < 20; i++ {
			l.observe(loginRec(ip, t0), "x.gr", "WP_LOGIN", "fail")
		}
	}
	if n := len(sink.of("login_spray")); n != loginRowsBurst {
		t.Fatalf("burst: %d rows", n)
	}
	wall += 60
	l.observe(loginRec("10.200.0.1", t0+60), "x.gr", "WP_LOGIN", "fail")
	for i := 0; i < 19; i++ {
		l.observe(loginRec("10.200.0.1", t0+60), "x.gr", "WP_LOGIN", "fail")
	}
	rows := sink.of("login_spray")
	if len(rows) != loginRowsBurst+1 || rows[len(rows)-1].Payload["suppressed"] == nil {
		t.Fatalf("after a minute: %d rows, last %+v", len(rows), rows[len(rows)-1].Payload)
	}
}

func TestLoginLedgerWiredFromIngest(t *testing.T) {
	e := NewEngine(Config{})
	if e.loginLedger == nil {
		t.Fatal("NewEngine did not build the login ledger")
	}
	sink := &rowSink{}
	e.loginLedger.emit = sink.emit
	line := func(i int, bypass, auth string) string {
		return strings.Replace(authBase, "1000.5", strconv.FormatInt(t0+int64(i), 10), 1) + "\t" + bypass + "\t" + auth
	}
	feed := func(l string) {
		rec, ok := parseSocketTSV(l)
		if !ok {
			t.Fatal("parse")
		}
		e.ingest(rec, l)
	}
	// A bypass client (a crawler, a CDN) is not counted.
	for i := 0; i < 25; i++ {
		feed(line(i, "2", "WP_LOGIN;li=0;l=/wp-login.php;c=wordpress_test_cookie"))
	}
	if len(sink.rows) != 0 {
		t.Fatalf("a bypass client was counted: %+v", sink.rows)
	}
	for i := 0; i < 25; i++ {
		feed(line(i, "0", "WP_LOGIN;li=0;l=/wp-login.php;c=wordpress_test_cookie"))
	}
	if n := len(sink.of("login_spray")); n != 1 {
		t.Fatalf("ingest → ledger: %d rows (%+v)", n, sink.rows)
	}
	// And a success after it.
	feed(line(30, "0", "WP_LOGIN;li=1;l=/wp-admin/;c=wordpress_logged_in_x"))
	if n := len(sink.of("login_dirty_success")); n != 1 {
		t.Fatalf("ingest ok → ledger: %d rows", n)
	}
}

// The first fleet day's two L4 false positives (2026-11-05).
func TestLoginLedgerDirtySuccessOwnerPatterns(t *testing.T) {
	// mygreecetours.org (virgo): the owner's tool logs in every few seconds
	// and sometimes fails; its sporadic failures flag it (L1 single-site),
	// but it had already succeeded there more often than it failed.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	ts := t0
	for i := 0; i < 30; i++ {
		ts += 6
		l.observe(loginRec("94.66.129.119", ts), "mygreecetours.org", "WP_LOGIN", "ok")
	}
	for i := 0; i < 25; i++ {
		ts += 6
		l.observe(loginRec("94.66.129.119", ts), "mygreecetours.org", "WP_LOGIN", "fail")
	}
	if len(sink.of("login_spray")) != 1 {
		t.Fatalf("the tool's burst still reads as an L1 shape (single_site): %d", len(sink.of("login_spray")))
	}
	l.observe(loginRec("94.66.129.119", ts+6), "mygreecetours.org", "WP_LOGIN", "ok")
	if d := sink.of("login_dirty_success"); len(d) != 0 {
		t.Fatalf("owner tool (more successes than failures before) got a dirty row: %+v", d)
	}

	// 62.1.118.59 (rigel): typos on welder.gr, a password-reset REQUEST,
	// then in. Anyone can request a reset (an attacker too, before its
	// spray), so it excuses nothing: still a row. Shadow; the fleet read
	// decides.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	for i := 0; i < 12; i++ {
		l.observe(loginRec("62.1.118.59", t0+int64(i)*60), "welder.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("62.1.118.59", t0+800), "dvs.welder.gr", "WP_LOGIN", "na")
	l.observe(loginRec("62.1.118.59", t0+900), "welder.gr", "WP_LOGIN", "ok")
	if d := sink.of("login_dirty_success"); len(d) != 1 || d[0].Payload["flagged_by"] != "own_fails" {
		t.Fatalf("a reset request must not excuse a success: %+v", d)
	}
}

func TestLoginLedgerDirtySuccessStillFires(t *testing.T) {
	// The first success after a run of failures, with no success before it.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < 12; i++ {
		l.observe(loginRec("192.0.2.50", t0+int64(i)*60), "one.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("192.0.2.50", t0+900), "one.gr", "WP_LOGIN", "ok")
	if len(sink.of("login_dirty_success")) != 1 {
		t.Fatal("first success after failures must still be a row")
	}
	// A flagged sprayer's FIRST success on a site it never touched (ok 0,
	// fails 0 there): still a row.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	for i := 0; i < 12; i++ {
		l.observe(loginRec("217.60.196.9", t0+int64(i)*60), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("217.60.196.9", t0+900), "victim.gr", "WP_LOGIN", "ok")
	if d := sink.of("login_dirty_success"); len(d) != 1 || d[0].Payload["flagged_by"] != "ip" {
		t.Fatalf("flagged sprayer on a fresh site: %+v", d)
	}
	// One earlier success does not excuse many failures after it.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	l.observe(loginRec("192.0.2.51", t0), "one.gr", "WP_LOGIN", "ok")
	for i := 0; i < 12; i++ {
		l.observe(loginRec("192.0.2.51", t0+60+int64(i)*60), "one.gr", "WP_LOGIN", "fail")
	}
	l.observe(loginRec("192.0.2.51", t0+5000), "one.gr", "WP_LOGIN", "ok")
	if len(sink.of("login_dirty_success")) != 1 {
		t.Fatal("1 success then 12 failures then a success: still a row")
	}
}

func TestLoginLedgerSitesCountOnlyFailures(t *testing.T) {
	// Successes on other sites do not make a three-site spray.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	l.observe(loginRec("198.51.100.60", t0), "a.gr", "WP_LOGIN", "ok")
	l.observe(loginRec("198.51.100.60", t0+1), "b.gr", "WP_LOGIN", "ok")
	for i := 0; i < 12; i++ {
		l.observe(loginRec("198.51.100.60", t0+10+int64(i)*600), "c.gr", "WP_LOGIN", "fail")
	}
	if n := len(sink.of("login_spray")); n != 0 {
		t.Fatalf("ok/reset sites counted as failed sites: %d rows", n)
	}
	if c := l.ips["198.51.100.60"]; c.failedSites() != 1 || c.nsites != 3 {
		t.Fatalf("failedSites=%d nsites=%d", c.failedSites(), c.nsites)
	}
}

func TestLoginLedgerResetRequestThroughIngest(t *testing.T) {
	e := NewEngine(Config{})
	sink := &rowSink{}
	e.loginLedger.emit = sink.emit
	feed := func(i int, auth string) {
		line := strings.Replace(authBase, "1000.5", strconv.FormatInt(t0+int64(i), 10), 1) + "\t0\t" + auth
		rec, ok := parseSocketTSV(line)
		if !ok {
			t.Fatal("parse")
		}
		e.ingest(rec, line)
	}
	for i := 0; i < 12; i++ {
		feed(i, "WP_LOGIN;li=0;l=/wp-login.php;c=wordpress_test_cookie")
	}
	feed(20, "WP_LOGIN;li=0;a=lostpassword;l=/wp-login.php;c=wordpress_test_cookie")
	feed(30, "WP_LOGIN;li=1;l=/wp-admin/;c=wordpress_logged_in_x")
	if n := len(sink.of("login_dirty_success")); n != 1 {
		t.Fatalf("a reset request in between excuses nothing: %d rows", n)
	}
}

func TestLoginLedgerSuccessSitesDoNotStarveFailures(t *testing.T) {
	// A client that logged in on every slot's worth of sites, then fails
	// slowly on other sites: the failures still take slots, so L1's site
	// spread sees them.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	for i := 0; i < loginMaxSites; i++ {
		l.observe(loginRec("198.51.100.70", t0+int64(i)), "own"+strconv.Itoa(i)+".gr", "WP_LOGIN", "ok")
	}
	for i := 0; i < 12; i++ {
		l.observe(loginRec("198.51.100.70", t0+600+int64(i)*400), "v"+strconv.Itoa(i%4)+".gr", "WP_LOGIN", "fail")
	}
	r := sink.of("login_spray")
	if len(r) != 1 || r[0].Payload["sites"] != 4 {
		t.Fatalf("slow spray after logins on %d sites: %+v", loginMaxSites, r)
	}
}

func TestLoginLedgerStuffingHitBeforeFlagStillReported(t *testing.T) {
	// One try on victim.gr gets in (not flagged yet: no row), then the
	// client sprays and is flagged, then uses the account again: that use
	// is a dirty success. A success with no failure on the site excuses
	// nothing.
	sink := &rowSink{}
	l := newLoginLedger(sink.emit)
	l.observe(loginRec("203.0.113.9", t0), "victim.gr", "WP_LOGIN", "ok")
	for i := 0; i < 12; i++ {
		l.observe(loginRec("203.0.113.9", t0+10+int64(i)*10), "s"+strconv.Itoa(i%3)+".gr", "WP_LOGIN", "fail")
	}
	if len(sink.of("login_spray")) != 1 {
		t.Fatal("the spray must flag the client")
	}
	l.observe(loginRec("203.0.113.9", t0+4000), "victim.gr", "WP_LOGIN", "ok")
	if d := sink.of("login_dirty_success"); len(d) != 1 || d[0].Payload["flagged_by"] != "ip" {
		t.Fatalf("stuffing hit's later use: %+v", d)
	}
	// And a later use more than an hour on is reported again.
	l.observe(loginRec("203.0.113.9", t0+8000), "victim.gr", "WP_LOGIN", "ok")
	if len(sink.of("login_dirty_success")) != 2 {
		t.Fatal("hourly re-report of a flagged client's use")
	}
}

func TestLoginLedgerPublishesLoginEvents(t *testing.T) {
	var got []LoginEvent
	oks := 0
	unsub := SubscribeLoginEvents(func(ev LoginEvent) {
		if ev.OK {
			oks++
			return
		}
		got = append(got, ev)
	})
	defer unsub()
	l := newLoginLedger((&rowSink{}).emit)

	// A site's own tool: successes first, then a failure there is the owner's.
	for i := 0; i < 3; i++ {
		l.observe(loginRec("94.66.129.119", t0+int64(i)), "www.mygreecetours.org", "WP_LOGIN", "ok")
	}
	l.observe(loginRec("94.66.129.119", t0+10), "mygreecetours.org", "WP_LOGIN", "fail")
	// A stranger's failure, and a success (never published).
	l.observe(loginRec("203.0.113.9", t0+20), "staging.victim.gr", "WP_LOGIN", "fail")
	l.observe(loginRec("203.0.113.9", t0+30), "victim.gr", "WP_LOGIN", "ok")
	// A success alone is not ownership: the next failure there still counts.
	l.observe(loginRec("203.0.113.10", t0+40), "a.gr", "WP_LOGIN", "fail")
	l.observe(loginRec("203.0.113.10", t0+41), "a.gr", "WP_LOGIN", "fail")
	l.observe(loginRec("203.0.113.10", t0+42), "a.gr", "WP_LOGIN", "ok")
	l.observe(loginRec("203.0.113.10", t0+43), "a.gr", "WP_LOGIN", "fail")

	if len(got) != 5 || oks != 5 {
		t.Fatalf("published %d failures and %d successes, want 5 and 5: %+v", len(got), oks, got)
	}
	if !got[0].Owner || got[0].Site != "mygreecetours.org" || got[0].IP != "94.66.129.119" {
		t.Fatalf("owner tool's failure: %+v", got[0])
	}
	if got[1].Owner || got[1].Site != "victim.gr" || got[1].Host != "staging.victim.gr" || got[1].Tag != "WP_LOGIN" {
		t.Fatalf("stranger's failure: %+v", got[1])
	}
	if got[4].Owner {
		t.Fatalf("1 success after 2 failures made the client the owner: %+v", got[4])
	}
	if got[1].When.Unix() != t0+20 {
		t.Fatalf("event time: %v", got[1].When)
	}

	// The kill switch stops the events with the rows.
	ConfigureLoginSignals(false)
	defer ConfigureLoginSignals(true)
	l.observe(loginRec("203.0.113.11", t0+50), "a.gr", "WP_LOGIN", "fail")
	if len(got) != 5 {
		t.Fatal("LOGIN_SIGNALS = 0 still published")
	}
}

func TestLoginEventFormMarksTheOtherWPForms(t *testing.T) {
	if !authFormFail(authField{Tag: "WP_LOGIN", Action: "lostpassword"}) ||
		!authFormFail(authField{Tag: "WP_LOGIN", Action: "register"}) ||
		authFormFail(authField{Tag: "WP_LOGIN"}) || authFormFail(authField{Tag: "WP_LOGIN", Action: "login"}) ||
		authFormFail(authField{Tag: "LOGIN_POST", Action: "lostpassword"}) ||
		authFormFail(authField{Tag: "WP_LOGIN", Action: "rp"}) || authFormFail(authField{Tag: "WP_LOGIN", Action: "postpass"}) {
		t.Fatal("authFormFail")
	}
	var got []LoginEvent
	unsub := SubscribeLoginEvents(func(ev LoginEvent) { got = append(got, ev) })
	defer unsub()
	l := newLoginLedger(nil)
	l.observeForm(loginRec("203.0.113.70", t0), "a.gr", "WP_LOGIN", "fail", true)
	l.observeForm(loginRec("203.0.113.70", t0+1), "a.gr", "WP_LOGIN", "ok", true)
	l.observe(loginRec("203.0.113.70", t0+2), "a.gr", "WP_LOGIN", "fail")
	if len(got) != 3 || !got[0].Form || got[1].Form || got[2].Form {
		t.Fatalf("Form on the published events: %+v", got)
	}
}
