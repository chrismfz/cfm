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
	if len(nets) != 1 || nets[0].Payload["net"] != "104.234.53.0/24" || nets[0].Payload["ips"] != 6 || nets[0].IP != "" || nets[0].Host != "" {
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
	if len(sink.of("login_spray")) != 5 || len(sink.of("login_spray_net")) != 1 {
		t.Fatalf("flagged IPs: %d spray, %d net", len(sink.of("login_spray")), len(sink.of("login_spray_net")))
	}

	// IPv6: one /64.
	sink = &rowSink{}
	l = newLoginLedger(sink.emit)
	for i := 0; i < 30; i++ {
		l.observe(loginRec("2001:db8:1:2::"+strconv.FormatInt(int64(i%6+1), 16), t0+int64(i)*400), "s.gr", "WP_LOGIN", "fail")
	}
	if nets := sink.of("login_spray_net"); len(nets) != 1 || nets[0].Payload["net"] != "2001:db8:1:2::/64" {
		t.Fatalf("v6 pool: %+v", nets)
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
	m := map[string]int64{}
	for i := 0; i < 3000; i++ {
		m["k"+strconv.Itoa(i)] = t0
	}
	evictLogin(m, t0+10, func(v int64) int64 { return v })
	if len(m) != 3000-loginEvictBatch {
		t.Fatalf("batch eviction: %d left", len(m))
	}
	evictLogin(m, t0+86400, func(v int64) int64 { return v })
	if len(m) != 0 {
		t.Fatalf("idle-for-a-day eviction: %d left", len(m))
	}
	// Per-IP hosts and per-net IP sets are capped.
	l := newLoginLedger(nil)
	for i := 0; i < 100; i++ {
		l.observe(loginRec("198.51.100.10", t0+int64(i)), "h"+strconv.Itoa(i)+".gr", "WP_LOGIN", "fail")
		l.observe(loginRec("10.9.8."+strconv.Itoa(i), t0+int64(i)), "x.gr", "WP_LOGIN", "fail")
	}
	if n := len(l.ips["198.51.100.10"].hosts); n != loginMaxHosts {
		t.Fatalf("hosts cap: %d", n)
	}
	if n := len(l.nets["10.9.8.0/24"].ips); n != loginMaxNetIPs {
		t.Fatalf("net IPs cap: %d", n)
	}
}

func TestLoginLedgerWiredFromIngest(t *testing.T) {
	e := NewEngine(Config{})
	if e.loginLedger == nil {
		t.Fatal("NewEngine did not build the login ledger")
	}
	sink := &rowSink{}
	e.loginLedger.emit = sink.emit
	for i := 0; i < 25; i++ {
		line := strings.Replace(authBase, "1000.5", strconv.FormatInt(t0+int64(i), 10), 1) + "\t0\tWP_LOGIN;li=0;l=/wp-login.php;c="
		rec, ok := parseSocketTSV(line)
		if !ok {
			t.Fatal("parse")
		}
		rec.Upstream = true
		e.ingest(rec, line)
	}
	if n := len(sink.of("login_spray")); n != 1 {
		t.Fatalf("ingest → ledger: %d rows (%+v)", n, sink.rows)
	}
}
