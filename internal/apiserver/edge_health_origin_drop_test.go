package apiserver

// Tests for edge_health Check E (origin-premature-close): the "origin accepted
// the connection then died on it" class. Log lines below are the real shape the
// edge writes (log_format cfm), taken from the 2026-09 Angie→Apache incident.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const dropTestNow int64 = 1789818900

// dropLine builds an access line for a gateway failure where the origin never
// sent a response header (uht="-"), `ageSec` seconds before dropTestNow.
func dropLine(host, status string, ageSec int64) string {
	return `ts="19/Sep/2026:14:54:50 +0300" msec=` + itoa64(dropTestNow-ageSec) +
		`.269 client=94.68.40.255 host=` + host +
		` method=GET uri=/wp-login.php proto="HTTP/2.0" status=` + status +
		` rt=2.801 urt="2.800" uct="0.007" uht="-" sslr="r" luams=1.0 ust=` + status +
		` uaddr=84.54.49.202:443 uloc="-" sch=https up=cfm_apache` +
		` pass=https://cfm_origin_https dst=84.54.49.202:9043 bytes=193`
}

// okLine is a healthy 200 through the same origin path.
func okLine(host string) string {
	return `ts="19/Sep/2026:14:31:42 +0300" msec=` + itoa64(dropTestNow-60) +
		`.001 client=94.68.40.255 host=` + host +
		` method=GET uri=/ proto="HTTP/2.0" status=200 rt=0.595 urt="0.595"` +
		` uct="0.007" uht="0.595" sslr="r" luams=0.0 ust=200 uaddr=84.54.49.202:443` +
		` uloc="-" sch=https up=cfm_apache pass=https://cfm_origin_https bytes=23637`
}

// stubDropScan wires the shared stubs for a Check E test: Angie (no keepalive
// trap), knob off, quiet error log, and the given access lines + scanned count.
func stubDropScan(t *testing.T, scanned int, lines []string) {
	t.Helper()
	edgeHealthNow = func() int64 { return dropTestNow }
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "angie", "Angie/1.12.2", true
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		for _, l := range lines {
			fn(l)
		}
		return "/var/log/angie/access.log", scanned, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/var/log/angie/error.log", 0, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "cfm_bridge_config.lua")
	if err := os.WriteFile(bridge, []byte("return {\n  origin_keepalive = false,\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	edgeHealthBridgeConfigPaths = []string{bridge}
}

// TestOriginDrop_IncidentShape reproduces the incident: ~0.07% of requests
// dying with no response header, spread across many vhosts ⇒ a warn finding
// that names the origin (not one app) and drives `overall`.
func TestOriginDrop_IncidentShape(t *testing.T) {
	defer stubEdgeHealth(t)()

	hosts := []string{
		"mousaon.infected.gr", "polykarpos-bio.gr", "sei.gr", "actcon.gr",
		"camomillablu.gr", "roostercafe.gr", "cinephos.gr",
	}
	var lines []string
	for i := 0; i < 35; i++ {
		lines = append(lines, dropLine(hosts[i%len(hosts)], "502", int64(i*10)))
	}
	lines = append(lines, okLine("mousaon.infected.gr"))
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")

	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn (0.070%% over the 0.02%% floor, under 0.2%% crit)", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	if got := ev["origin_no_response_header"]; got != 35 {
		t.Errorf("origin_no_response_header = %v, want 35", got)
	}
	if got := ev["rate_pct"]; got != "0.070" {
		t.Errorf("rate_pct = %v, want 0.070", got)
	}
	if got := ev["distinct_hosts"]; got != len(hosts) {
		t.Errorf("distinct_hosts = %v, want %d", got, len(hosts))
	}
	// The scope phrase is what tells an operator this is the origin, not one app.
	if s := f["summary"].(string); !strings.Contains(s, "an origin-wide fault") {
		t.Errorf("summary should indict the origin across vhosts, got %q", s)
	}
	if rep["overall"] != "warn" {
		t.Errorf("overall = %v, want warn", rep["overall"])
	}
}

// TestOriginDrop_IgnoresApplicationErrors is the core discriminator: a 5xx the
// origin actually ANSWERED (uht set) and a plain 500 are application errors,
// not dropped connections, and must never reach the finding.
func TestOriginDrop_IgnoresApplicationErrors(t *testing.T) {
	defer stubEdgeHealth(t)()

	answered502 := strings.Replace(dropLine("shop.gr", "502", 30), `uht="-"`, `uht="0.412"`, 1)
	// A 500 is outside the gateway set entirely — not counted even headerless.
	app500 := dropLine("shop.gr", "500", 30)
	// "status=502" inside the URI must not be read as the status field.
	inURI := `ts="x" msec=` + itoa64(dropTestNow-30) + `.0 client=1.2.3.4 host=shop.gr` +
		` method=GET uri=/debug?status=502 proto="HTTP/1.1" status=200 uht="0.100" up=cfm_apache`

	stubDropScan(t, 10_000, []string{answered502, app500, inURI, okLine("shop.gr")})

	rep := buildEdgeHealthReport(context.Background(), 10_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok (no genuine premature closes)", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	if got := ev["gateway_5xx_total"]; got != 1 {
		t.Errorf("gateway_5xx_total = %v, want 1 (the answered 502 only)", got)
	}
}

// TestOriginDrop_FloorBeatsRate pins the quiet-node guard: 9 drops in a 100-line
// window is a 9% rate — far over the critical rate — but under the absolute
// event floor, so it must stay `ok` rather than cry wolf on a near-idle node.
func TestOriginDrop_FloorBeatsRate(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < edgeHealthOriginDropMinEvents-1; i++ {
		lines = append(lines, dropLine("quiet.gr", "502", int64(i)))
	}
	stubDropScan(t, 100, lines)

	rep := buildEdgeHealthReport(context.Background(), 100)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok (%d events is under the %d floor despite a 9%% rate)",
			f["severity"], edgeHealthOriginDropMinEvents-1, edgeHealthOriginDropMinEvents)
	}
}

// TestOriginDrop_RateBeatsFloor is the mirror: plenty of events in absolute
// terms, but a vanishing share of a huge window ⇒ background noise, not an
// incident.
func TestOriginDrop_RateBeatsFloor(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 15; i++ {
		lines = append(lines, dropLine("busy.gr", "502", int64(i)))
	}
	stubDropScan(t, 500_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 500_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok (0.003%% is under the 0.02%% warn rate)", f["severity"])
	}
}

// TestOriginDrop_Critical: a genuine outage — 1 request in 250 losing its
// origin, still happening now.
func TestOriginDrop_Critical(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, dropLine("shop.gr", "504", int64(i%600)))
	}
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "critical" {
		t.Fatalf("severity = %v, want critical", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	byStatus := ev["by_status"].(map[string]int)
	if byStatus["504"] != 200 {
		t.Errorf("by_status[504] = %d, want 200", byStatus["504"])
	}
	// A single affected vhost must read as that app, not an origin-wide fault.
	if s := f["summary"].(string); !strings.Contains(s, "likely that app, not the origin") {
		t.Errorf("single-vhost summary should scope to the app, got %q", s)
	}
	if rep["overall"] != "critical" {
		t.Errorf("overall = %v, want critical", rep["overall"])
	}
}

// TestOriginDrop_Resolved: the drops are all older than the freshness window,
// so the incident reads as stopped — warn, never a stale critical.
func TestOriginDrop_Resolved(t *testing.T) {
	defer stubEdgeHealth(t)()

	old := edgeHealthOriginDropFreshWindowSec + 600 // comfortably outside
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, dropLine("shop.gr", "502", old+int64(i)))
	}
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn (rate is critical-grade but nothing is recent)", f["severity"])
	}
	if s := f["summary"].(string); !strings.Contains(s, "appears to have stopped") {
		t.Errorf("summary should read as resolved, got %q", s)
	}
	ev := f["evidence"].(map[string]any)
	if got := ev["recent_drops"]; got != 0 {
		t.Errorf("recent_drops = %v, want 0", got)
	}
}

// TestOriginDrop_NoTimestampsFailSafe: an access log without msec= must be
// treated as LIVE, never silently downgraded — the same fail-safe the 421
// check uses.
func TestOriginDrop_NoTimestampsFailSafe(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 200; i++ {
		l := dropLine("shop.gr", "502", 30)
		// Strip the msec field entirely.
		l = strings.Replace(l, "msec="+itoa64(dropTestNow-30)+".269 ", "", 1)
		lines = append(lines, l)
	}
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "critical" {
		t.Fatalf("severity = %v, want critical (unparseable timestamps must fail safe to live)", f["severity"])
	}
}

// TestPct3 pins the rate formatting: these rates live in hundredths of a
// percent, where coarser rounding would render a real incident as 0.00.
func TestPct3(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0.0007, "0.070"},
		{0.002, "0.200"},
		{0.0002, "0.020"},
		{0.0000001, "0.000"},
		{1, "100.000"},
	}
	for _, c := range cases {
		if got := pct3(c.in); got != c.want {
			t.Errorf("pct3(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOriginDrop_ForgedStatusInUserAgent is the spoofing guard: the ua= field is
// client-controlled and nginx does not escape spaces in it, and edge-SERVED
// responses (challenge/block/redirect) legitimately carry uht="-". Matching a
// status-shaped pattern anywhere in the line would therefore let a visitor
// manufacture origin-drop events — and, now that Check E feeds whats_wrong, a
// fake critical. Only the FIRST status= token (the real field) may count.
func TestOriginDrop_ForgedStatusInUserAgent(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 200; i++ {
		// A challenge page served BY THE EDGE: real status 403, no upstream, and
		// a User-Agent crafted to look like a 502 log field.
		lines = append(lines, `ts="x" msec=`+itoa64(dropTestNow-30)+
			`.0 client=1.2.3.4 host=victim.gr method=GET uri=/ proto="HTTP/1.1"`+
			` status=403 rt=0.001 uct="-" uht="-" uaddr=- up=cfm_challenge`+
			` ua="Mozilla/5.0 status=502 x"`)
	}
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok — a forged status in ua= must not count", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	if got := ev["gateway_5xx_total"]; got != 0 {
		t.Errorf("gateway_5xx_total = %v, want 0 (the real status is 403)", got)
	}
}

// TestOriginDrop_RequiresUpstreamPeer: uht="-" alone is not enough. A response
// the EDGE produced by itself (no upstream selected ⇒ uaddr=-) is not an
// origin-hop fault and must not be counted, however many of them there are.
func TestOriginDrop_RequiresUpstreamPeer(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 200; i++ {
		// Genuine status=502, genuine uht="-", but no upstream was ever chosen —
		// e.g. the admin upstream-error page while the daemon restarts.
		lines = append(lines, strings.Replace(
			dropLine("victim.gr", "502", 30), "uaddr=84.54.49.202:443", "uaddr=-", 1))
	}
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok — no upstream peer means no origin hop", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	if got := ev["gateway_5xx_total"]; got != 200 {
		t.Errorf("gateway_5xx_total = %v, want 200 (counted as gateway 5xx, just not as drops)", got)
	}
	if got := ev["origin_no_response_header"]; got != 0 {
		t.Errorf("origin_no_response_header = %v, want 0", got)
	}
}

// A connect/TLS failure names its peer (nginx sets $upstream_addr once a peer is
// chosen) and IS an origin-hop fault, so it must still count.
func TestOriginDrop_ConnectFailureStillCounts(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 35; i++ {
		lines = append(lines, strings.Replace(
			dropLine("shop.gr", "502", int64(i)), `uct="0.007"`, `uct="-"`, 1))
	}
	stubDropScan(t, 50_000, lines)

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-premature-close")
	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn — a never-usable origin connection is still an origin fault", f["severity"])
	}
}

// ── Check C recency ───────────────────────────────────────────────────────────
// A fatal cfm_origin_ka tier is worker-lifetime, not per-request, so old
// evidence must NOT be silently cleared — but it must also not sit as a
// permanent `critical` for as long as it stays in the error-log tail, now that
// Check C feeds whats_wrong. Fresh ⇒ critical; stale ⇒ warn, with the age and
// the "still live if not reloaded" caveat spelled out.

// errLineAt renders an edge error-log line stamped `age` before dropTestNow, in
// the same LOCAL time nginx/Angie write.
func errLineAt(age int64, body string) string {
	return time.Unix(dropTestNow-age, 0).Local().Format("2006/01/02 15:04:05") +
		" [error] 123#123: " + body
}

func stubKATier(t *testing.T, errLines []string) {
	t.Helper()
	edgeHealthNow = func() int64 { return dropTestNow }
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "angie", "Angie/1.12.2", true
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/var/log/angie/access.log", 50_000, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		for _, l := range errLines {
			fn(l)
		}
		return "/var/log/angie/error.log", len(errLines), nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "cfm_bridge_config.lua")
	if err := os.WriteFile(bridge, []byte("return {\n  origin_keepalive = true,\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	edgeHealthBridgeConfigPaths = []string{bridge}
}

func TestOriginKATier_FreshFatalIsCritical(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubKATier(t, []string{errLineAt(120, "[cfm_origin_ka] ngx.balancer unavailable")})

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-ka-tier")
	if f["severity"] != "critical" {
		t.Fatalf("severity = %v, want critical (2m old)", f["severity"])
	}
}

func TestOriginKATier_StaleFatalDegradesToWarn(t *testing.T) {
	defer stubEdgeHealth(t)()
	stale := edgeHealthOriginKAFreshWindowSec + 3600 // 7h ago
	stubKATier(t, []string{errLineAt(stale, "[cfm_origin_ka] ngx.balancer unavailable")})

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-ka-tier")
	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn (stale evidence must not be a permanent critical)", f["severity"])
	}
	// ...but it must NOT read as resolved: the module loads once per worker.
	s := f["summary"].(string)
	if !strings.Contains(s, "still live") {
		t.Errorf("stale summary must keep the still-live caveat, got %q", s)
	}
	ev := f["evidence"].(map[string]any)
	ages, ok := ev["tier_age_sec"].(map[string]int64)
	if !ok || ages["balancer_unavailable"] < stale {
		t.Errorf("evidence should carry this tier's age: %v", ev)
	}
}

// Recency is PER TIER: a fresh module_load_failed must not grade an old,
// already-fixed balancer_unavailable as live — that would report both the wrong
// severity and the wrong root cause.
func TestOriginKATier_RecencyIsPerTier(t *testing.T) {
	defer stubEdgeHealth(t)()
	stale := edgeHealthOriginKAFreshWindowSec + 3600
	stubKATier(t, []string{
		errLineAt(stale, "[cfm_origin_ka] ngx.balancer unavailable"), // old, fixed
		errLineAt(60, "cfm_origin_ka load failed"),                   // fresh
	})

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-ka-tier")
	// balancer_unavailable matches first in the switch and is stale ⇒ warn,
	// graded on ITS own newest line, not the fresh load-failure.
	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn (the reported tier is the stale one)", f["severity"])
	}
	ages := f["evidence"].(map[string]any)["tier_age_sec"].(map[string]int64)
	if ages["balancer_unavailable"] < stale {
		t.Errorf("balancer_unavailable should be aged at ~%ds, got %v", stale, ages)
	}
	if ages["module_load_failed"] > 120 {
		t.Errorf("module_load_failed should be fresh, got %v", ages)
	}
}

// Fail-safe: a fatal line without a parseable timestamp counts as fresh, never
// silently downgraded — the same posture Checks B and E take.
func TestOriginKATier_UnparseableTimestampFailsSafe(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubKATier(t, []string{"no timestamp here [cfm_origin_ka] cfm_origin_ka load failed"})

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-ka-tier")
	if f["severity"] != "critical" {
		t.Fatalf("severity = %v, want critical (unparseable ⇒ treat as live)", f["severity"])
	}
}

// A FRESH degraded (non-fatal) tier is a warning.
func TestOriginKATier_FreshDegradedIsWarn(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubKATier(t, []string{errLineAt(300, "[cfm_origin_ka] keepalive-race retry is unavailable")})

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-ka-tier")
	if f["severity"] != "warn" {
		t.Fatalf("severity = %v, want warn", f["severity"])
	}
}

// ...but a STALE one must not sit in whats_wrong as a permanent warning until it
// scrolls out of the error-log window (weeks on a quiet node). A degraded tier
// is a capability gap the edge tolerates, so stale evidence leaves triage while
// staying fully visible in this tool's summary and tiers map.
func TestOriginKATier_StaleDegradedLeavesTriage(t *testing.T) {
	defer stubEdgeHealth(t)()
	stubKATier(t, []string{errLineAt(edgeHealthOriginKAFreshWindowSec+7200,
		"[cfm_origin_ka] keepalive-race retry is unavailable")})

	rep := buildEdgeHealthReport(context.Background(), 50_000)
	f := findFinding(t, rep, "origin-ka-tier")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok", f["severity"])
	}
	s := f["summary"].(string)
	if !strings.Contains(s, "stale evidence") {
		t.Errorf("stale degraded summary must still name what it saw, got %q", s)
	}
	if tiers := f["evidence"].(map[string]any)["tiers"].(map[string]int); tiers["degraded_no_retry"] != 1 {
		t.Errorf("tiers must still carry the evidence: %v", tiers)
	}
}

// TestOriginDrop_RetriedRequestShapes covers the comma-joined per-attempt uht
// list. cfm_origin_ka arms set_more_tries(1) on every POOLED port-80 origin
// request, so `uht="-, -"` is the NORMAL failure shape there — matching only the
// single-valued `uht="-"` reported `ok` straight through an outage.
func TestOriginDrop_RetriedRequestShapes(t *testing.T) {
	// Both attempts failed ⇒ a drop.
	bothFailed := func(i int) string {
		l := strings.Replace(dropLine("shop.gr", "502", int64(i)), `uht="-"`, `uht="-, -"`, 1)
		return strings.Replace(l, "uaddr=84.54.49.202:443", "uaddr=84.54.49.202:80, 84.54.49.202:80", 1)
	}
	// The retry succeeded ⇒ the client was served; NOT a drop.
	retrySucceeded := func(i int) string {
		l := strings.Replace(dropLine("shop.gr", "502", int64(i)), `uht="-"`, `uht="-, 0.412"`, 1)
		return strings.Replace(l, "uaddr=84.54.49.202:443", "uaddr=84.54.49.202:80, 84.54.49.202:80", 1)
	}

	t.Run("all attempts failed counts", func(t *testing.T) {
		defer stubEdgeHealth(t)()
		var lines []string
		for i := 0; i < 35; i++ {
			lines = append(lines, bothFailed(i))
		}
		stubDropScan(t, 50_000, lines)

		f := findFinding(t, buildEdgeHealthReport(context.Background(), 50_000), "origin-premature-close")
		if f["severity"] != "warn" {
			t.Fatalf("severity = %v, want warn — a pooled retry that also failed is still a drop", f["severity"])
		}
		if got := f["evidence"].(map[string]any)["origin_no_response_header"]; got != 35 {
			t.Errorf("origin_no_response_header = %v, want 35", got)
		}
	})

	t.Run("successful retry does not count", func(t *testing.T) {
		defer stubEdgeHealth(t)()
		var lines []string
		for i := 0; i < 200; i++ {
			lines = append(lines, retrySucceeded(i))
		}
		stubDropScan(t, 50_000, lines)

		f := findFinding(t, buildEdgeHealthReport(context.Background(), 50_000), "origin-premature-close")
		if f["severity"] != "ok" {
			t.Fatalf("severity = %v, want ok — the retry served the client", f["severity"])
		}
	})
}

// TestOriginDrop_ForgedStatusInCFHeader is the injection case the ua= test
// misses: cf="$http_cf_connecting_ip" is a raw client header logged THREE
// fields BEFORE the real status=, so "first match wins" is not enough on its
// own — the status must be read from outside quoted values entirely.
func TestOriginDrop_ForgedStatusInCFHeader(t *testing.T) {
	defer stubEdgeHealth(t)()

	var lines []string
	for i := 0; i < 200; i++ {
		// Real status 499 (client aborted mid-upstream): genuine uht="-" and a
		// genuine peer, with CF-Connecting-IP: `0 status=502 0`.
		lines = append(lines, `ts="x" msec=`+itoa64(dropTestNow-30)+
			`.0 client=1.2.3.4 peer=1.2.3.4 cf="0 status=502 0" host=victim.gr`+
			` method=GET uri=/ proto="HTTP/1.1" status=499 rt=0.5 uct="0.007"`+
			` uht="-" uaddr=84.54.49.202:443 up=cfm_apache`)
	}
	stubDropScan(t, 50_000, lines)

	f := findFinding(t, buildEdgeHealthReport(context.Background(), 50_000), "origin-premature-close")
	if f["severity"] != "ok" {
		t.Fatalf("severity = %v, want ok — a status forged inside cf= must not count", f["severity"])
	}
	if got := f["evidence"].(map[string]any)["gateway_5xx_total"]; got != 0 {
		t.Errorf("gateway_5xx_total = %v, want 0 (the real status is 499)", got)
	}
}

func TestStripQuotedAndLineStatus(t *testing.T) {
	cases := []struct{ line, want string }{
		{`cf="0 status=502 0" status=499 ua="x"`, "499"},
		{`cf="-" status=502 ua="Mozilla status=200 x"`, "502"},
		{`cf="-" ua="status=502"`, ""},
		{`status=200`, "200"},
	}
	for _, c := range cases {
		if got := lineStatus(c.line); got != c.want {
			t.Errorf("lineStatus(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}
