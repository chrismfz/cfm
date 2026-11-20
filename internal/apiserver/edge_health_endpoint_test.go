package apiserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall/netfilterdiag"
	"cfm/internal/originrealip"
	webdet "cfm/internal/webdetector"
)

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// TestNativeKeepaliveTrap pins the engine/version → trap logic that names the
// 421 root cause (nginx >=1.29.7 native keepalive default-on & SNI-blind).
func TestNativeKeepaliveTrap(t *testing.T) {
	cases := []struct {
		engine, version string
		wantBase        string
		wantTrap        bool
	}{
		{"openresty", "openresty/1.31.1.1", "1.31.1", true},  // fleet
		{"openresty", "openresty/1.29.7.1", "1.29.7", true},  // exact boundary
		{"openresty", "openresty/1.29.6.1", "1.29.6", false}, // just below
		{"openresty", "openresty/1.27.5.1", "1.27.5", false}, // older
		{"angie", "Angie/1.12.1", "", false},                 // Angie keeps it off
		{"nginx", "nginx/1.31.0", "1.31.0", true},
		{"cfm-edge", "nginx/1.31.9", "1.31.9", true}, // cfm-edge -v prints nginx's line
	}
	for _, c := range cases {
		base, trap := nativeKeepaliveTrap(c.engine, c.version)
		if base != c.wantBase || trap != c.wantTrap {
			t.Errorf("nativeKeepaliveTrap(%q,%q) = (%q,%v), want (%q,%v)",
				c.engine, c.version, base, trap, c.wantBase, c.wantTrap)
		}
	}
}

// TestEdgeHealthReport_WarmReuse421 drives the full correlation: OpenResty 1.31.1
// (trap version) + ORIGIN_KEEPALIVE on + warm-reuse 421s ⇒ overall critical.
func TestEdgeHealthReport_WarmReuse421(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()

	// Active engine: openresty 1.31.1.1.
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		fn(`t client=1.2.3.4 host=pireasplus.gr status=421 uct="0.000" up=cfm_apache pass=https://cfm_origin_https`)
		fn(`t client=1.2.3.4 host=pireasplus.gr status=421 uct="0.000" up=cfm_apache pass=https://cfm_origin_https`)
		fn(`t client=9.9.9.9 host=other.gr status=421 uct="0.045" up=cfm_apache pass=https://84.54.49.35:443`) // not warm
		return "/usr/local/openresty/nginx/logs/access.log", 3, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		fn(`... [cfm_origin_ka] HTTP(80) origin pooling active`)
		fn(`... [cfm_origin_ka] origin port 443: per-request connection, never pooled ...`)
		return "/usr/local/openresty/nginx/logs/error.log", 2, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "cfm_bridge_config.lua")
	if err := os.WriteFile(bridge, []byte("return {\n  origin_keepalive = true,\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 1000)

	if rep["engine"] != "openresty" {
		t.Errorf("engine = %v, want openresty", rep["engine"])
	}
	if rep["native_keepalive_trap"] != true {
		t.Errorf("native_keepalive_trap = %v, want true", rep["native_keepalive_trap"])
	}
	if rep["origin_keepalive_knob"] != "true" {
		t.Errorf("origin_keepalive_knob = %v, want true", rep["origin_keepalive_knob"])
	}
	if rep["overall"] != "critical" {
		t.Fatalf("overall = %v, want critical", rep["overall"])
	}
	// The 421 finding must be critical and count exactly the warm-reuse ones.
	f := findFinding(t, rep, "origin-421-fingerprint")
	if f["severity"] != "critical" {
		t.Errorf("421 finding severity = %v, want critical", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	if ev["warm_reuse_421"] != 2 || ev["status_421_total"] != 3 {
		t.Errorf("421 counts = warm %v / total %v, want 2 / 3", ev["warm_reuse_421"], ev["status_421_total"])
	}
}

// TestEdgeHealthReport_Clean: trap version but knob off and no 421s ⇒ overall ok.
func TestEdgeHealthReport_Clean(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()

	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/access.log", 5000, nil // no 421 lines emitted
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 100, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "cfm_bridge_config.lua")
	_ = os.WriteFile(bridge, []byte("return { origin_keepalive = false }\n"), 0o600)
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 1000)
	if rep["overall"] != "ok" {
		t.Fatalf("overall = %v, want ok (knob off, no 421s)", rep["overall"])
	}
	if rep["origin_keepalive_knob"] != "false" {
		t.Errorf("knob = %v, want false", rep["origin_keepalive_knob"])
	}
}

// TestEdgeHealthReport_Precision locks in the false-positive guards: a retried
// request (uct list) is not "warm", and "status=421" inside a URI/param is not
// counted as a real 421.
func TestEdgeHealthReport_Precision(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 0, nil
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		fn(`host=a.gr status=421 uct="0.000" pass=https://cfm_origin_https`)        // real warm
		fn(`host=b.gr status=421 uct="0.000, 0.052" pass=https://cfm_origin_https`) // retried → NOT warm
		fn(`host=c.gr "GET /?status=421 HTTP/1.1" status=200 uct="0.010"`)          // param, real status=200 → NOT a 421
		return "/log/access.log", 3, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "b.lua")
	_ = os.WriteFile(bridge, []byte("origin_keepalive = true"), 0o600)
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 1000)
	f := findFinding(t, rep, "origin-421-fingerprint")
	ev := f["evidence"].(map[string]any)
	if ev["status_421_total"] != 2 {
		t.Errorf("status_421_total = %v, want 2 (the URI-param line excluded)", ev["status_421_total"])
	}
	if ev["warm_reuse_421"] != 1 {
		t.Errorf("warm_reuse_421 = %v, want 1 (the retry list excluded)", ev["warm_reuse_421"])
	}
}

// TestEdgeHealthReport_UnknownVersion: engine known but version unreadable must
// NOT report an all-clear on the trap check.
func TestEdgeHealthReport_UnknownVersion(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "", true // version unreadable
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/access.log", 100, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 0, nil
	}
	edgeHealthBridgeConfigPaths = []string{filepath.Join(t.TempDir(), "absent.lua")}

	rep := buildEdgeHealthReport(context.Background(), 1000)
	f := findFinding(t, rep, "engine-version-trap")
	if f["severity"] != "unknown" {
		t.Errorf("engine-version-trap severity = %v, want unknown (must not all-clear an unreadable version)", f["severity"])
	}
}

// TestEdgeHealthReport_HealthyKnobOnNoWolf: a correctly-configured node (trap
// engine, knob ON, no 421s, activation lines aged out of the window) must NOT
// escalate — overall ok, no permanent warn (the cry-wolf regression).
func TestEdgeHealthReport_HealthyKnobOnNoWolf(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/access.log", 50000, nil // no 421s
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 20000, nil // no [cfm_origin_ka] lines (aged out)
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "b.lua")
	_ = os.WriteFile(bridge, []byte("origin_keepalive = true"), 0o600)
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 1000)
	if rep["overall"] != "ok" {
		t.Fatalf("overall = %v, want ok (healthy knob-on node must not cry wolf)", rep["overall"])
	}
	if f := findFinding(t, rep, "engine-version-trap"); f["severity"] != "ok" {
		t.Errorf("engine-version-trap = %v, want ok (trap+knob-on+no-421 is not a warn)", f["severity"])
	}
	if f := findFinding(t, rep, "origin-ka-tier"); f["severity"] != "ok" {
		t.Errorf("origin-ka-tier = %v, want ok (empty tiers ≠ inactive)", f["severity"])
	}
}

// TestEdgeHealthReport_CriticalErrorTiers: the fatal error-log lines each map to
// a reachable critical tier (the load-failure line is `[cfm]`-tagged; the
// balancer-unavailable line matched no tier before).
func TestEdgeHealthReport_CriticalErrorTiers(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"module load failed", `2026/08/27 [error] 1#1: *5 [cfm] cfm_origin_ka load failed: nil, ...`},
		{"balancer unavailable", `2026/08/27 [error] 1#1: *5 [cfm_origin_ka] ngx.balancer unavailable: nil`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := stubEdgeHealth(t)
			defer restore()
			edgeHealthDetect = func(context.Context) (string, string, bool) { return "openresty", "openresty/1.31.1.1", true }
			edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
				return "/log/access.log", 100, nil
			}
			line := tc.line
			edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
				fn(line)
				return "/log/error.log", 1, nil
			}
			edgeHealthBridgeConfigPaths = []string{filepath.Join(t.TempDir(), "absent.lua")}

			rep := buildEdgeHealthReport(context.Background(), 1000)
			f := findFinding(t, rep, "origin-ka-tier")
			if f["severity"] != "critical" {
				t.Errorf("origin-ka-tier = %v, want critical for %q", f["severity"], tc.name)
			}
		})
	}
}

// TestEdgeHealthReport_KnobUnknownNotOk: trap engine but the bridge config is
// unreadable (knob unknown) must be "unknown" on the trap check, never "ok".
func TestEdgeHealthReport_KnobUnknownNotOk(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	edgeHealthDetect = func(context.Context) (string, string, bool) { return "openresty", "openresty/1.31.1.1", true }
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/access.log", 100, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 0, nil
	}
	edgeHealthBridgeConfigPaths = []string{filepath.Join(t.TempDir(), "absent.lua")} // knob unreadable

	rep := buildEdgeHealthReport(context.Background(), 1000)
	if f := findFinding(t, rep, "engine-version-trap"); f["severity"] != "unknown" {
		t.Errorf("engine-version-trap = %v, want unknown (knob unreadable, can't all-clear)", f["severity"])
	}
}

// TestEdgeHealthReport_WarmReuseResolved: a warm-reuse 421 storm sits in the
// scanned window but every hit predates the freshness window (the fix/restart
// took hold minutes ago). It must read `warn` (resolved, decays out), NOT
// `critical`, and must not escalate the engine-version-trap check either — this
// is the exact "the default wide window kept crying critical for minutes after
// the fix" regression that motivated the recency gate.
func TestEdgeHealthReport_WarmReuseResolved(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	const now = int64(1_800_000_000)
	edgeHealthNow = func() int64 { return now }
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	old := now - 1200 // 20 min ago (> the 10-min fresh window)
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		line := `msec=` + itoa64(old) + ` host=rokas.com status=421 uct="0.000" pass=https://cfm_origin_https`
		fn(line)
		fn(line)
		fn(line)
		return "/log/access.log", 200000, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 100, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "b.lua")
	_ = os.WriteFile(bridge, []byte("origin_keepalive = true"), 0o600)
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 200000)
	if rep["overall"] != "warn" {
		t.Fatalf("overall = %v, want warn (resolved storm ≠ live critical)", rep["overall"])
	}
	f := findFinding(t, rep, "origin-421-fingerprint")
	if f["severity"] != "warn" {
		t.Errorf("origin-421-fingerprint = %v, want warn", f["severity"])
	}
	ev := f["evidence"].(map[string]any)
	if ev["warm_reuse_421"] != 3 || ev["recent_warm_421"] != 0 {
		t.Errorf("counts = warm %v / recent %v, want 3 / 0", ev["warm_reuse_421"], ev["recent_warm_421"])
	}
	if f := findFinding(t, rep, "engine-version-trap"); f["severity"] != "ok" {
		t.Errorf("engine-version-trap = %v, want ok (no LIVE 421 ⇒ not critical)", f["severity"])
	}
}

// TestEdgeHealthReport_WarmReuseLiveByTimestamp: a warm-reuse 421 inside the
// freshness window is a LIVE incident ⇒ critical, with recent_warm_421 > 0.
func TestEdgeHealthReport_WarmReuseLiveByTimestamp(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	const now = int64(1_800_000_000)
	edgeHealthNow = func() int64 { return now }
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	fresh := now - 60 // 1 min ago (inside the 10-min fresh window)
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		fn(`msec=` + itoa64(now-1200) + ` host=a.gr status=421 uct="0.000" pass=https://cfm_origin_https`) // old
		fn(`msec=` + itoa64(fresh) + ` host=b.gr status=421 uct="0.000" pass=https://cfm_origin_https`)    // live
		return "/log/access.log", 50000, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 0, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "b.lua")
	_ = os.WriteFile(bridge, []byte("origin_keepalive = true"), 0o600)
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 50000)
	if rep["overall"] != "critical" {
		t.Fatalf("overall = %v, want critical (a warm 421 inside the fresh window is live)", rep["overall"])
	}
	f := findFinding(t, rep, "origin-421-fingerprint")
	ev := f["evidence"].(map[string]any)
	if ev["warm_reuse_421"] != 2 || ev["recent_warm_421"] != 1 {
		t.Errorf("counts = warm %v / recent %v, want 2 / 1", ev["warm_reuse_421"], ev["recent_warm_421"])
	}
}

// TestEdgeHealthReport_WarmReuseNoTimestampFailsafe: warm 421s with no parseable
// msec (an older log format) must FAIL SAFE to critical — never silently
// downgrade a real storm just because recency can't be judged.
func TestEdgeHealthReport_WarmReuseNoTimestampFailsafe(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	edgeHealthNow = func() int64 { return 1_800_000_000 }
	edgeHealthDetect = func(context.Context) (string, string, bool) {
		return "openresty", "openresty/1.31.1.1", true
	}
	edgeHealthScanAccess = func(_ context.Context, _ []string, _ string, _ int, fn func(string)) (string, int, error) {
		fn(`host=a.gr status=421 uct="0.000" pass=https://cfm_origin_https`) // no msec field
		return "/log/access.log", 50000, nil
	}
	edgeHealthScanError = func(_ context.Context, _ []string, _ string, _ int, _ func(string)) (string, int, error) {
		return "/log/error.log", 0, nil
	}
	dir := t.TempDir()
	bridge := filepath.Join(dir, "b.lua")
	_ = os.WriteFile(bridge, []byte("origin_keepalive = true"), 0o600)
	edgeHealthBridgeConfigPaths = []string{bridge}

	rep := buildEdgeHealthReport(context.Background(), 50000)
	if rep["overall"] != "critical" {
		t.Fatalf("overall = %v, want critical (unparseable recency must fail safe)", rep["overall"])
	}
}

// TestEdgeHealthReport_OriginRealIP covers Check G: an edge in front of an origin
// that does not trust its loopback warns (qualityweb, 2026-10-29), the same
// origin without an edge does not (avgerinos), and an undetectable origin is
// unknown, never a finding.
func TestEdgeHealthReport_OriginRealIP(t *testing.T) {
	restore := stubEdgeHealth(t)
	defer restore()
	edgeHealthDetect = func(context.Context) (string, string, bool) { return "angie", "Angie/1.12.4", true }
	edgeHealthScanAccess = func(context.Context, []string, string, int, func(string)) (string, int, error) {
		return "/var/log/angie/access.log", 0, nil
	}
	edgeHealthScanError = func(context.Context, []string, string, int, func(string)) (string, int, error) {
		return "/var/log/angie/error.log", 0, nil
	}
	edgeHealthBridgeConfigPaths = []string{filepath.Join(t.TempDir(), "absent.lua")}

	untrusted := originrealip.Probe{Panel: "cpanel", Stack: "apache", Header: "CF-Connecting-IP",
		Note: "no RemoteIPInternalProxy/RemoteIPTrustedProxy 127.0.0.1 in the Apache config"}
	edgeHealthOriginRealIP = func() (originrealip.Probe, bool) { return untrusted, true }
	rep := buildEdgeHealthReport(context.Background(), 1000)
	f := findFinding(t, rep, "origin-real-ip")
	if f["severity"] != "warn" || rep["overall"] != "warn" {
		t.Fatalf("edge in front, untrusted: finding=%v overall=%v", f, rep["overall"])
	}
	if s, _ := f["summary"].(string); !strings.Contains(s, "127.0.0.1") {
		t.Errorf("summary = %q", s)
	}

	edgeHealthOriginRealIP = func() (originrealip.Probe, bool) { return untrusted, false }
	rep = buildEdgeHealthReport(context.Background(), 1000)
	if f := findFinding(t, rep, "origin-real-ip"); f["severity"] != "ok" {
		t.Fatalf("no edge in front: %v", f)
	}

	// Trusted now, but the next DirectAdmin rewrite_confs undoes it (OpenLiteSpeed).
	doomed := originrealip.Probe{Panel: "directadmin", Stack: "litespeed", Trusted: true,
		Directive: "useIpInProxyHeader 2 (OpenLiteSpeed)", Source: "/etc/openlitespeed/httpd-accesscontrol.conf",
		Warning: "trusted now, but not after `da build rewrite_confs`"}
	edgeHealthOriginRealIP = func() (originrealip.Probe, bool) { return doomed, true }
	rep = buildEdgeHealthReport(context.Background(), 1000)
	if f := findFinding(t, rep, "origin-real-ip"); f["severity"] != "warn" || !strings.Contains(fmt.Sprint(f), "rewrite_confs") {
		t.Fatalf("trusted with a warning: %v", f)
	}
	doomed.Warning = ""
	rep = buildEdgeHealthReport(context.Background(), 1000)
	if f := findFinding(t, rep, "origin-real-ip"); f["severity"] != "ok" {
		t.Fatalf("trusted: %v", f)
	}

	edgeHealthOriginRealIP = func() (originrealip.Probe, bool) {
		return originrealip.Probe{Panel: "plain", Stack: "unknown", Note: "no apache/litespeed/nginx origin detected on disk"}, true
	}
	rep = buildEdgeHealthReport(context.Background(), 1000)
	if f := findFinding(t, rep, "origin-real-ip"); f["severity"] != "unknown" {
		t.Fatalf("unknown origin: %v", f)
	}
}

// Check H, earth before 2026-11-17: Imunify360 DNATs tcp/443 to WebShield at
// -100, ahead of CFM's web redirect at -99, and WebShield is busy.
func TestEdgeHealthReport_WebDNATOrder(t *testing.T) {
	defer stubEdgeHealth(t)()
	now := time.Date(2026, 11, 17, 10, 30, 0, 0, time.UTC)
	edgeHealthNow = func() int64 { return now.Unix() }
	nftJSON := func(cfmPrio string) string {
		return `{"nftables":[
 {"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
 {"chain":{"family":"ip","table":"nat","name":"INPUT_imunify360"}},
 {"chain":{"family":"inet","table":"cfm_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":` + cfmPrio + `,"policy":"accept"}},
 {"rule":{"family":"ip","table":"nat","chain":"PREROUTING","expr":[{"jump":{"target":"INPUT_imunify360"}}]}},
 {"rule":{"family":"ip","table":"nat","chain":"INPUT_imunify360","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":52223}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}}
]}`
	}
	setNFT := func(cfmPrio string) {
		edgeHealthNATReport = func(context.Context) (netfilterdiag.Report, error) {
			return netfilterdiag.Analyze([]byte(nftJSON(cfmPrio)), netfilterdiag.Expected{})
		}
	}
	var b strings.Builder
	old := now.Add(-time.Hour).Format("02/Jan/2006:15:04:05 -0700")
	b.WriteString(`1.2.3.4 - - [` + old + `] "GET / HTTP/1.1" 200 1 a.gr "-" "ua" WL:"0" "-" XFF:"-" CAPTCHA:"0" PEER:1.2.3.4` + "\n")
	for i := 0; i < 150; i++ {
		ts := now.Add(-time.Duration(i) * time.Second).Format("02/Jan/2006:15:04:05 -0700")
		xff := `XFF:"9.9.9.9"`
		if i%3 == 0 {
			xff = `XFF:"-"`
		}
		b.WriteString(`172.68.62.86 - - [` + ts + `] "GET / HTTP/2.0" 200 1 a.gr "-" "ua" WL:"0" "-" ` + xff + ` CAPTCHA:"0" PEER:172.68.62.86` + "\n")
	}
	log := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(log, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	edgeHealthWebShieldLog = log

	setNFT("-99")
	f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order")
	ev := f["evidence"].(map[string]any)
	if f["severity"] != "warn" || ev["webshield_requests"] != 150 || ev["webshield_proxied"] != 100 || ev["webshield_count_complete"] != true ||
		!strings.Contains(f["next"].(string), "NFT_DNAT_PRIORITY = -101") || !strings.Contains(f["summary"].(string), "imunify") {
		t.Fatalf("imunify first, busy: %v", f)
	}
	if strings.Contains(f["next"].(string), "challenge") || !strings.Contains(f["next"].(string), "drops") {
		t.Fatalf("a graylisted client is dropped by Imunify, not challenged: %q", f["next"])
	}
	// A line longer than the read buffer (a scanner's huge URI) is skipped,
	// not the end of the count.
	long := `9.9.9.9 - - [` + now.Format("02/Jan/2006:15:04:05 -0700") + `] "GET /` + strings.Repeat("a", 200<<10) + ` HTTP/1.1" 404 1 a.gr "-" "ua" WL:"0" "-" XFF:"-" CAPTCHA:"0" PEER:9.9.9.9` + "\n"
	if err := os.WriteFile(log, []byte(b.String()[:strings.Index(b.String(), "\n")+1]+long+b.String()[strings.Index(b.String(), "\n")+1:]), 0o644); err != nil {
		t.Fatal(err)
	}
	if ev := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order")["evidence"].(map[string]any); ev["webshield_requests"] != 151 {
		t.Fatalf("long line: %v", ev)
	}
	// A DNAT ahead at -200: CFM cannot go ahead of it (nft refuses -201).
	edgeHealthNATReport = func(context.Context) (netfilterdiag.Report, error) {
		return netfilterdiag.Analyze([]byte(strings.Replace(nftJSON("-99"), `"prio":-100`, `"prio":-200`, 1)), netfilterdiag.Expected{})
	}
	if f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order"); strings.Contains(f["next"].(string), "-201") || !strings.Contains(f["next"].(string), "has to move later") {
		t.Fatalf("-200: %v", f["next"])
	}
	// Another tool's DNAT ahead (Docker publishing :443 from iptables-nft's
	// PREROUTING): warn on the order, naming it, with no WebShield measure.
	edgeHealthNATReport = func(context.Context) (netfilterdiag.Report, error) {
		return netfilterdiag.Analyze([]byte(strings.ReplaceAll(nftJSON("-99"), "INPUT_imunify360", "DOCKER")), netfilterdiag.Expected{})
	}
	edgeHealthWebShieldLog = filepath.Join(t.TempDir(), "absent.log")
	if f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order"); f["severity"] != "warn" || !strings.Contains(f["summary"].(string), "iptables-nft") || !strings.Contains(f["summary"].(string), "not Imunify360") {
		t.Fatalf("docker ahead: %v", f)
	}
	edgeHealthWebShieldLog = log
	// CFM first: ok, whatever WebShield logs.
	setNFT("-101")
	if f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order"); f["severity"] != "ok" {
		t.Fatalf("cfm first: %v", f)
	}
	// Imunify first but WebShield quiet (speedhost): the documented choice, ok.
	setNFT("-99")
	edgeHealthNow = func() int64 { return now.Add(2 * time.Hour).Unix() }
	if f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order"); f["severity"] != "ok" {
		t.Fatalf("imunify first, quiet: %v", f)
	}
	// No log to measure with: unknown, never ok.
	edgeHealthWebShieldLog = filepath.Join(t.TempDir(), "absent.log")
	if f := findFinding(t, buildEdgeHealthReport(context.Background(), 1000), "web-dnat-order"); f["severity"] != "unknown" {
		t.Fatalf("unmeasured: %v", f)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func stubEdgeHealth(t *testing.T) func() {
	t.Helper()
	oDet, oAcc, oErr, oBridge, oNow, oCDN, oServ := edgeHealthDetect, edgeHealthScanAccess, edgeHealthScanError, edgeHealthBridgeConfigPaths, edgeHealthNow, edgeHealthCDNSuspects, edgeHealthChallengeServing
	// Check F reads the challenge server's in-process tracker; a test that
	// does not set it sees no suspects, whatever else ran in this binary.
	edgeHealthCDNSuspects = func(time.Time) []webdet.CDNCacheSuspect { return nil }
	oDirect, oDownloads := edgeHealthDirectBounces, edgeHealthDownloadBounces
	edgeHealthDirectBounces = func(time.Time) []webdet.CDNCacheSuspect { return nil }
	edgeHealthDownloadBounces = func(time.Time) []webdet.CDNCacheSuspect { return nil }
	edgeHealthChallengeServing = func() bool { return true }
	oNAT, oWSLog := edgeHealthNATReport, edgeHealthWebShieldLog
	edgeHealthNATReport = func(context.Context) (netfilterdiag.Report, error) { return netfilterdiag.Report{}, nil }
	edgeHealthWebShieldLog = filepath.Join(t.TempDir(), "absent.log")
	oRealIP := edgeHealthOriginRealIP
	edgeHealthOriginRealIP = func() (originrealip.Probe, bool) {
		return originrealip.Probe{Panel: "cpanel", Stack: "apache", Trusted: true, Directive: "RemoteIP{Internal,Trusted}Proxy 127.0.0.1", Source: "/etc/apache2/conf.d/i360.remoteip.conf", Header: "X-Forwarded-For"}, true
	}
	return func() {
		edgeHealthNATReport, edgeHealthWebShieldLog = oNAT, oWSLog
		edgeHealthOriginRealIP = oRealIP
		edgeHealthDirectBounces, edgeHealthDownloadBounces = oDirect, oDownloads
		edgeHealthDetect, edgeHealthScanAccess, edgeHealthScanError, edgeHealthBridgeConfigPaths, edgeHealthNow, edgeHealthCDNSuspects, edgeHealthChallengeServing = oDet, oAcc, oErr, oBridge, oNow, oCDN, oServ
	}
}

func findFinding(t *testing.T, rep map[string]any, check string) map[string]any {
	t.Helper()
	for _, f := range rep["findings"].([]map[string]any) {
		if f["check"] == check {
			return f
		}
	}
	t.Fatalf("finding %q not present", check)
	return nil
}
