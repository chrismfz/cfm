package apiserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

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

// ── helpers ──────────────────────────────────────────────────────────────────

func stubEdgeHealth(t *testing.T) func() {
	t.Helper()
	oDet, oAcc, oErr, oBridge := edgeHealthDetect, edgeHealthScanAccess, edgeHealthScanError, edgeHealthBridgeConfigPaths
	return func() {
		edgeHealthDetect, edgeHealthScanAccess, edgeHealthScanError, edgeHealthBridgeConfigPaths = oDet, oAcc, oErr, oBridge
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
