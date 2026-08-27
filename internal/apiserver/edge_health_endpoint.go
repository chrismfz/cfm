package apiserver

// edge_health_endpoint.go — GET /api/v1/system/edge-health (read-only,
// admin-only). Backs the MCP edge_health tool: a focused, CORRELATED view of the
// in-path edge → origin hop that the raw tails (edge_access_tail /
// edge_error_tail) and generic config_drift can't give in one call.
//
// It exists because of the 2026-08 cross-SNI 421 incident (docs/proxy-performance
// .md): the symptom (status=421, warm uct≈0 through cfm_origin_https) sat in the
// edge access log for a week while the root cause lived in the live config ×
// engine version (nginx ≥ 1.29.7 turned native upstream keepalive ON by default,
// SNI-blind). Nothing correlated the two. This endpoint reads logs AND engine
// version together and names the class.
//
// Tier 1 (this iteration) — the checks that would have caught the incident in
// minutes:
//   A. engine + version + native-keepalive-default-on trap flag
//   B. 421 / SNI-mismatch fingerprint from the edge access log (warm-reuse shape),
//      RECENCY-AWARE: only 421s inside a freshness window drive `critical`, so a
//      resolved storm still in the file tail reads `warn`, not a stale `critical`.
//   C. [cfm_origin_ka] activation/degradation tiers from the edge error log
//   D. ORIGIN_KEEPALIVE knob state (from the published bridge config)
// See docs/edge-health.md for the design and the Tier-2/3 follow-ups (live
// config-invariant, Apache AH02032 correlation, latency split).
//
// Read-only: it only reads files and, for the engine version, runs the edge
// binary's `-v` (never `-t`/reload) under a short timeout against an allow-listed
// path. Host-wide edge state → admin-only, same family as the other
// /api/v1/system/* reads.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/edgeengine"
	"cfm/internal/edgelog"
	webdet "cfm/internal/webdetector"
)

// Injectable seams (tests stub these). Engine detection is delegated to the
// shared edgeengine leaf — the SINGLE source of truth for the OpenResty/Angie
// candidate lists + version parse, so it can't drift from the heartbeat agent's
// copy (CLAUDE.md §5).
var (
	edgeHealthDetect     = edgeengine.Detect
	edgeHealthScanAccess = edgelog.ScanAccess
	edgeHealthScanError  = edgelog.ScanError
	// Where the daemon publishes the ORIGIN_KEEPALIVE knob for the edge.
	edgeHealthBridgeConfigPaths = []string{"/var/lib/cfm/lua/cfm_bridge_config.lua"}
	// Wall-clock seam (tests stub it) so the 421 recency verdict is deterministic.
	edgeHealthNow = func() int64 { return time.Now().Unix() }
)

var (
	ehHostRe = regexp.MustCompile(`(?:^|\s)host=(\S+)`)
	// status=421 as the ACTUAL log field (whitespace-delimited), so a request
	// URI/param/referer that merely contains "status=421" doesn't inflate it.
	ehStatus421Re = regexp.MustCompile(`(?:^|\s)status=421(?:\s|$)`)
	// Warm-reuse signal: uct is the SINGLE value "0.000". A retried request logs
	// a comma-joined list (uct="0.000, 0.052") — a genuine fresh connect — which
	// this deliberately does NOT match (the quote must follow 0.000 directly).
	ehUctZeroRe = regexp.MustCompile(`uct="0\.000"`)
	ehKnobRe    = regexp.MustCompile(`origin_keepalive\s*=\s*(true|false)`)
	ehDigitsRe  = regexp.MustCompile(`^(\d+)`)
	// The edge writes msec=<unix epoch with millis> on every access line
	// (log_format cfm). We use the integer seconds to age a 421 against now,
	// which is timezone-proof (unlike the human ts="…" field).
	ehMsecRe = regexp.MustCompile(`(?:^|\s)msec=(\d+)`)
)

// nativeKeepaliveDefaultVer is the first nginx version where upstream keepalive
// is ON by default (and SNI-blind). See docs/proxy-performance.md.
var nativeKeepaliveDefaultVer = []int{1, 29, 7}

const (
	edgeHealthDefaultWindow = 50_000
	edgeHealthMaxWindow     = 500_000
	edgeHealthErrWindow     = 20_000
	// A warm-reuse 421 older than this, with NONE newer, reads as a resolved
	// incident (warn) rather than a live one (critical). A real cross-SNI storm
	// under load emits many 421s/min, so 5 min can't miss a live one; keeping it
	// this short means the verdict flips to `warn` within ~5 min of a fix instead
	// of lingering `critical` while the pre-fix storm sits in the file tail.
	edgeHealth421FreshWindowSec int64 = 300 // 5 minutes
)

func handleSystemEdgeHealth(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	window := edgeHealthDefaultWindow
	if v := strings.TrimSpace(r.URL.Query().Get("window")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			window = n
		}
	}
	if window > edgeHealthMaxWindow {
		window = edgeHealthMaxWindow
	}
	_ = json.NewEncoder(w).Encode(buildEdgeHealthReport(r.Context(), window))
}

// buildEdgeHealthReport runs the Tier-1 checks and returns the response map.
// Split from the handler so tests exercise the correlation/severity logic with
// stubbed runners + log scanners, without the admin gate.
func buildEdgeHealthReport(ctx context.Context, window int) map[string]any {
	engine, version, _ := edgeHealthDetect(ctx)
	nginxBase, trap := nativeKeepaliveTrap(engine, version)
	knob, knobPath := readOriginKeepaliveKnob()

	sev := severityTracker{}
	findings := []map[string]any{}

	// ── Check B: 421 / SNI-mismatch fingerprint (access log) ────────────────────
	// Recency-aware: an edge restart/reload wipes the upstream keepalive pool, so
	// a cross-SNI 421 can only recur once pooling rebuilds. We therefore drive the
	// LIVE verdict off warm-reuse 421s inside a freshness window (msec epoch), not
	// the raw count — else a wide file-tail scan keeps re-reading the pre-fix 421
	// storm and reads `critical` for minutes after the fix already took hold.
	now := edgeHealthNow()
	freshCutoff := now - edgeHealth421FreshWindowSec
	total421, warm421, recentWarm421 := 0, 0, 0
	var newestWarmTS int64 // 0 ⇒ no warm 421 carried a parseable msec
	hostCounts := map[string]int{}
	accLog, accScanned, accErr := edgeHealthScanAccess(ctx, []string{"status=421"}, "", window, func(line string) {
		if !ehStatus421Re.MatchString(line) {
			return // "status=421" appeared in the URI/param/referer, not the status field
		}
		total421++
		warm := strings.Contains(line, "cfm_origin_https") && ehUctZeroRe.MatchString(line)
		if warm {
			warm421++
			if ts := parseMsecUnix(line); ts > 0 {
				if ts > newestWarmTS {
					newestWarmTS = ts
				}
				if ts >= freshCutoff {
					recentWarm421++
				}
			}
		}
		if m := ehHostRe.FindStringSubmatch(line); m != nil {
			h := strings.Trim(m[1], `",`)
			// Cap DISTINCT hosts, but keep counting hosts already in the map so a
			// wide (>cap) 421 spread still ranks the true worst offenders.
			if h != "" {
				if _, seen := hostCounts[h]; seen || len(hostCounts) < 4096 {
					hostCounts[h]++
				}
			}
		}
	})
	// A warm 421 is LIVE if one is inside the freshness window, OR if we could not
	// parse a timestamp from ANY warm line (newestWarmTS==0) — fail-safe toward
	// flagging rather than silently downgrading a real storm on a log format that
	// lacks msec. `warm421Live` also gates the engine-version-trap critical below.
	warm421Live := warm421 > 0 && (recentWarm421 > 0 || newestWarmTS == 0)
	warmEv := func() map[string]any {
		ev := map[string]any{
			"status_421_total": total421, "warm_reuse_421": warm421,
			"recent_warm_421": recentWarm421, "fresh_window_sec": edgeHealth421FreshWindowSec,
			"scanned_lines": accScanned, "log_file": accLog,
			"top_hosts": topHosts(hostCounts, 8),
		}
		if newestWarmTS > 0 {
			ev["newest_warm_421_unix"] = newestWarmTS
			ev["newest_warm_421_age_sec"] = now - newestWarmTS
		}
		return ev
	}
	switch {
	case accErr != nil:
		findings = append(findings, sev.add("origin-421-fingerprint", "unknown",
			"could not read the edge access log", map[string]any{
				"error": accErr.Error(), "available_logs": edgelog.AvailableLogs(),
			}, "check edge access-log presence/permissions"))
	case warm421Live:
		note := ""
		if newestWarmTS == 0 {
			note = " (timestamps unavailable — treating as live)"
		}
		findings = append(findings, sev.add("origin-421-fingerprint", "critical",
			itoa(warm421)+" warm-reuse 421s (uct≈0 via cfm_origin_https) in the last "+itoa(accScanned)+" access lines — the cross-SNI 443-reuse signature; "+itoa(recentWarm421)+" in the last "+itoa(int(edgeHealth421FreshWindowSec/60))+"m"+note,
			warmEv(), "verify 443 origin reuse is off at every layer (origin-config-invariant, edge_error_tail)"))
	case warm421 > 0:
		// Warm-reuse 421s exist but ALL are older than the freshness window: the
		// incident is in the file tail but has stopped (fix/restart took hold).
		// Report `warn` — visible, decays to ok as they scroll out — not `critical`.
		findings = append(findings, sev.add("origin-421-fingerprint", "warn",
			itoa(warm421)+" warm-reuse 421s in the scanned window but NONE in the last "+itoa(int(edgeHealth421FreshWindowSec/60))+"m (newest "+itoa(int((now-newestWarmTS)/60))+"m ago) — the cross-SNI 443-reuse incident appears resolved; confirm keepalive 0 + proxy_ssl_session_reuse off is live so it can't recur",
			warmEv(), "confirm the origin-hop SNI-safety config is applied + reloaded (check_origin_ka_config.sh, edge_error_tail)"))
	case total421 > 0:
		findings = append(findings, sev.add("origin-421-fingerprint", "warn",
			itoa(total421)+" status=421 in the last "+itoa(accScanned)+" access lines, but none with the warm-reuse signature — may be a genuinely misconfigured vhost, not pooling",
			map[string]any{
				"status_421_total": total421, "warm_reuse_421": 0,
				"scanned_lines": accScanned, "log_file": accLog,
				"top_hosts": topHosts(hostCounts, 8),
			}, "inspect the 421 hosts' SSL vhost config on the origin"))
	default:
		findings = append(findings, sev.add("origin-421-fingerprint", "ok",
			"no status=421 in the last "+itoa(accScanned)+" access lines", map[string]any{
				"scanned_lines": accScanned, "log_file": accLog,
			}, ""))
	}

	// ── Check A: engine + version trap ──────────────────────────────────────────
	aEv := map[string]any{
		"engine": engine, "version": version, "nginx_base": nginxBase,
		"native_keepalive_default_on": trap, "origin_keepalive_knob": knob,
	}
	switch {
	case engine == "":
		findings = append(findings, sev.add("engine-version-trap", "unknown",
			"could not detect the active edge engine/version", aEv, "check that angie/openresty is running"))
	case (strings.EqualFold(engine, "openresty") || strings.EqualFold(engine, "nginx")) && nginxBase == "":
		// Engine known but version unreadable: we CANNOT rule out the
		// nginx>=1.29.7 native-keepalive trap, so this is "unknown", never "ok"
		// (an all-clear here would mask the exact 421 root cause).
		findings = append(findings, sev.add("engine-version-trap", "unknown",
			engineLabel(engine, version)+": version unreadable — cannot confirm whether native upstream keepalive is default-on (nginx ≥ 1.29.7); the 443-reuse trap cannot be ruled out",
			aEv, "check the edge binary path / `-v` output; verify `keepalive 0` on cfm_origin_* regardless"))
	case trap && knob == "true" && warm421Live:
		findings = append(findings, sev.add("engine-version-trap", "critical",
			engineLabel(engine, version)+": native upstream keepalive is ON by default and SNI-blind, ORIGIN_KEEPALIVE is on, and LIVE warm-reuse 421s are present — classic 443 cross-SNI reuse",
			aEv, "ensure `keepalive 0` on cfm_origin_* (OpenResty) + proxy_ssl_session_reuse off; deploy + edge reload"))
	case trap && knob == "true":
		// Knob on, no LIVE warm-reuse 421s (either none at all, or only a resolved
		// storm still in the file tail — Check B reports that separately). The
		// 443-reuse CLASS applies, but Tier-1 cannot verify the SNI-safety config
		// invariant (keepalive 0 / proxy_ssl_session_reuse off) — that is the CI
		// gate + Tier-2's job. Report the exposure informatively, NOT as `warn`:
		// warning here would fire forever on every correctly-configured node (cry
		// wolf), and anything wiring whats_wrong on `overall` would too.
		findings = append(findings, sev.add("engine-version-trap", "ok",
			engineLabel(engine, version)+": native keepalive default-on & SNI-blind, ORIGIN_KEEPALIVE on, no live cross-SNI 421s — the SNI-safety config MUST be present; this Tier-1 check does not verify it (check_origin_ka_config.sh / edge_health Tier-2 does)",
			aEv, ""))
	case trap && knob == "false":
		findings = append(findings, sev.add("engine-version-trap", "ok",
			engineLabel(engine, version)+": native keepalive default-on, but ORIGIN_KEEPALIVE is off — origin traffic is not routed through cfm_origin_*, so nothing pools",
			aEv, ""))
	case trap:
		// knob == "unknown": the bridge config couldn't be read, so we can't
		// confirm whether origin traffic is pooled — never an all-clear.
		findings = append(findings, sev.add("engine-version-trap", "unknown",
			engineLabel(engine, version)+": native keepalive default-on & SNI-blind, but the ORIGIN_KEEPALIVE knob state could not be read — cannot confirm whether origin traffic is routed through cfm_origin_*",
			aEv, "check /var/lib/cfm/lua/cfm_bridge_config.lua"))
	default:
		findings = append(findings, sev.add("engine-version-trap", "ok",
			engineLabel(engine, version)+": native upstream keepalive not default-on for this engine/version",
			aEv, ""))
	}

	// ── Check C: [cfm_origin_ka] tiers (edge error log) ─────────────────────────
	tiers := map[string]int{}
	classify := func(line string) {
		switch {
		case strings.Contains(line, "ngx.balancer unavailable"):
			tiers["balancer_unavailable"]++
		case strings.Contains(line, "cfm_origin_ka load failed"):
			tiers["module_load_failed"]++
		case strings.Contains(line, "HTTP(80) origin pooling active"):
			tiers["http80_pooling_active"]++
		case strings.Contains(line, "origin port 443: per-request"):
			tiers["https443_per_request"]++
		case strings.Contains(line, "keepalive-race retry is unavailable"):
			tiers["degraded_no_retry"]++
		case strings.Contains(line, "engine lacks balancer.enable_keepalive"),
			strings.Contains(line, "enable_keepalive raised"),
			strings.Contains(line, "enable_keepalive failed"):
			tiers["degraded_unpooled_80"]++
		}
	}
	// The fatal load-failure line is tagged `[cfm]`, not `[cfm_origin_ka]`, so it
	// needs its own pre-filter substring or scanLog would drop it before classify.
	errLog, _, errErr := edgeHealthScanError(ctx, []string{"[cfm_origin_ka]", "cfm_origin_ka load failed"}, "", edgeHealthErrWindow, classify)
	cEv := map[string]any{"tiers": tiers, "log_file": errLog}
	switch {
	case errErr != nil:
		findings = append(findings, sev.add("origin-ka-tier", "unknown",
			"could not read the edge error log", map[string]any{
				"error": errErr.Error(), "available_logs": edgelog.AvailableErrorLogs(),
			}, ""))
	case tiers["balancer_unavailable"] > 0:
		findings = append(findings, sev.add("origin-ka-tier", "critical",
			"ngx.balancer is unavailable in some workers — every origin request through the cfm_origin_* upstreams fails (502/ngx.exit ERROR)", cEv,
			"edge_error_tail grep=cfm_origin_ka; check the lua-resty-core/balancer module"))
	case tiers["module_load_failed"] > 0:
		findings = append(findings, sev.add("origin-ka-tier", "critical",
			"cfm_origin_ka failed to load in some workers — the balancer_by_lua fell back to inline set_current_peer", cEv,
			"edge_error_tail grep=cfm_origin_ka; validate the Lua and reload"))
	case tiers["degraded_unpooled_80"] > 0 || tiers["degraded_no_retry"] > 0:
		findings = append(findings, sev.add("origin-ka-tier", "warn",
			"cfm_origin_ka is running degraded on some workers (see tiers)", cEv, "edge_error_tail grep=cfm_origin_ka"))
	default:
		// No degraded/failed tiers. An EMPTY tiers map is NOT a problem: the
		// activation lines are once-per-worker and age out of the live error log
		// (logrotate reopen, or > the scan window), so their absence is not
		// evidence the module is inactive — only a genuine degradation is.
		findings = append(findings, sev.add("origin-ka-tier", "ok",
			"cfm_origin_ka reporting no degradation (activation lines are once-per-worker and may have aged out of the window; the knob may also be off)", cEv, ""))
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return sevRank(findings[i]["severity"].(string)) > sevRank(findings[j]["severity"].(string))
	})

	return map[string]any{
		"ok":                      true,
		"schema":                  "system.edge_health.v1",
		"engine":                  engine,
		"version":                 version,
		"nginx_base":              nginxBase,
		"native_keepalive_trap":   trap,
		"origin_keepalive_knob":   knob,
		"origin_keepalive_source": knobPath,
		"overall":                 sev.overall(),
		"findings":                findings,
	}
}

// nativeKeepaliveTrap reports the underlying nginx base version (best-effort) and
// whether native upstream keepalive is ON by default on this engine/version.
//   - OpenResty A.B.C.D → nginx base A.B.C; trap = base ≥ 1.29.7.
//   - bare nginx → trap = version ≥ 1.29.7.
//   - Angie → trap = false: Angie deliberately did NOT adopt nginx 1.29.7's
//     default-on change (keepalive `Default: —`) and even rejects `keepalive 0`.
func nativeKeepaliveTrap(engine, version string) (nginxBase string, trap bool) {
	if strings.EqualFold(engine, "angie") {
		return "", false
	}
	nums := parseDottedInts(versionNumeric(version))
	if len(nums) < 3 {
		return "", false
	}
	base := nums[:3]
	nginxBase = itoa(base[0]) + "." + itoa(base[1]) + "." + itoa(base[2])
	return nginxBase, geVersion(base, nativeKeepaliveDefaultVer)
}

// versionNumeric strips a leading "name/" prefix, e.g. "openresty/1.31.1.1" →
// "1.31.1.1", "1.27.5" → "1.27.5".
func versionNumeric(v string) string {
	if i := strings.LastIndex(v, "/"); i >= 0 {
		return v[i+1:]
	}
	return v
}

func parseDottedInts(s string) []int {
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		m := ehDigitsRe.FindStringSubmatch(strings.TrimSpace(p))
		if m == nil {
			break
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// geVersion reports a ≥ b, comparing component-by-component.
func geVersion(a, b []int) bool {
	for i := 0; i < len(b); i++ {
		av := 0
		if i < len(a) {
			av = a[i]
		}
		if av != b[i] {
			return av > b[i]
		}
	}
	return true
}

// ── ORIGIN_KEEPALIVE knob (published bridge config) ────────────────────────────

func readOriginKeepaliveKnob() (state, path string) {
	for _, p := range edgeHealthBridgeConfigPaths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := ehKnobRe.FindStringSubmatch(string(b)); m != nil {
			return m[1], p
		}
	}
	return "unknown", ""
}

// ── helpers ────────────────────────────────────────────────────────────────────

func engineLabel(engine, version string) string {
	if version == "" {
		return engine
	}
	return engine + " (" + version + ")"
}

func itoa(n int) string { return strconv.Itoa(n) }

// parseMsecUnix extracts the integer Unix seconds from an edge access line's
// msec=<epoch> field. Returns 0 when absent/unparseable so the caller can
// fail-safe (treat unknown recency as live).
func parseMsecUnix(line string) int64 {
	m := ehMsecRe.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func topHosts(counts map[string]int, n int) []map[string]any {
	type kv struct {
		host string
		n    int
	}
	arr := make([]kv, 0, len(counts))
	for h, c := range counts {
		arr = append(arr, kv{h, c})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].n != arr[j].n {
			return arr[i].n > arr[j].n
		}
		return arr[i].host < arr[j].host
	})
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		out = append(out, map[string]any{"host": e.host, "count": e.n})
	}
	return out
}

// severityTracker accumulates the max severity across findings.
type severityTracker struct{ max int }

func (s *severityTracker) add(check, severity, summary string, evidence map[string]any, next string) map[string]any {
	if r := sevRank(severity); r > s.max {
		s.max = r
	}
	m := map[string]any{"check": check, "severity": severity, "summary": summary, "evidence": evidence}
	if next != "" {
		m["next"] = next
	}
	return m
}

func (s *severityTracker) overall() string { return sevName(s.max) }

func sevRank(name string) int {
	switch name {
	case "critical":
		return 3
	case "warn":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

func sevName(rank int) string {
	switch rank {
	case 3:
		return "critical"
	case 2:
		return "warn"
	case 1:
		return "unknown"
	default:
		return "ok"
	}
}
