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
//   E. origin premature-close / gateway-5xx rate from the edge access log —
//      the "the origin is dying under us" class (see below).
// See docs/edge-health.md for the design and the Tier-2/3 follow-ups (live
// config-invariant, Apache AH02032 correlation, latency split).
//
// Check E was added after a 2026-09 incident on an Angie→Apache node where
// mod_brotli segfaulted the Apache workers: ~900 requests/day across dozens of
// vhosts died with `upstream prematurely closed connection`, and NOTHING
// surfaced it. whats_wrong reported only an unrelated flapping unit, so the
// 502s were found by a human who happened to be browsing one of the sites.
// The discriminator is `uht="-"` on a gateway-class status WITH a real `uaddr=`:
// the edge selected an origin peer and never got a response header back. That
// covers both shapes of an origin-hop fault — a connection accepted then dropped
// (the incident above) and one that never became usable (connect/TLS failure) —
// while excluding responses the edge produced by itself (challenge, block, admin
// error page), which also log `uht="-"` but name no peer. An application 500
// always carries a header, so this subset isolates "the origin failed us" from
// "the app returned an error" — and it is ~0 on a healthy node.
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
	// ehStatusRe reads the real status field — but ONLY ever from a line with
	// its quoted values blanked out (stripQuoted), never from the raw line.
	// log_format cfm carries several client-controlled values, and nginx does
	// not escape spaces inside them, so a status-shaped token can be injected:
	// `CF-Connecting-IP: 0 status=502 0` lands in `cf="…"` THREE fields BEFORE
	// the real status=, and an aborted request logs uht="-" with a real peer.
	// ~100 such requests would manufacture a critical origin-drop verdict that
	// now propagates into whats_wrong. Reading only unquoted text closes it for
	// every such field at once (cf=, ua=, referer=, uri= when quoted), because
	// nginx escapes a literal `"` inside a value as \x22 — so a client can
	// never break out of the quotes. The unquoted fields ahead of status= are
	// server-generated or space-free (a raw space in $request_uri cannot survive
	// request-line parsing), so nothing can inject an earlier token there.
	ehStatusRe = regexp.MustCompile(`(?:^|\s)status=(\d{3})(?:\s|$)`)
	// Warm-reuse signal: uct is the SINGLE value "0.000". A retried request logs
	// a comma-joined list (uct="0.000, 0.052") — a genuine fresh connect — which
	// this deliberately does NOT match (the quote must follow 0.000 directly).
	ehUctZeroRe = regexp.MustCompile(`uct="0\.000"`)
	ehKnobRe    = regexp.MustCompile(`origin_keepalive\s*=\s*(true|false)`)
	ehDigitsRe  = regexp.MustCompile(`^(\d+)`)
	// uht carries ONE value per upstream attempt, comma-joined. The leading
	// `(?:^|\s)uht="` anchor is injection-proof on its own: a client cannot emit
	// a literal `"` into a logged value (nginx escapes it as \x22), so this can
	// only ever match the real field. See noResponseHeader for why every element
	// must be "-" rather than the whole value being the single string "-".
	ehUhtRe = regexp.MustCompile(`(?:^|\s)uht="([^"]*)"`)
	// uaddr names the upstream peer the edge selected. It is "-" (or absent)
	// when NO upstream was ever contacted — an edge-synthesised response such as
	// a challenge page, a block, or the admin upstream-error page while the
	// daemon restarts. Requiring a real peer is what keeps Check E about the
	// ORIGIN hop: a connect/TLS failure still names its peer (nginx sets
	// $upstream_addr once a peer is chosen) and correctly counts, while a
	// response the edge produced by itself never does.
	ehUaddrRe = regexp.MustCompile(`(?:^|\s)uaddr=(\S+)`)
	// The edge ERROR log opens each line with local-time "YYYY/MM/DD HH:MM:SS".
	// Unlike the access log there is no epoch field, so this is the only way to
	// age a tier line.
	ehErrTSRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)
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

	// ── Check E thresholds ────────────────────────────────────────────────────
	// Calibrated against the fleet on 2026-09-19. On the incident node ~916
	// premature closes landed in a day against ~1.3M requests ≈ 0.07%; every
	// healthy node measured 0–2 in a 20k-line window (≈0.0001%). So the warn
	// rate sits ~3x under the incident and ~200x over healthy noise, and the
	// crit rate marks a genuine outage (1 request in 500 losing its origin).
	//
	// The absolute floor is what keeps this honest on a quiet node: a 2-line
	// window with one drop is 50%, not an incident. Rate AND floor must both
	// be met, so low-traffic nodes can't rate-spike into a false finding.
	edgeHealthOriginDropMinEvents            = 10
	edgeHealthOriginDropWarnRate             = 0.0002 // 0.02% of scanned requests
	edgeHealthOriginDropCritRate             = 0.002  // 0.2%
	edgeHealthOriginDropFreshWindowSec int64 = 900    // 15 minutes

	// Check C freshness. A fatal cfm_origin_ka tier is WORKER-LIFETIME, not
	// per-request: the module loads once at worker start, so an old line can
	// still describe a live condition if the edge has not been reloaded since.
	// It is therefore degraded to `warn` when stale — never to `ok` — with the
	// age spelled out. Without this the line stays a PERMANENT critical for as
	// long as it sits in the error-log tail, which (now that Check C feeds
	// whats_wrong) is exactly the cry-wolf failure Checks B and E avoid. The
	// acute symptom of a genuinely-still-broken module is a 502 storm, and
	// Check E carries that as its own critical, so nothing is hidden.
	edgeHealthOriginKAFreshWindowSec int64 = 6 * 3600 // 6 hours
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

	// Check E accumulators. They ride the SAME access-log pass as the 421
	// fingerprint — one tail of a multi-GB log, two checks — so adding this
	// check costs no extra I/O.
	gateway5xx, originDrop, recentDrops := 0, 0, 0
	dropByStatus := map[string]int{}
	dropHosts := map[string]int{}
	var newestDropTS int64 // 0 ⇒ no drop carried a parseable msec
	dropFreshCutoff := now - edgeHealthOriginDropFreshWindowSec

	accLog, accScanned, accErr := edgeHealthScanAccess(ctx,
		[]string{"status=421", "status=502", "status=503", "status=504"}, "", window, func(line string) {
			// Resolve the real status ONCE per line. The two checks then key off
			// the same parsed value, which also makes their branches provably
			// disjoint (a line carries exactly one status).
			status := lineStatus(line)
			switch status {
			case "502", "503", "504":
				gateway5xx++
				// Both conditions are required: no response header came back AND
				// the edge actually selected an origin peer (see ehUaddrRe).
				if noResponseHeader(line) && hasUpstreamPeer(line) {
					originDrop++
					dropByStatus[status]++
					if ts := parseMsecUnix(line); ts > 0 {
						if ts > newestDropTS {
							newestDropTS = ts
						}
						if ts >= dropFreshCutoff {
							recentDrops++
						}
					}
					countHost(dropHosts, line)
				}
			case "421":
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
				countHost(hostCounts, line)
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

	// ── Check E: origin premature-close / gateway 5xx ──────────────────────────
	// Deliberately skipped when the access log could not be read: Check B already
	// reported that as `unknown`, and a second copy of the same failure is noise.
	if accErr == nil {
		dropRate := 0.0
		if accScanned > 0 {
			dropRate = float64(originDrop) / float64(accScanned)
		}
		// Live unless every drop is older than the freshness window. As with the
		// 421 check, unparseable timestamps fail SAFE (treated as live) so a log
		// format without msec can't silently downgrade a real incident.
		dropLive := recentDrops > 0 || (originDrop > 0 && newestDropTS == 0)
		eEv := func() map[string]any {
			ev := map[string]any{
				"origin_no_response_header": originDrop,
				"gateway_5xx_total":         gateway5xx,
				"by_status":                 dropByStatus,
				"rate_pct":                  pct3(dropRate),
				"recent_drops":              recentDrops,
				"fresh_window_sec":          edgeHealthOriginDropFreshWindowSec,
				"distinct_hosts":            len(dropHosts),
				"top_hosts":                 topHosts(dropHosts, 8),
				"scanned_lines":             accScanned,
				"log_file":                  accLog,
			}
			if newestDropTS > 0 {
				ev["newest_drop_unix"] = newestDropTS
				ev["newest_drop_age_sec"] = now - newestDropTS
			}
			return ev
		}
		// A spread across many vhosts indicts the ORIGIN itself (crashing workers,
		// exhausted pool); a single vhost indicts that app. Saying which one up
		// front is what turns this finding into a starting point.
		scope := "across " + itoa(len(dropHosts)) + " vhosts — an origin-wide fault"
		if len(dropHosts) == 1 {
			scope = "all on a single vhost — likely that app, not the origin"
		}
		const dropNext = "edge_error_tail grep=\"upstream prematurely closed\" for the failing hosts, then dmesg_tail grep=segfault (a crashing origin worker) and service_status for the origin daemon"

		switch {
		case originDrop == 0:
			// Same evidence shape as every other branch (one check, one contract):
			// a reader gets origin_no_response_header:0 explicitly rather than a
			// missing key they have to interpret.
			findings = append(findings, sev.add("origin-premature-close", "ok",
				"no gateway 5xx without a response header from a selected origin peer in the last "+itoa(accScanned)+" access lines",
				eEv(), ""))
		case originDrop >= edgeHealthOriginDropMinEvents && dropRate >= edgeHealthOriginDropCritRate && dropLive:
			findings = append(findings, sev.add("origin-premature-close", "critical",
				itoa(originDrop)+" of "+itoa(accScanned)+" requests ("+pct3(dropRate)+"%) got a gateway 5xx with NO response header from the selected origin peer, "+scope+"; "+itoa(recentDrops)+" in the last "+itoa(int(edgeHealthOriginDropFreshWindowSec/60))+"m — the origin is failing the requests the edge hands it",
				eEv(), dropNext))
		case originDrop >= edgeHealthOriginDropMinEvents && dropRate >= edgeHealthOriginDropWarnRate && dropLive:
			findings = append(findings, sev.add("origin-premature-close", "warn",
				itoa(originDrop)+" of "+itoa(accScanned)+" requests ("+pct3(dropRate)+"%) got a gateway 5xx with NO response header from the selected origin peer, "+scope+"; "+itoa(recentDrops)+" in the last "+itoa(int(edgeHealthOriginDropFreshWindowSec/60))+"m. A healthy origin answers with a header even when the app errors, so these are failed origin connections, not application 500s",
				eEv(), dropNext))
		case originDrop >= edgeHealthOriginDropMinEvents && dropRate >= edgeHealthOriginDropWarnRate:
			// Present in the window but all older than the freshness window: the
			// incident appears to have stopped. Visible as `warn`, decaying to ok
			// as the lines scroll out — same posture as the resolved-421 case.
			findings = append(findings, sev.add("origin-premature-close", "warn",
				itoa(originDrop)+" origin premature-closes in the scanned window but NONE in the last "+itoa(int(edgeHealthOriginDropFreshWindowSec/60))+"m (newest "+itoa(int((now-newestDropTS)/60))+"m ago) — the origin fault appears to have stopped; confirm what fixed it so it can't silently return",
				eEv(), dropNext))
		default:
			// Below the floor and/or the rate: a handful of dropped connections is
			// normal background on a busy box (an origin restart, a killed worker).
			// Reporting it would cry wolf on every healthy node.
			findings = append(findings, sev.add("origin-premature-close", "ok",
				itoa(originDrop)+" origin premature-closes in the last "+itoa(accScanned)+" access lines ("+pct3(dropRate)+"%) — below the "+itoa(edgeHealthOriginDropMinEvents)+"-event / "+pct3(edgeHealthOriginDropWarnRate)+"% reporting floor",
				eEv(), ""))
		}
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
	// Recency is tracked PER TIER, not as one max across tiers: the switch below
	// reports whichever problem tier matches first, so a shared "newest" would
	// let a fresh module_load_failed grade an already-fixed, 10h-old
	// balancer_unavailable as a live critical — wrong severity AND wrong root
	// cause. tierNoTS marks a tier whose line carried no parseable timestamp,
	// which fails safe to "fresh".
	tierTS := map[string]int64{}
	tierNoTS := map[string]bool{}
	classify := func(line string) {
		key := ""
		switch {
		case strings.Contains(line, "ngx.balancer unavailable"):
			tiers["balancer_unavailable"]++
			key = "balancer_unavailable"
		case strings.Contains(line, "cfm_origin_ka load failed"):
			tiers["module_load_failed"]++
			key = "module_load_failed"
		case strings.Contains(line, "HTTP(80) origin pooling active"):
			tiers["http80_pooling_active"]++
		case strings.Contains(line, "origin port 443: per-request"):
			tiers["https443_per_request"]++
		case strings.Contains(line, "keepalive-race retry is unavailable"):
			tiers["degraded_no_retry"]++
			key = "degraded_no_retry"
		case strings.Contains(line, "engine lacks balancer.enable_keepalive"),
			strings.Contains(line, "enable_keepalive raised"),
			strings.Contains(line, "enable_keepalive failed"):
			tiers["degraded_unpooled_80"]++
			key = "degraded_unpooled_80"
		}
		if key == "" {
			return // an activation tier — nothing to age
		}
		// Fail safe, as everywhere else here: an unparseable timestamp counts as
		// fresh rather than silently downgrading a live fault.
		if ts := parseErrorLogUnix(line); ts > 0 {
			if ts > tierTS[key] {
				tierTS[key] = ts
			}
		} else {
			tierNoTS[key] = true
		}
	}
	// The fatal load-failure line is tagged `[cfm]`, not `[cfm_origin_ka]`, so it
	// needs its own pre-filter substring or scanLog would drop it before classify.
	errLog, _, errErr := edgeHealthScanError(ctx, []string{"[cfm_origin_ka]", "cfm_origin_ka load failed"}, "", edgeHealthErrWindow, classify)
	// tierFresh reports whether THIS tier's newest line is inside the window (or
	// carried no parseable timestamp → fail safe to fresh).
	tierFresh := func(key string) bool {
		if tierNoTS[key] {
			return true
		}
		ts := tierTS[key]
		return ts > 0 && ts >= now-edgeHealthOriginKAFreshWindowSec
	}
	tierAgeHours := func(key string) int { return int((now - tierTS[key]) / 3600) }
	cEv := map[string]any{"tiers": tiers, "log_file": errLog}
	if len(tierTS) > 0 {
		ages := map[string]int64{}
		for k, ts := range tierTS {
			ages[k] = now - ts
		}
		cEv["tier_age_sec"] = ages
	}
	// staleNote spells out that old evidence is NOT the same as a fixed fault:
	// these lines are once-per-worker, so the condition stays live until reload.
	staleNote := func(key string) string {
		return " — NOTE: newest such line is " + itoa(tierAgeHours(key)) +
			"h old, so it is downgraded rather than reported at full severity; these lines are written once per worker, so if the edge has NOT been reloaded since, the condition is still live (the acute symptom, a 502 storm, would surface as origin-premature-close)"
	}
	// fatalFinding grades a fatal tier: fresh ⇒ critical, stale ⇒ warn. Never
	// `ok` — a stale fatal line can still describe a live fault.
	fatalFinding := func(key, summary, next string) map[string]any {
		if tierFresh(key) {
			return sev.add("origin-ka-tier", "critical", summary, cEv, next)
		}
		return sev.add("origin-ka-tier", "warn", summary+staleNote(key), cEv, next)
	}
	switch {
	case errErr != nil:
		findings = append(findings, sev.add("origin-ka-tier", "unknown",
			"could not read the edge error log", map[string]any{
				"error": errErr.Error(), "available_logs": edgelog.AvailableErrorLogs(),
			}, ""))
	case tiers["balancer_unavailable"] > 0:
		findings = append(findings, fatalFinding("balancer_unavailable",
			"ngx.balancer is unavailable in some workers — every origin request through the cfm_origin_* upstreams fails (502/ngx.exit ERROR)",
			"edge_error_tail grep=cfm_origin_ka; check the lua-resty-core/balancer module"))
	case tiers["module_load_failed"] > 0:
		findings = append(findings, fatalFinding("module_load_failed",
			"cfm_origin_ka failed to load in some workers — the balancer_by_lua fell back to inline set_current_peer",
			"edge_error_tail grep=cfm_origin_ka; validate the Lua and reload"))
	case tiers["degraded_unpooled_80"] > 0 || tiers["degraded_no_retry"] > 0:
		// Degraded tiers are once-per-worker too, so they need the same ageing or
		// they sit in whats_wrong as a permanent warning until they scroll out of
		// the error-log window — weeks on a quiet node. Unlike a fatal tier these
		// describe a CAPABILITY gap the edge tolerates (traffic still flows, just
		// unpooled or without the keepalive-race retry), so stale evidence drops
		// out of triage rather than being downgraded one step: it stays fully
		// visible here in the summary, the tiers map and tier_age_sec.
		key := "degraded_unpooled_80"
		if tiers["degraded_no_retry"] > 0 && tierTS["degraded_no_retry"] > tierTS[key] {
			key = "degraded_no_retry"
		}
		if tierFresh(key) {
			findings = append(findings, sev.add("origin-ka-tier", "warn",
				"cfm_origin_ka is running degraded on some workers (see tiers)", cEv, "edge_error_tail grep=cfm_origin_ka"))
		} else {
			findings = append(findings, sev.add("origin-ka-tier", "ok",
				"cfm_origin_ka logged a degraded tier (see tiers) but the newest such line is "+itoa(tierAgeHours(key))+
					"h old; these are once-per-worker lines, so this is stale evidence of a capability gap rather than a live fault — re-check with edge_error_tail if the edge has not been reloaded since",
				cEv, ""))
		}
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

// pct3 renders a 0..1 ratio as a percentage string with 3 decimals ("0.071").
// Fixed notation, not %g: origin-drop rates live in the hundredths of a percent,
// where %g would render "7.1e-02" and 2 decimals would round a real incident to
// a reassuring "0.07" — or to "0.00" one order of magnitude down.
func pct3(ratio float64) string { return strconv.FormatFloat(ratio*100, 'f', 3, 64) }

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

// stripQuoted blanks every "…" region so no client-controlled field VALUE can
// contribute a token to a field-level match. nginx escapes a literal `"` inside
// a value as \x22, so quote parity is unambiguous. Length is preserved (each
// suppressed byte becomes a space) purely so offsets stay comparable.
func stripQuoted(line string) string {
	var b strings.Builder
	b.Grow(len(line))
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			b.WriteByte(' ')
			continue
		}
		if inQuote {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// lineStatus returns the request's real status code, read from outside any
// quoted value. "" when the line carries no status field.
func lineStatus(line string) string {
	if m := ehStatusRe.FindStringSubmatch(stripQuoted(line)); m != nil {
		return m[1]
	}
	return ""
}

// noResponseHeader reports whether NO upstream attempt returned a response
// header. nginx logs one uht value per attempt, comma-joined, and
// cfm_origin_ka arms set_more_tries(1) on every POOLED port-80 origin request
// — so `uht="-, -"` is the normal shape of a failed request on that path, not
// an exotic one. Matching only the single-valued `uht="-"` would miss it
// entirely and report `ok` through exactly the outage this check exists to
// catch. A retry that DID get a header (`uht="-, 0.412"`) is not a drop: the
// client was served, so every element must be "-".
func noResponseHeader(line string) bool {
	m := ehUhtRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	for _, p := range strings.Split(m[1], ",") {
		if strings.TrimSpace(p) != "-" {
			return false
		}
	}
	return true
}

// hasUpstreamPeer reports whether the edge selected an upstream peer for this
// request — i.e. uaddr names a real address rather than "-"/absent. See
// ehUaddrRe for why Check E requires it.
func hasUpstreamPeer(line string) bool {
	m := ehUaddrRe.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	// With a retry the field is `uaddr=a, a`; \S+ captures the first element,
	// which is all we need — any real peer means an origin hop was attempted.
	v := strings.Trim(m[1], `",`)
	return v != "" && v != "-"
}

// countHost tallies an access line's host= field into counts. It caps the
// number of DISTINCT hosts but keeps counting hosts already in the map, so a
// spread wider than the cap still ranks the true worst offenders (and a
// 10k-vhost box can't turn one bad deploy into an unbounded allocation).
func countHost(counts map[string]int, line string) {
	m := ehHostRe.FindStringSubmatch(line)
	if m == nil {
		return
	}
	h := strings.Trim(m[1], `",`)
	if h == "" {
		return
	}
	if _, seen := counts[h]; seen || len(counts) < 4096 {
		counts[h]++
	}
}

// parseErrorLogUnix extracts Unix seconds from an edge ERROR log line's leading
// "YYYY/MM/DD HH:MM:SS" stamp, which nginx/Angie write in LOCAL time. Returns 0
// when absent/unparseable so the caller can fail safe (treat it as fresh).
func parseErrorLogUnix(line string) int64 {
	m := ehErrTSRe.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	t, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
	if err != nil {
		return 0
	}
	return t.Unix()
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
