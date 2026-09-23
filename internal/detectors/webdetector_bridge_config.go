package detectors

import (
	"time"

	"cfm/internal/sslcollector"
)

// webdetectorBridgeConfig builds the webdetector → edge-Lua runtime knobs
// (/var/lib/cfm/lua/cfm_bridge_config.lua) from the global and [webdetector]
// sections of detectors.conf: each knob's default lives HERE, and the Lua
// reader (cfm_bridge_cfg.lua) applies the same default to an absent field.
// Split out of Manager start so the defaults are unit-tested
// (webdetector_bridge_config_test.go), SITE_CACHE and MICRO_CACHE_ENFORCE
// among them. One deliberate asymmetry: the Lua reader keeps
// micro_cache_enforce OFF for an absent field. Every file the daemon writes
// carries it, so the field is absent only in a file from an older daemon, or
// when there is no readable file (never written: the base detectors.conf has
// no [webdetector]); then the edge stays in dry run.
func webdetectorBridgeConfig(global, wdKV map[string]string) sslcollector.WebdetectorBridgeConfig {
	cfg := sslcollector.WebdetectorBridgeConfig{
		ClearanceRefresh: kvBool(wdKV, "CHALLENGE_COOKIE_REFRESH", true),
		// Origin keepalive (edge → Apache backend connection pooling).
		// Default off; see docs/proxy-performance.md before arming.
		OriginKeepalive: kvBool(wdKV, "ORIGIN_KEEPALIVE", false),
		OriginKAIdleSec: kvInt(wdKV, "ORIGIN_KEEPALIVE_IDLE_SEC", 3),
		OriginKAMaxReqs: kvInt(wdKV, "ORIGIN_KEEPALIVE_MAX_REQS", 1000),
		// Authoritative clearance-cookie lifetime — SAME resolver the
		// webdetector register uses for SetCookieLife, so the edge Lua
		// re-mint TTL can never drift from what the daemon mints.
		CookieLifeSec: int(resolveChallengeCookieLife(global, wdKV) / time.Second),
		// Panel enforce modes (off|logonly|enforce). Default ENFORCE:
		// the fleet runs panel WAF + bridge-decision enforcement on by
		// default; a node that misbehaves sets PANEL_*_MODE=off|logonly
		// there. Missing/unknown → enforce (token.go re-normalises, and
		// cfm_panel.lua's resolver defaults to enforce for an absent field
		// too). kvStrClean tolerates an inline ;/# comment (§5).
		PanelWAFMode:      kvStrClean(wdKV, "PANEL_WAF_MODE", "enforce"),
		PanelDecisionMode: kvStrClean(wdKV, "PANEL_DECISION_MODE", "enforce"),
		// Panel-port consult of the fleet-armed fingerprint policy
		// (master plan item): an operator-armed fp `deny` covers the
		// panel ports too. Same off|logonly|enforce ladder and
		// enforce default as its siblings; FP_POLICY=0 still kills
		// the whole consult regardless of this mode.
		PanelFPPolicyMode: kvStrClean(wdKV, "PANEL_FP_POLICY_MODE", "enforce"),
		// Post-clearance nav-cadence shadow (cfm_pcw, Track-2 B2). Edge
		// LOG-ONLY measurement; default on. Replaces the CFM_PCW env
		// kill-switch so the toggle is config-driven (POST_CLEARANCE_CADENCE=0
		// disables) and applies within ~10s without a proxy reload.
		PostClearanceCadence: kvBool(wdKV, "POST_CLEARANCE_CADENCE", true),
		// Fingerprint-policy edge gate. Same key the webdetector
		// registration feeds into ConfigureFingerprintPolicyEnforcement
		// (daemon-side answers); published here so FP_POLICY=0 also
		// removes the edge's whole Step-0c cost, not just its answers.
		FPPolicy: kvBool(wdKV, "FP_POLICY", true),
		// Site Cache master gate (per-vhost edge caching). Default ON,
		// but a pure KILL SWITCH — not a second opt-in: the per-vhost
		// policy store (default empty) is the only thing that arms a
		// vhost, so nothing caches until an operator arms one, master on
		// or not. SITE_CACHE=0 is the panic button: this node's edge stops
		// caching (no feed poll, no cache gate, no stamp, no stats push)
		// ~10s after this is written (~15s from saving detectors.conf),
		// without disarming any vhost, so re-arming is instant.
		SiteCache: kvBool(wdKV, "SITE_CACHE", true),
		// Tier B micro-cache ENFORCE gate (anonymous-page micro-caching).
		// Default ON since 2026-09-23, after the design §5.7 checklist passed
		// on a live WordPress vhost (virgo): like SITE_CACHE it is a kill
		// switch, and arming a vhost's micro tier is the opt-in (the store is
		// empty by default). MICRO_CACHE_ENFORCE=0 puts this node's micro tier
		// in DRY-RUN (verdict on the observe header, no ngx.exec, nothing
		// stored) without disarming any vhost.
		MicroCacheEnforce: kvBool(wdKV, "MICRO_CACHE_ENFORCE", true),
	}
	// Guard nonsense values; the Lua side re-guards but keep the
	// published file sane. Idle must stay below Apache's
	// KeepAliveTimeout (EA4 default 5s) — capped at 60s for
	// operators who raised Apache's too.
	if cfg.OriginKAIdleSec < 1 {
		cfg.OriginKAIdleSec = 1
	} else if cfg.OriginKAIdleSec > 60 {
		cfg.OriginKAIdleSec = 60
	}
	if cfg.OriginKAMaxReqs < 1 {
		cfg.OriginKAMaxReqs = 1000
	}
	return cfg
}
