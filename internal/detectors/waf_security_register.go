package detectors

import (
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/wafsec"
	"cfm/internal/webdetector"
)

// wafSecurityFamilies builds the per-family threshold map, covering EVERY WAF
// reason-family from the authoritative registry so none is silently
// unconfigurable and new families are picked up automatically
// (TestWAFSecurityFamilyCoverage guards this). The config key for a family is
// its name minus the "WAF_" prefix (WAF_SQLI → SQLI).
//
// Default: a family ships ON (threshold 1) iff it has an edge-`block` rule
// today — because Phase 1 only feeds edge-`block` hits, those are the only
// families that can actually autoblock. Everything else defaults to 0
// (edge-only). WAF_BACKDOOR is armed to 1 as well even though it has no block
// rule yet, so it autoblocks the moment one of its rules (e.g. 438) is promoted
// to block after that rule's own burn-in.
//
// WAF_CVE follows the normal block-rule rule: it has an edge-`block` rule
// (10001, the Simple File List upload RCE) so it arms to 1 by default — the
// operator explicitly wants CVE hits to nft-ban AND surface on Slack/mail (an
// un-armed family is dropped by the detector, so it would notify nothing). The
// family is HETEROGENEOUS (many CVE rules of varying FP confidence), so a
// lower-confidence CVE rule must ship with a per-rule `RULE_<id> = 0` override
// in the SAME change that adds it, holding just that rule while the family stays
// armed. DRY_RUN = 1 gives a watch-first burn-in without real bans.
//
// WAF_WEBSHELL follows the normal rule too: it has an edge-`block` rule (413,
// the proper-noun webshell drop-path subset) so it arms to 1. It was held at 0
// through its burn-in — arming it nft-bans a source that GETs `/c99.php`, which
// includes benign internet scanners (Shodan/Censys/uptime monitors) — but the
// operator runs it armed fleet-wide and confirms it reliably blocks malicious
// scanners/scrapers/bots with acceptable collateral, so it is now armed by
// default (2026-07-18). Narrow the scope per-rule with `RULE_413 = 0` or
// exempt sources with `ALLOW_UA_CONTAINS` / `ALLOW_NETS` if a scanner matters.
//
// WAF_TRAVERSAL is the deliberate exception the other way: rule 101 was
// promoted to edge-`block` on 2026-09-05 (clean 6-server FP review), which
// would auto-arm the family, but it is HELD at 0 for its own burn-in
// (CLAUDE.md §6: arming a newly block-promoted family is an opt-in decision).
// The volume is the reason: ~11 500 hits and ~2 300 distinct source IPs per
// week fleet-wide, almost all Google-Cloud `.env` / `/proc/self/environ`
// sweeps — armed at threshold 1 that is ~330 six-hour bans and alerts per day.
// The edge already returns 403 to every hit; the ban adds cross-request
// persistence and notification, which the operator arms with `TRAVERSAL = 1`
// once the alert volume is judged acceptable (or with DRY_RUN = 1 first).
//
// heldAutoblockFamilies is the ONE source for that hold: the default loop,
// the DefaultsTemplate rendered into a fresh detectors.conf and
// TestWAFSecurityFamilyCoverage all read it, so arming a family later is a
// one-line deletion here (plus the reference detectors.conf comment).
var heldAutoblockFamilies = map[string]string{
	"WAF_TRAVERSAL": "rule 101 is edge-block since 2026-09-05 but the family is HELD un-armed for burn-in (volume: ~2 300 scanner IPs/week). Set 1 to ban.",
}

func wafSecurityFamilies(kv KV) map[string]int {
	families := map[string]int{}
	for _, fam := range webdetector.WAFReasonFamilies() {
		def := 0
		if webdetector.WAFFamilyHasBlockRule(fam) || fam == "WAF_BACKDOOR" {
			def = 1
		}
		if _, held := heldAutoblockFamilies[fam]; held {
			def = 0
		}
		key := strings.TrimPrefix(fam, "WAF_")
		families[fam] = kvInt(kv, key, def)
	}
	return families
}

// wafSecurityDefaultsTemplate is the [waf_security] block a fresh
// detectors.conf is rendered from; held families are added from
// heldAutoblockFamilies so the rendered default can never drift from the
// code default.
func wafSecurityDefaultsTemplate() map[string]string {
	t := map[string]string{
		"ENABLED": "1", "EVERY": "20s", "WINDOW": "30m", "DRY_RUN": "0",
		"SQLI": "1", "RCE": "1", "UPLOAD_FNAME": "1", "UPLOAD_CONTENT": "1", "BACKDOOR": "1",
		"WEBSHELL": "1", // edge-block rule 413; armed by default (blocks webshell-probing scanners/bots). Exempt a source with ALLOW_UA_CONTAINS/ALLOW_NETS or hold with RULE_413=0.
		"CVE":      "1", // named-vuln family; armed (rule 10001 is block). Hold a low-confidence CVE rule with RULE_<id>=0 when it lands.
		"BLOCK":    "6h",
	}
	for fam := range heldAutoblockFamilies {
		t[strings.TrimPrefix(fam, "WAF_")] = "0"
	}
	return t
}

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:             "waf_security",
		Title:               "WAF security",
		Description:         "Persistent cross-request nft block from in-path WAF hits, scored per reason-family.",
		DefaultsTemplate:    wafSecurityDefaultsTemplate(),
		LeniencySupported:   true,
		LeniencyRecommended: true,
	})

	Register("waf_security", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 20*time.Second)

		families := wafSecurityFamilies(kv)

		// Per-rule-id overrides: any RULE_<id> = N key (parser keeps arbitrary
		// keys, uppercased) wins over the family default for that rule id.
		overrides := map[string]int{}
		for k, v := range kv {
			if !strings.HasPrefix(k, "RULE_") {
				continue
			}
			id := strings.TrimSpace(strings.TrimPrefix(k, "RULE_"))
			if id == "" {
				continue
			}
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				overrides[id] = n
			}
		}

		cfg := wafsec.Config{
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", 30*time.Minute),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			Families:        families,
			RuleOverrides:   overrides,
			DryRun:          kvBool(kv, "DRY_RUN", false), // observe-only override; the shipped config uses a soft TTL block instead
			AllowIPs:        csvKV(kv, "ALLOW_IPS"),
			AllowNets:       csvKV(kv, "ALLOW_NETS"),
			AllowUAContains: csvKV(kv, "ALLOW_UA_CONTAINS"),
			PathExceptions:  csvKV(kv, "PATH_EXCEPTIONS"),
		}
		d := wafsec.New(cfg)
		d.SetName(section)
		// Phase 1: only edge-BLOCK hits feed the counter ("block at WAF → nft
		// candidate"). This scopes autoblock to what the edge itself already
		// blocks — the high-confidence, rule-accurate set — rather than every
		// rule in a family: a family like WAF_RCE spans block rule 320 AND
		// logonly 322-327, and WAF_BACKDOOR has no block-tier rules at all, so
		// family-only keying would pull in logonly/challenge recon. Phase 2 will
		// relax this to also feed challenge-tier families (bot-persistence).
		webdetector.SubscribeWAFHitEvents(func(ev webdetector.WAFHitEvent) {
			if ev.Action != "block" {
				return
			}
			d.Enqueue(ev.InputEvent())
		})
		return d, nil
	})
}
