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
// WAF_WEBSHELL and WAF_CVE are the deliberate EXCEPTIONS: each has an
// edge-`block` rule (WEBSHELL 413; WAF_CVE 10001, the Simple File List upload
// RCE) but is left at 0 (not auto-armed), so adding those block rules does not
// silently turn a probe into a 6h nft ban on every deployment — existing
// /etc/cfm/detectors.conf files that don't list the family would otherwise
// inherit the armed default. WAF_CVE additionally is HETEROGENEOUS (many CVE
// rules of varying FP confidence), so family-wide arming is opt-in: set
// `CVE = 1` (family) or `RULE_<id> = 1` (one detector) after burn-in.
func wafSecurityFamilies(kv KV) map[string]int {
	families := map[string]int{}
	for _, fam := range webdetector.WAFReasonFamilies() {
		def := 0
		if (webdetector.WAFFamilyHasBlockRule(fam) && fam != "WAF_WEBSHELL" && fam != "WAF_CVE") || fam == "WAF_BACKDOOR" {
			def = 1
		}
		key := strings.TrimPrefix(fam, "WAF_")
		families[fam] = kvInt(kv, key, def)
	}
	return families
}

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:     "waf_security",
		Title:       "WAF security",
		Description: "Persistent cross-request nft block from in-path WAF hits, scored per reason-family.",
		DefaultsTemplate: map[string]string{
			"ENABLED": "1", "EVERY": "20s", "WINDOW": "30m", "DRY_RUN": "0",
			"SQLI": "1", "RCE": "1", "UPLOAD_FNAME": "1", "UPLOAD_CONTENT": "1", "BACKDOOR": "1",
			"WEBSHELL": "0", // has an edge-block rule (413) but held un-armed; opt in with 1
			"BLOCK": "6h",
		},
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
