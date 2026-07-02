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

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:     "waf_security",
		Title:       "WAF security",
		Description: "Persistent cross-request nft block from in-path WAF hits, scored per reason-family.",
		DefaultsTemplate: map[string]string{
			"ENABLED": "1", "EVERY": "20s", "WINDOW": "30m", "DRY_RUN": "1",
			"SQLI": "1", "RCE": "1", "BACKDOOR": "1", "UPLOAD_EXPLOIT": "1",
		},
		LeniencySupported:   true,
		LeniencyRecommended: true,
	})

	Register("waf_security", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 20*time.Second)

		// Config short-names expand to the underlying WAF reason-families the
		// edge actually emits. Phase 1 ships the edge-`block` (0-FP) families
		// ON at threshold 1; every challenge-tier family ships at 0 (edge-only)
		// until live cfm.detectors.log data justifies turning it on — see
		// docs/waf-autoblock-design.md.
		sqli := kvInt(kv, "SQLI", 1)     // WAF_SQLI + WAF_SQLI_LEXICAL
		upload := kvInt(kv, "UPLOAD_EXPLOIT", 1) // WAF_UPLOAD_FNAME + WAF_UPLOAD_CONTENT
		families := map[string]int{
			"WAF_SQLI":           sqli,
			"WAF_SQLI_LEXICAL":   sqli,
			"WAF_RCE":            kvInt(kv, "RCE", 1),
			"WAF_BACKDOOR":       kvInt(kv, "BACKDOOR", 1),
			"WAF_UPLOAD_FNAME":   upload,
			"WAF_UPLOAD_CONTENT": upload,
			"WAF_WEBSHELL":       kvInt(kv, "WEBSHELL", 0),
			"WAF_XXE":            kvInt(kv, "XXE", 0),
			"WAF_SSRF":           kvInt(kv, "SSRF", 0),
			"WAF_BAD_UA":         kvInt(kv, "BAD_UA", 0),
			"WAF_IP_HOST":        kvInt(kv, "IP_HOST", 0),
			"WAF_AUTH_BURST":     kvInt(kv, "AUTH_BURST", 0),
			"WAF_SUPERGLOBAL":    kvInt(kv, "SUPERGLOBAL", 0),
			"WAF_BAD_UTF8":       kvInt(kv, "BAD_UTF8", 0),
		}

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
			DryRun:          kvBool(kv, "DRY_RUN", true), // safe default: log, don't block, until an operator flips it
			AllowIPs:        csvKV(kv, "ALLOW_IPS"),
			AllowNets:       csvKV(kv, "ALLOW_NETS"),
			AllowUAContains: csvKV(kv, "ALLOW_UA_CONTAINS"),
			PathExceptions:  csvKV(kv, "PATH_EXCEPTIONS"),
		}
		d := wafsec.New(cfg)
		d.SetName(section)
		webdetector.SubscribeWAFHitEvents(func(ev webdetector.WAFHitEvent) {
			d.Enqueue(ev.InputEvent())
		})
		return d, nil
	})
}
