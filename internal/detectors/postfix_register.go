package detectors

import (
    "fmt"
    "strconv"
    "strings"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/detectors/postfix"
)

// Shared state for Postfix detector (same dir as Exim’s)
// you *can* reuse eximState, but separate is cleaner.
var postfixState, _ = core.LoadState("")

func init() {
    Register("postfix_security", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
        defEvery    := kvDur(global, "DEFAULT_EVERY",    20*time.Second)
        defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

        // Enrichment dirs: section overrides global
        rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
        var dirs []string
        if rawDirs != "" {
            fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
                return r == ',' || r == ':' || r == ' ' || r == '\t'
            })
            for _, f := range fields {
                if f != "" {
                    dirs = append(dirs, f)
                }
            }
        }

        useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
        usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR",    true))

        cfg := postfix.SecConfig{
            LogPath:      kvStrClean(kv, "LOG_PATH", ""),
            JournalUnit:  kvStrClean(kv, "JOURNAL_UNIT", ""),
            JournalMatch: kvStrClean(kv, "JOURNAL_MATCHES", ""),
            Every:        kvDur(kv, "EVERY", defEvery),
            Window:       kvDur(kv, "WINDOW", 15*time.Minute),
            SampleLimit:  kvInt(kv, "SAMPLE_LIMIT", 10),
            Cooldown:     kvDur(kv, "COOLDOWN", defCooldown),

            UseEnrich:  useEnrich,
            UsePTR:     usePTR,
            EnrichDirs: dirs,
            Thresholds: map[string]int{}, // we’ll populate below
        }

        // ---- thresholds ----
        // Specials
        if v := kvInt(kv, "AUTHFAIL_IP", 0); v > 0 {
            cfg.Thresholds["AUTHFAIL_IP"] = v
        }
        if v := kvInt(kv, "AUTHFAIL_USER", 0); v > 0 {
            cfg.Thresholds["AUTHFAIL_USER"] = v
        }

        // Known rule keys
        known := []string{
            "AUTHFAIL",
            "RELAY_DENIED",
            "USER_UNKNOWN",
            "RCPT_REJECT",
            "RBL_HIT",
            "NONSMTP_CMD",
            "PIPELINING",
            "TLS_ERR",
        }

        // Direct per-rule keys (allow 0 = disable)
        for _, k := range known {
            raw := kvStrClean(kv, k, "__MISSING__")
            if raw == "__MISSING__" {
                continue
            }
            n, err := strconv.Atoi(strings.TrimSpace(raw))
            if err == nil {
                cfg.Thresholds[k] = n
            }
        }

        // Optional bundle: RULE_THRESHOLDS=KEY=VAL,KEY=VAL,...
        if raw := kvStrClean(kv, "RULE_THRESHOLDS", ""); raw != "" {
            parts := strings.FieldsFunc(raw, func(r rune) bool {
                return r == ',' || r == ' ' || r == '\t'
            })
            for _, p := range parts {
                if p == "" || !strings.Contains(p, "=") {
                    continue
                }
                kvp := strings.SplitN(p, "=", 2)
                name := strings.TrimSpace(kvp[0])
                val  := strings.TrimSpace(kvp[1])
                if name == "" || val == "" {
                    continue
                }
                if n, err := strconv.Atoi(val); err == nil {
                    cfg.Thresholds[name] = n // allow 0 = off
                } else {
                    fmt.Printf("[detectors][%s] ignoring RULE_THRESHOLDS entry %q (invalid int)\n", section, p)
                }
            }
        }

        sec := postfix.NewSecurity(cfg)
        sec.SetName(section)
        if postfixState != nil {
            sec.SetState(postfixState)
        }

        return sec, nil
    })
}
