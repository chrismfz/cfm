package detectors

import (
    "fmt"
    "strconv"
    "strings"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/detectors/postfix"
)



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

        return sec, nil
    })



    // ───────────────────── postfix_queues ─────────────────────
    Register("postfix_queues", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
        defEvery    := kvDur(global, "DEFAULT_EVERY",    60*time.Second)
        defTimeout  := kvDur(global, "DEFAULT_TIMEOUT",   8*time.Second)
        defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

        cfg := postfix.QueuesConfig{
            TotalCmd:    kvStrClean(kv, "TOTAL_CMD", "mailq | tail -n +2 | grep -v 'Mail queue is empty' | wc -l"),
            ListCmd:     kvStrClean(kv, "LIST_CMD",  "mailq"),
            Every:       kvDur(kv, "EVERY", defEvery),
            Timeout:     kvDur(kv, "TIMEOUT", defTimeout),
            MaxTotal:    kvInt(kv, "QUEUE_TOTAL_MAX",  500),
            MaxFrozen:   kvInt(kv, "QUEUE_FROZEN_MAX", 200),
            SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
            Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
        }

        q := postfix.NewQueues(cfg)
        // Name δεν είναι τόσο κρίσιμο εδώ, αλλά βάλε το section για να ξεχωρίζει στα logs
        _ = section
        return q, nil
    })





    Register("postfix_relays", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
        defEvery := kvDur(global, "DEFAULT_EVERY", 5*time.Second)
        defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

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
        usePTR := kvBool(kv, "PTR", kvBool(global, "PTR", true))

        cfg := postfix.RelaysConfig{
            LogPath:     kvStrClean(kv, "LOG_PATH", ""),
            Every:       kvDur(kv, "EVERY", defEvery),
            Window:      kvDur(kv, "WINDOW", 15*time.Minute),
            SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
            Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),

            LocalUserMax:  kvInt(kv, "LOCAL_USER_MAX", 50),
            AuthUserMax:   kvInt(kv, "AUTH_USER_MAX", 50),
            AuthIPMax:     kvInt(kv, "AUTH_IP_MAX", 80),
            AuthUserIPMax: kvInt(kv, "AUTH_USERIP_MAX", 40),
            UnauthIPMax:   kvInt(kv, "UNAUTH_IP_MAX", 20),

            UseEnrich:  useEnrich,
            UsePTR:     usePTR,
            EnrichDirs: dirs,
        }

        rr := postfix.NewRelays(cfg)
        rr.SetName(section)
        return rr, nil
    })
















}

