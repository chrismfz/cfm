package detectors

import (
    "strings"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/detectors/dovecot"
)

func init() {
    Register("dovecot_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
        defEvery    := kvDur(global, "DEFAULT_EVERY",    2*time.Second)
        defWindow   := kvDur(global, "DEFAULT_WINDOW",   15*time.Minute)
        defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

        // Global enrichment defaults with per-section override
        rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
        var dirs []string
        if rawDirs != "" {
            fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
                return r == ',' || r == ':' || r == ' ' || r == '\t'
            })
            for _, f := range fields { if f != "" { dirs = append(dirs, f) } }
        }
        useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
        usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR",    true))

        cfg := dovecot.Config{
            Mode:        kvStrClean(kv, "MODE", "journal"),
            LogPath:     kvStrClean(kv, "LOG_PATH", ""),
            JournalUnit: kvStrClean(kv, "JOURNAL_UNIT", "dovecot.service"),
            Every:       kvDur(kv, "EVERY", defEvery),
            Window:      kvDur(kv, "WINDOW", defWindow),
            Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
            SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),

            AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP",   20),
            AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 10),

            UseEnrich:  useEnrich,
            UsePTR:     usePTR,
            EnrichDirs: dirs,
        }

        det := dovecot.NewAuth(cfg)
        det.SetName(section)
        return det, nil
    })
}
