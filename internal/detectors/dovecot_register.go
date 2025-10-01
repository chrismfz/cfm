package detectors

import (
    "strings"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/detectors/dovecot"
    "cfm/internal/logging"
)


// shared state for detectors
var dovecotState, _ = core.LoadState("")

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



        // choose source based on MODE and log it
        mode := strings.ToLower(cfg.Mode)
        switch mode {
        case "file":
            src := core.NewFileTailer(cfg.LogPath)
            det.SetSource(src)
            if dovecotState != nil {
                key := core.FileStateKey(section, cfg.LogPath)
                det.SetState(dovecotState, key)
            }
            logging.Logf("[detectors][%s] using log: %s", section, cfg.LogPath)
        default: // "journal"
            j := core.NewJournalTailer(cfg.JournalUnit)
            det.SetSource(j)

            if dovecotState != nil {
                // pseudo-path ensures uniqueness per journal unit
                key := core.FileStateKey(section, "journal:"+cfg.JournalUnit)
                det.SetState(dovecotState, key)
            }

            logging.Logf("[detectors][%s] using journal: unit=%s", section, cfg.JournalUnit)
        }

        // pretty start line
        if mode == "file" {
            logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=file log=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
                section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.LogPath, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
        } else {
            logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=journal unit=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
                section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.JournalUnit, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
        }

        return det, nil


    })
}
