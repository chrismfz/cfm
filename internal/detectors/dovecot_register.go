package detectors

import (
    "strings"
    "time"
    "os"
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
            Mode:           kvStrClean(kv, "MODE", "journal"),
            LogPath:        kvStrClean(kv, "LOG_PATH", ""),
            JournalUnit:    kvStrClean(kv, "JOURNAL_UNIT", "dovecot.service"),
            DockerContainer: kvStrClean(kv, "DOCKER_CONTAINER", ""),
            Every:          kvDur(kv, "EVERY", defEvery),
            Window:         kvDur(kv, "WINDOW", defWindow),
            Cooldown:       kvDur(kv, "COOLDOWN", defCooldown),
            SampleLimit:    kvInt(kv, "SAMPLE_LIMIT", 10),

            AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP",   20),
            AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 10),

            UseEnrich:  useEnrich,
            UsePTR:     usePTR,
            EnrichDirs: dirs,
        }

        // Optional docker args: DOCKER_ARGS = --details,--tail=200
        if raw := kvStrClean(kv, "DOCKER_ARGS", ""); raw != "" {
            var extra []string
            fields := strings.FieldsFunc(raw, func(r rune) bool {
                return r == ',' || r == ';' || r == ' ' || r == '\t'
            })
            for _, f := range fields {
                if f != "" {
                    extra = append(extra, f)
                }
            }
            if len(extra) > 0 {
                cfg.DockerArgs = extra
            }
        }



        // Αν δώσεις DOCKER_CONTAINER και δεν έχεις βάλει ρητά MODE,
        // γύρνα σε docker mode (αντί για default "journal").
        if cfg.DockerContainer != "" && strings.EqualFold(cfg.Mode, "journal") {
            cfg.Mode = "docker"
        }

        det := dovecot.NewAuth(cfg)
        det.SetName(section)


        // choose source based on MODE, with autodetect + fallback
        mode := strings.ToLower(cfg.Mode)

        switch mode {
        case "file":
            // autodetect file path if blank
            logPath := cfg.LogPath
            if strings.TrimSpace(logPath) == "" {
                logPath = guessMailLog()
            }
            src := core.NewFileTailer(logPath)
            det.SetSource(src)
            if dovecotState != nil {
                key := core.FileStateKey(section, logPath)
                det.SetState(dovecotState, key)
            }
            logging.Logf("[detectors][%s] using file log: %s", section, logPath)
            cfg.LogPath = logPath

        case "docker":
            // docker logs mode
            container := strings.TrimSpace(cfg.DockerContainer)
            if container == "" {
                // αν δεν έδωσες container, πέφτουμε πίσω σε journal/file
                logging.Logf("[detectors][%s] MODE=docker αλλά DOCKER_CONTAINER είναι κενό – falling back to journal/file", section)
                mode = "journal"
            } else {
                src := core.NewDockerTailer(container, cfg.DockerArgs...)
                det.SetSource(src)
                if dovecotState != nil {
                    key := core.FileStateKey(section, "docker:"+container)
                    det.SetState(dovecotState, key)
                }
                logging.Logf("[detectors][%s] using docker logs (container=%s, args=%v)", section, container, cfg.DockerArgs)
            }
            fallthrough

        default: // "journal"

            // Try journal first; if unavailable, fall back to file
            j := core.NewJournalTailer(cfg.JournalUnit)
            if err := j.Open(); err == nil {
                if cerr := j.Close(); cerr != nil {
                    // Not fatal: we only probed availability; detector will reopen later.
                    logging.Logf("[detectors][%s] journal probe close error (unit=%s): %v", section, cfg.JournalUnit, cerr)
                }
                det.SetSource(j)
                if dovecotState != nil {
                    key := core.FileStateKey(section, "journal:"+cfg.JournalUnit)
                    det.SetState(dovecotState, key)
                }
                logging.Logf("[detectors][%s] using journal: unit=%s", section, cfg.JournalUnit)
            } else {
                // Fallback to file
                logPath := cfg.LogPath
                if strings.TrimSpace(logPath) == "" {
                    logPath = guessMailLog()
                }
                src := core.NewFileTailer(logPath)
                det.SetSource(src)
                if dovecotState != nil {
                    key := core.FileStateKey(section, logPath)
                    det.SetState(dovecotState, key)
                }
                logging.Logf("[detectors][%s] journal unavailable (unit=%s): %v — falling back to file log: %s",
                    section, cfg.JournalUnit, err, logPath)
                cfg.Mode = "file"
                cfg.LogPath = logPath
            }

        }

        // pretty start line

        switch strings.ToLower(cfg.Mode) {
        case "file":

            logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=file log=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
                section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.LogPath, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
        case "docker":
            logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=docker container=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
                section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.DockerContainer, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
        default: // journal
            logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=journal unit=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
                section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.JournalUnit, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
        }
        return det, nil


    })
}




// ---- helpers ---------------------------------------------------------------
func guessMailLog() string {
   // Prefer /var/log/maillog (RHEL/cPanel), else /var/log/mail.log (Debian/Ubuntu)
    if fileExists("/var/log/maillog") { return "/var/log/maillog" }
    if fileExists("/var/log/mail.log") { return "/var/log/mail.log" }
    // last resort: dovecot’s own default in Auth.NewAuth will use /var/log/maillog
    return "/var/log/maillog"
}
func fileExists(p string) bool {
    fi, err := os.Stat(p)
    return err == nil && !fi.IsDir()
}
