package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/mysql"
	"cfm/internal/logging"
)

func init() {
	Register("mysql", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery    := kvDur(global, "DEFAULT_EVERY",    2*time.Second)
		defWindow   := kvDur(global, "DEFAULT_WINDOW",   10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
		var dirs []string
		if rawDirs != "" {
			fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			})
			for _, f := range fields {
				if f != "" { dirs = append(dirs, f) }
			}
		}
		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR",    true))

		logPath := kvStrClean(kv, "LOG_PATH", "auto")
		if logPath == "auto" {
			if auto := mysql.ResolveForAuto(); auto != "" {
				logPath = auto
			}
		}

		cfg := mysql.LoginConfig{
			Mode:        "file",
			LogPath:     logPath,
			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 12),

			DeniedPerIP:   kvInt(kv, "DENIED_IP",   10),
			DeniedPerUser: kvInt(kv, "DENIED_USER", 10),
			RootPerIP:     kvInt(kv, "ROOT_IP",     3),
			ScanPerIP:     kvInt(kv, "SCAN_IP",     20),

			UseEnrich:        useEnrich,
			UsePTR:           usePTR,
			EnrichDirs:       dirs,
			IgnoreLocalhost:  kvBool(kv, "IGNORE_LOCALHOST", true),
			IgnoreCpanel:     kvBool(kv, "IGNORE_CPANEL_UTIL", true),
		}

		d := mysql.NewMySQL(cfg)
		d.SetName(section)
		d.SetSource(core.NewFileTailer(cfg.LogPath))

		logging.Logf("[detectors] start %s (log=%s every=%s window=%s cooldown=%s limits: ip=%d user=%d root=%d scan=%d enrich=%t ptr=%t)",
			section, cfg.LogPath, cfg.Every, cfg.Window, cfg.Cooldown,
			cfg.DeniedPerIP, cfg.DeniedPerUser, cfg.RootPerIP, cfg.ScanPerIP,
			cfg.UseEnrich, cfg.UsePTR)

		return d, nil
	})
}
