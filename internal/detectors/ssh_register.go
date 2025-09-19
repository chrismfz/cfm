package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/ssh"
	"cfm/internal/logging"
)

func init() {
	Register("ssh_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery    := kvDur(global, "DEFAULT_EVERY",    2*time.Second)
		defWindow   := kvDur(global, "DEFAULT_WINDOW",   10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		// dirs list
		rawDirs := kvStr(kv, "ENRICH_DIRS", "")
		var dirs []string
		if rawDirs != "" {
			fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			})
			for _, f := range fields {
				if f != "" { dirs = append(dirs, f) }
			}
		}

		cfg := ssh.AuthConfig{
			Mode:        kvStr(kv, "MODE", "journal"), // Debian 13 defaults journal
			LogPath:     kvStr(kv, "LOG_PATH", "/var/log/secure"),
			JournalUnit: kvStr(kv, "JOURNAL_UNIT", "sshd.service"),

			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),

			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP",   25),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 15),
			DDOSPerIP:       kvInt(kv, "DDOS_IP",       30),

			UseEnrich:  kvBool(kv, "ENRICH", true),
			UsePTR:     kvBool(kv, "PTR",    true),
			EnrichDirs: dirs,
		}

		d := ssh.NewAuth(cfg)
		d.SetName(section)

		// choose source based on MODE
		switch cfg.Mode {
		case "file":
			d.SetSource(core.NewFileTailer(cfg.LogPath))
		default: // "journal"
			j := core.NewJournalTailer(cfg.JournalUnit)
			d.SetSource(j)
		}

		// pretty start line
		if cfg.Mode == "file" {
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=file log=%s limits: ip=%d user=%d ddos=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.LogPath, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.DDOSPerIP, cfg.UseEnrich, cfg.UsePTR, dirs)
		} else {
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=journal unit=%s limits: ip=%d user=%d ddos=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.JournalUnit, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.DDOSPerIP, cfg.UseEnrich, cfg.UsePTR, dirs)
		}

		return d, nil
	})
}
