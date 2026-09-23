package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/proxmox"
	"cfm/internal/logging"
)

var proxmoxState = core.DefaultState()

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:             "proxmox_auth",
		Title:               "Proxmox authentication",
		Description:         "Detect authentication failures from Proxmox VE auth/pvedaemon logs.",
		DefaultsTemplate:    map[string]string{"ENABLED": "1", "MODE": "journal", "JOURNAL_UNIT": "pvedaemon.service", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "SAMPLE_LIMIT": "10", "AUTHFAIL_IP": "20", "AUTHFAIL_USER": "10", "BLOCK": "dryrun", "BLOCK_COOLDOWN": "20m", "ENRICH": "1", "PTR": "1", "ENRICH_DIRS": "/var/lib/cfm/maxmind:/etc/cfm"},
		ExamplePresets:      []meta.Preset{{ID: "proxmox_ve_journal", Title: "Proxmox VE journal", Description: "Use journald for pvedaemon authentication events.", Template: map[string]string{"MODE": "journal", "JOURNAL_UNIT": "pvedaemon.service"}}},
		LeniencySupported:   true,
		LeniencyRecommended: true,
	})

	Register("proxmox_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 15*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		cfg := proxmox.Config{
			Mode:            strings.ToLower(kvStrClean(kv, "MODE", "journal")),
			LogPath:         kvStrClean(kv, "LOG_PATH", "/var/log/auth.log"),
			JournalUnit:     kvStrClean(kv, "JOURNAL_UNIT", "pvedaemon.service"),
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", defWindow),
			Cooldown:        kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 20),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 10),
		}

		d := proxmox.NewAuth(cfg)
		d.SetName(section)

		switch cfg.Mode {
		case "file":
			src := core.NewFileTailer(cfg.LogPath)
			d.SetSource(src)
			if proxmoxState != nil {
				key := core.FileStateKey(section, cfg.LogPath)
				d.SetState(proxmoxState, key)
			}
			logging.Logf("[detectors][%s] source=file path=%s (explicit)", section, cfg.LogPath)
		default:
			src := core.NewJournalTailer(cfg.JournalUnit)
			d.SetSource(src)
			if proxmoxState != nil {
				key := core.FileStateKey(section, "journal:"+cfg.JournalUnit)
				d.SetState(proxmoxState, key)
			}
			logging.Logf("[detectors][%s] source=journal unit=%s (explicit)", section, cfg.JournalUnit)
		}

		logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=%s unit=%s log=%s limits: ip=%d user=%d)",
			section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.Mode, cfg.JournalUnit, cfg.LogPath, cfg.AuthFailPerIP, cfg.AuthFailPerUser)

		return d, nil
	})
}
