package detectors

import (
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/ngmauth"
	"cfm/internal/logging"
)

// shared resume state for the ngm_auth detector (dir-mode, same as cpanel)
var ngmAuthState = core.DefaultState()

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:           "ngm_auth",
		Title:             "NGM panel login",
		Description:       "Detect abusive NGM control-panel login attempts.",
		DefaultsTemplate:  map[string]string{"ENABLED": "1", "LOG_PATH": "/var/log/ngm/auth.log", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "BLOCK": "dryrun"},
		ExamplePresets:    []meta.Preset{{ID: "ngm", Title: "NGM", Description: "Default NGM panel auth.log path.", Template: map[string]string{"LOG_PATH": "/var/log/ngm/auth.log"}}},
		LeniencySupported: true,
	})
	Register("ngm_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		cfg := ngmauth.AuthConfig{
			Mode:    "file", // auth.log is a file
			LogPath: kvStrClean(kv, "LOG_PATH", "/var/log/ngm/auth.log"),

			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 16),

			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 25),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 15),
			AdminFailPerIP:  kvInt(kv, "ADMIN_IP", 5), // stricter for role=admin
			TokenFailPerIP:  kvInt(kv, "TOKEN_IP", 10),
		}

		d := ngmauth.New(cfg)
		d.SetName(section)
		src := core.NewFileTailer(cfg.LogPath)
		d.SetSource(src)
		// resume state (unique key per section+path)
		if ngmAuthState != nil {
			d.SetState(ngmAuthState, core.FileStateKey(section, cfg.LogPath))
		}

		logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s log=%s limits: ip=%d user=%d admin=%d token=%d)",
			section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.LogPath, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.AdminFailPerIP, cfg.TokenFailPerIP)

		return d, nil
	})
}
