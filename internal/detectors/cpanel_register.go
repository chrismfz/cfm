package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/cpanel"
	"cfm/internal/detectors/meta"
	"cfm/internal/logging"
)

// shared state for detectors
var cpanelState, _ = core.LoadState("")

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:           "cpanel",
		Title:             "cPanel login",
		Description:       "Detect abusive cPanel/Webmail login attempts.",
		DefaultsTemplate:  map[string]string{"ENABLED": "1", "LOG_PATH": "/usr/local/cpanel/logs/login_log", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "BLOCK": "dryrun"},
		ExamplePresets:    []meta.Preset{{ID: "cpanel", Title: "cPanel", Description: "Default cPanel login_log path.", Template: map[string]string{"MODE": "file", "LOG_PATH": "/usr/local/cpanel/logs/login_log"}}},
		LeniencySupported: true,
	})
	Register("cpanel", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		// Enrichment defaults (same pattern as SSH) :contentReference[oaicite:2]{index=2}
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

		cfg := cpanel.LoginConfig{
			Mode:    "file", // login_log is a file
			LogPath: kvStrClean(kv, "LOG_PATH", "/usr/local/cpanel/logs/login_log"),

			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),

			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 25),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 15),
			RootFailPerIP:   kvInt(kv, "ROOT_IP", 5), // stricter default for WHM root

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,
		}

		d := cpanel.NewLogin(cfg)
		d.SetName(section)
		src := core.NewFileTailer(cfg.LogPath)
		d.SetSource(src)
		// resume state (unique key per section+path)
		if cpanelState != nil {
			key := core.FileStateKey(section, cfg.LogPath)
			d.SetState(cpanelState, key)
		}

		logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s log=%s limits: ip=%d user=%d root=%d enrich=%t ptr=%t dirs=%v)",
			section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.LogPath, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.RootFailPerIP, cfg.UseEnrich, cfg.UsePTR, dirs)

		return d, nil
	})
}
