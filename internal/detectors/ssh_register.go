package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/srcresolve"
	"cfm/internal/detectors/ssh"
	"cfm/internal/logging"
)

// shared state for detectors
var sshState, _ = core.LoadState("")

// ssh_auth source candidates for srcresolve (first = historical default).
// Debian aliases sshd.service to ssh.service but journald indexes only the
// real name, so both units are tried; file fallback covers non-systemd hosts.
var (
	sshJournalUnits = []string{"sshd.service", "ssh.service"}
	sshLogFiles     = []string{"/var/log/secure", "/var/log/auth.log"}
)

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:          "ssh_auth",
		Title:            "SSH authentication",
		Description:      "Detect SSH brute-force/authentication abuse.",
		DefaultsTemplate: map[string]string{"ENABLED": "1", "MODE": "auto", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "BLOCK": "dryrun"},
		ExamplePresets: []meta.Preset{
			{ID: "generic", Title: "Generic Linux", Description: "Journald-based SSH defaults.", Template: map[string]string{"MODE": "journal", "JOURNAL_UNIT": "sshd.service"}},
			{ID: "cpanel", Title: "cPanel host", Description: "File mode for cPanel-like log layouts.", Template: map[string]string{"MODE": "file", "LOG_PATH": "/var/log/secure"}},
		},
		LeniencySupported:   true,
		LeniencyRecommended: true,
	})
	Register("ssh_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		// Enrichment: global defaults, allow per-section override
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

		cfg := ssh.AuthConfig{
			Mode:        kvStrClean(kv, "MODE", "auto"), // auto|journal|file; explicit values win
			LogPath:     kvStrClean(kv, "LOG_PATH", ""),
			JournalUnit: kvStrClean(kv, "JOURNAL_UNIT", ""),

			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),

			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 25),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 15),
			DDOSPerIP:       kvInt(kv, "DDOS_IP", 30),

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,
		}

		// Resolution + provisional policy live in planSSHSource
		// (source_report.go), shared with the dry-run source report.
		plan := planSSHSource(section, kv, srcresolve.DefaultProbes())
		res := plan.res
		if plan.note != "" {
			logging.Logf("[detectors][%s] %s — set MODE/JOURNAL_UNIT/LOG_PATH to override", section, plan.note)
		}

		// Reflect the resolved source into cfg BEFORE NewAuth so alert extras
		// (mode/log/unit) report what is actually tailed.
		switch res.Kind {
		case srcresolve.KindJournal:
			cfg.Mode, cfg.JournalUnit = "journal", res.Unit
		case srcresolve.KindFile:
			cfg.Mode, cfg.LogPath = "file", res.Path
		}

		d := ssh.NewAuth(cfg)
		d.SetName(section)

		switch res.Kind {
		case srcresolve.KindJournal:
			d.SetSource(core.NewJournalTailer(res.Unit))
			if sshState != nil {
				// pseudo-path for a unique journal key
				d.SetState(sshState, core.FileStateKey(section, "journal:"+res.Unit))
			}
			logging.Logf("[detectors][%s] source=journal unit=%s (%s)", section, res.Unit, res.Reason)
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=journal unit=%s limits: ip=%d user=%d ddos=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, res.Unit, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.DDOSPerIP, cfg.UseEnrich, cfg.UsePTR, dirs)
		case srcresolve.KindFile:
			d.SetSource(core.NewFileTailer(res.Path))
			if sshState != nil {
				d.SetState(sshState, core.FileStateKey(section, res.Path))
			}
			logging.Logf("[detectors][%s] source=file path=%s (%s)", section, res.Path, res.Reason)
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=file log=%s limits: ip=%d user=%d ddos=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, res.Path, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.DDOSPerIP, cfg.UseEnrich, cfg.UsePTR, dirs)
		default:
			// ssh_auth has no docker source; unreachable with the Spec above.
			logging.Logf("[detectors][%s] unsupported source kind %q (%s); detector starts without a source", section, res.Kind, res.Reason)
		}

		return d, nil
	})
}
