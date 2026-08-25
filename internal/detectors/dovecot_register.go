package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/dovecot"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/srcresolve"
	"cfm/internal/logging"
)

// shared state for detectors
var dovecotState, _ = core.LoadState("")

// dovecot_auth source candidates for srcresolve (first = historical default).
// File candidates mirror the old guessMailLog() order (syslog mail logs — the
// parser expects syslog-framed lines, so dovecot's native log file is NOT a
// candidate); the docker pattern matches mailcow-style container names.
var (
	dovecotJournalUnits   = []string{"dovecot.service"}
	dovecotLogFiles       = []string{"/var/log/maillog", "/var/log/mail.log"}
	dovecotDockerPatterns = []string{"dovecot"}
)

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:           "dovecot_auth",
		Title:             "Dovecot authentication",
		Description:       "Detect abusive IMAP/POP authentication attempts.",
		DefaultsTemplate:  map[string]string{"ENABLED": "1", "MODE": "auto", "EVERY": "2s", "WINDOW": "15m", "COOLDOWN": "20m", "BLOCK": "dryrun"},
		ExamplePresets:    []meta.Preset{{ID: "mailcow", Title: "mailcow", Description: "Use container logs.", Template: map[string]string{"MODE": "docker", "DOCKER_CONTAINER": "dovecot-mailcow"}}},
		LeniencySupported: true,
	})
	Register("dovecot_auth", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 15*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		// Global enrichment defaults with per-section override
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

		cfg := dovecot.Config{
			Mode:            kvStrClean(kv, "MODE", "auto"), // auto|journal|file|docker; explicit values win
			LogPath:         kvStrClean(kv, "LOG_PATH", ""),
			JournalUnit:     kvStrClean(kv, "JOURNAL_UNIT", ""),
			DockerContainer: kvStrClean(kv, "DOCKER_CONTAINER", ""),
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", defWindow),
			Cooldown:        kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),

			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 20),
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

		// Resolution + provisional policy live in planDovecotSource
		// (source_report.go), shared with the dry-run source report.
		plan := planDovecotSource(section, kv, srcresolve.DefaultProbes())
		res := plan.res
		if plan.note != "" {
			logging.Logf("[detectors][%s] %s — set MODE/JOURNAL_UNIT/LOG_PATH/DOCKER_CONTAINER to override", section, plan.note)
		}

		// Reflect the resolved source into cfg BEFORE NewAuth so alert extras
		// (mode/log/unit/container) report what is actually tailed. (The old
		// register mutated cfg after NewAuth, which never reached the detector.)
		switch res.Kind {
		case srcresolve.KindJournal:
			cfg.Mode, cfg.JournalUnit = "journal", res.Unit
		case srcresolve.KindFile:
			cfg.Mode, cfg.LogPath = "file", res.Path
		case srcresolve.KindDocker:
			cfg.Mode, cfg.DockerContainer = "docker", res.Container
		}

		det := dovecot.NewAuth(cfg)
		det.SetName(section)

		switch res.Kind {
		case srcresolve.KindJournal:
			det.SetSource(core.NewJournalTailer(res.Unit))
			if dovecotState != nil {
				det.SetState(dovecotState, core.FileStateKey(section, "journal:"+res.Unit))
			}
			logging.Logf("[detectors][%s] source=journal unit=%s (%s)", section, res.Unit, res.Reason)
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=journal unit=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, res.Unit, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
		case srcresolve.KindFile:
			det.SetSource(core.NewFileTailer(res.Path))
			if dovecotState != nil {
				det.SetState(dovecotState, core.FileStateKey(section, res.Path))
			}
			logging.Logf("[detectors][%s] source=file path=%s (%s)", section, res.Path, res.Reason)
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=file log=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, res.Path, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
		case srcresolve.KindDocker:
			det.SetSource(core.NewDockerTailer(res.Container, cfg.DockerArgs...))
			if dovecotState != nil {
				det.SetState(dovecotState, core.FileStateKey(section, "docker:"+res.Container))
			}
			logging.Logf("[detectors][%s] source=docker container=%s args=%v (%s)", section, res.Container, cfg.DockerArgs, res.Reason)
			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=docker container=%s limits: ip=%d user=%d enrich=%t ptr=%t dirs=%v)",
				section, cfg.Every, cfg.Window, cfg.Cooldown, res.Container, cfg.AuthFailPerIP, cfg.AuthFailPerUser, cfg.UseEnrich, cfg.UsePTR, dirs)
		}

		return det, nil
	})
}
