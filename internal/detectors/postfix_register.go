package detectors

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/postfix"
	"cfm/internal/detectors/srcresolve"
	"cfm/internal/logging"
)

// postfix source candidates for srcresolve (first = historical default).
// Debian runs the real instance as postfix@-.service (postfix.service is an
// aggregator); EL runs postfix.service — the signature probe picks whichever
// journal actually carries postfix lines.
var (
	postfixJournalUnits   = []string{"postfix@-.service", "postfix.service"}
	postfixLogFiles       = []string{"/var/log/maillog", "/var/log/mail.log"}
	postfixDockerPatterns = []string{"postfix"}
)

// postfixJournalSignature keeps the journal candidates content-aware: a unit
// qualifies only when its recent entries carry postfix's syslog tag
// ("postfix/smtpd[123]: …"), never on mere entry existence — journald
// attributes by cgroup, so a unit's journal can hold OTHER services' lines
// (docs/detectors-config-unification.md §3a).
const postfixJournalSignature = `postfix(/[a-z0-9-]+)?\[\d+\]:`

// dockerizePostfixQueueCmds returns the queue commands with the MTA
// invocation (the first pipeline segment) wrapped in `docker exec`; the rest
// of the pipeline keeps running on the host over the container's stdout. The
// total pipeline mirrors postfix.NewQueues' exact default — count message
// HEADER lines (queue id + numeric size), never raw lines, which over-count
// 3-5× (recipient + reason lines).
func dockerizePostfixQueueCmds(container string) (total, list string) {
	return "docker exec " + container + ` mailq | grep -E '^[A-Za-z0-9]+ +[0-9]' | wc -l`,
		"docker exec " + container + " mailq"
}

// explicitSourceKeys counts how many of the source keys carry a real explicit
// value ("" and "auto" are requests to resolve).
func explicitSourceKeys(vals ...string) int {
	n := 0
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" && !strings.EqualFold(v, "auto") {
			n++
		}
	}
	return n
}

// applyPostfixSourcePlan applies planPostfixLogSource's outcome to a config's
// three source fields so exactly one is set (the postfix package wires
// whichever is non-empty, journald > docker > file). Returns disable=true
// when the plan says the section self-disables (register returns nil, nil).
// All policy lives in the planner (source_report.go) — shared with the
// dry-run source-resolution report — this is only the wiring glue.
func applyPostfixSourcePlan(section string, plan sourcePlan, unit, container, path *string) (disable bool) {
	if plan.disable {
		logging.Logf("[detectors][%s] %s (%s)", section, plan.note, plan.res.Reason)
		return true
	}
	if plan.note != "" {
		logging.Logf("[detectors][%s] %s", section, plan.note)
	}
	if plan.passthrough {
		return false
	}
	switch plan.res.Kind {
	case srcresolve.KindJournal:
		*unit, *container, *path = plan.res.Unit, "", ""
		logging.Logf("[detectors][%s] source=journal unit=%s (%s)", section, plan.res.Unit, plan.res.Reason)
	case srcresolve.KindDocker:
		*unit, *container, *path = "", plan.res.Container, ""
		logging.Logf("[detectors][%s] source=docker container=%s (%s)", section, plan.res.Container, plan.res.Reason)
	case srcresolve.KindFile:
		*unit, *container, *path = "", "", plan.res.Path
		logging.Logf("[detectors][%s] source=file path=%s (%s)", section, plan.res.Path, plan.res.Reason)
	}
	return false
}

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:           "postfix_security",
		Title:             "Postfix security",
		Description:       "Detect Postfix authentication and policy failures.",
		DefaultsTemplate:  map[string]string{"ENABLED": "1", "MODE": "auto", "EVERY": "20s", "WINDOW": "15m", "COOLDOWN": "20m", "BLOCK": "dryrun"},
		ExamplePresets:    []meta.Preset{{ID: "mailcow", Title: "mailcow", Description: "Dockerized mailcow postfix logs.", Template: map[string]string{"MODE": "docker", "DOCKER_CONTAINER": "postfix-mailcow"}}},
		LeniencySupported: true,
	})
	meta.Register(meta.DetectorMeta{
		TypeKey:          "postfix_queues",
		Title:            "Postfix queues",
		Description:      "Monitor queue growth/frozen queue pressure.",
		DefaultsTemplate: map[string]string{"ENABLED": "1", "EVERY": "60s", "BLOCK": "dryrun"},
	})
	meta.Register(meta.DetectorMeta{
		TypeKey:           "postfix_relays",
		Title:             "Postfix relays",
		Description:       "Detect suspicious relay activity.",
		DefaultsTemplate:  map[string]string{"ENABLED": "1", "MODE": "auto", "EVERY": "20s", "WINDOW": "15m", "BLOCK": "dryrun"},
		LeniencySupported: true,
	})
	Register("postfix_security", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 20*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		// Enrichment dirs: section overrides global
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

		cfg := postfix.SecConfig{
			LogPath:         kvStrClean(kv, "LOG_PATH", ""),
			JournalUnit:     kvStrClean(kv, "JOURNAL_UNIT", ""),
			JournalMatch:    kvStrClean(kv, "JOURNAL_MATCHES", ""),
			DockerContainer: kvStrClean(kv, "DOCKER_CONTAINER", ""),
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", 15*time.Minute),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			Cooldown:        kvDur(kv, "COOLDOWN", defCooldown),

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,
			Thresholds: map[string]int{}, // we’ll populate below
		}

		// Optional comma/space/colon-separated Docker args, e.g.:
		// DOCKER_ARGS = --details,--tail=200
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

		// ---- thresholds ----
		// Specials
		if v := kvInt(kv, "AUTHFAIL_IP", 0); v > 0 {
			cfg.Thresholds["AUTHFAIL_IP"] = v
		}
		if v := kvInt(kv, "AUTHFAIL_USER", 0); v > 0 {
			cfg.Thresholds["AUTHFAIL_USER"] = v
		}

		// Known rule keys
		known := []string{
			"AUTHFAIL",
			"RELAY_DENIED",
			"USER_UNKNOWN",
			"RCPT_REJECT",
			"RBL_HIT",
			"NONSMTP_CMD",
			"PIPELINING",
			"TLS_ERR",
		}

		// Direct per-rule keys (allow 0 = disable)
		for _, k := range known {
			raw := kvStrClean(kv, k, "__MISSING__")
			if raw == "__MISSING__" {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(raw))
			if err == nil {
				cfg.Thresholds[k] = n
			}
		}

		// Optional bundle: RULE_THRESHOLDS=KEY=VAL,KEY=VAL,...
		if raw := kvStrClean(kv, "RULE_THRESHOLDS", ""); raw != "" {
			parts := strings.FieldsFunc(raw, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t'
			})
			for _, p := range parts {
				if p == "" || !strings.Contains(p, "=") {
					continue
				}
				kvp := strings.SplitN(p, "=", 2)
				name := strings.TrimSpace(kvp[0])
				val := strings.TrimSpace(kvp[1])
				if name == "" || val == "" {
					continue
				}
				if n, err := strconv.Atoi(val); err == nil {
					cfg.Thresholds[name] = n // allow 0 = off
				} else {
					fmt.Printf("[detectors][%s] ignoring RULE_THRESHOLDS entry %q (invalid int)\n", section, p)
				}
			}
		}

		if applyPostfixSourcePlan(section, planPostfixLogSource(section, kv, registrationProbes()),
			&cfg.JournalUnit, &cfg.DockerContainer, &cfg.LogPath) {
			return nil, nil
		}

		sec := postfix.NewSecurity(cfg)
		sec.SetName(section)

		return sec, nil
	})

	// ───────────────────── postfix_queues ─────────────────────
	Register("postfix_queues", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 60*time.Second)
		defTimeout := kvDur(global, "DEFAULT_TIMEOUT", 8*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		// Queue command plan (shared with the source-resolution report):
		// explicit commands verbatim; host postfix → empty so NewQueues fills
		// its exact header-count defaults; postfix only in a discovered
		// container (mailcow) → the commands wrapped in `docker exec`; neither
		// → self-disable, unless the docker CLI exists (daemon/container may
		// not be up yet at boot — stay alive, `cfm detector reload` re-resolves).
		plan, totalCmd, listCmd := planPostfixQueues(section, kv, registrationProbes())
		if plan.disable {
			logging.Logf("[detectors][%s] %s (%s)", section, plan.note, plan.res.Reason)
			return nil, nil
		}
		if plan.note != "" {
			logging.Logf("[detectors][%s] %s", section, plan.note)
		}
		if plan.res.Kind == srcresolve.KindDocker {
			logging.Logf("[detectors][%s] using docker container %s for queue commands (%s)", section, plan.res.Container, plan.res.Reason)
		}

		cfg := postfix.QueuesConfig{
			TotalCmd:    totalCmd,
			ListCmd:     listCmd,
			Every:       kvDur(kv, "EVERY", defEvery),
			Timeout:     kvDur(kv, "TIMEOUT", defTimeout),
			MaxTotal:    kvInt(kv, "QUEUE_TOTAL_MAX", 500),
			MaxFrozen:   kvInt(kv, "QUEUE_FROZEN_MAX", 200),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
		}

		q := postfix.NewQueues(cfg)
		// Name δεν είναι τόσο κρίσιμο εδώ, αλλά βάλε το section για να ξεχωρίζει στα logs
		_ = section
		return q, nil
	})

	Register("postfix_relays", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 5*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		// Enrichment dirs: section overrides global
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

		cfg := postfix.RelaysConfig{
			LogPath:         kvStrClean(kv, "LOG_PATH", ""),
			JournalUnit:     kvStrClean(kv, "JOURNAL_UNIT", ""),
			JournalMatch:    kvStrClean(kv, "JOURNAL_MATCHES", ""),
			DockerContainer: kvStrClean(kv, "DOCKER_CONTAINER", ""),
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", 15*time.Minute),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			Cooldown:        kvDur(kv, "COOLDOWN", defCooldown),

			LocalUserMax:  kvInt(kv, "LOCAL_USER_MAX", 50),
			AuthUserMax:   kvInt(kv, "AUTH_USER_MAX", 50),
			AuthIPMax:     kvInt(kv, "AUTH_IP_MAX", 80),
			AuthUserIPMax: kvInt(kv, "AUTH_USERIP_MAX", 40),
			UnauthIPMax:   kvInt(kv, "UNAUTH_IP_MAX", 20),

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,
		}

		// Optional Docker args (όπως και στο postfix_security)
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

		// Same source plan as postfix_security (JOURNAL_MATCHES passes through
		// verbatim; nil,nil = postfix absent, section auto-disabled).
		if applyPostfixSourcePlan(section, planPostfixLogSource(section, kv, registrationProbes()),
			&cfg.JournalUnit, &cfg.DockerContainer, &cfg.LogPath) {
			return nil, nil
		}

		rr := postfix.NewRelays(cfg)
		rr.SetName(section)
		return rr, nil
	})

}
