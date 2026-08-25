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

// applyPostfixSourceResolution resolves the log source for a log-based postfix
// detector and rewrites the three source fields so exactly one is set (the
// postfix package wires whichever is non-empty, journald > docker > file).
// Returns disable=true when postfix is nowhere to be found — the register
// should return (nil, nil) so the manager skips the section cleanly.
func applyPostfixSourceResolution(section, mode string, unit, container, path *string) (disable bool) {
	// More than one explicit source key: the package's historical precedence
	// (journald > docker > file) decides, exactly as before the resolver —
	// never silently reorder an existing config's source choice.
	if explicitSourceKeys(*unit, *container, *path) > 1 {
		logging.Logf("[detectors][%s] multiple explicit source keys set; using them as-is (journald > docker > file)", section)
		return false
	}

	res := srcresolve.Resolve(srcresolve.Spec{
		Service:           section,
		Mode:              mode,
		JournalUnit:       *unit,
		LogPath:           *path,
		DockerContainer:   *container,
		JournalCandidates: postfixJournalUnits,
		JournalSignature:  postfixJournalSignature,
		FileCandidates:    postfixLogFiles,
		DockerPatterns:    postfixDockerPatterns,
	}, srcresolve.DefaultProbes())

	switch res.Kind {
	case srcresolve.KindJournal:
		*unit, *container, *path = res.Unit, "", ""
		logging.Logf("[detectors][%s] source=journal unit=%s (%s)", section, res.Unit, res.Reason)
	case srcresolve.KindDocker:
		*unit, *container, *path = "", res.Container, ""
		logging.Logf("[detectors][%s] source=docker container=%s (%s)", section, res.Container, res.Reason)
	case srcresolve.KindFile:
		*unit, *container, *path = "", "", res.Path
		logging.Logf("[detectors][%s] source=file path=%s (%s)", section, res.Path, res.Reason)
	default:
		if !strings.EqualFold(strings.TrimSpace(mode), "auto") && strings.TrimSpace(mode) != "" {
			// Explicit mode that resolved nothing: never cross modes and never
			// self-disable — keep the operator's config exactly as written
			// (pre-resolver semantics: the package wires whatever keys exist).
			logging.Logf("[detectors][%s] %s; keeping explicit config as-is", section, res.Reason)
			return false
		}
		if !postfixPresent() {
			if dockerCLIPresent() {
				// Docker exists but no postfix container was discovered — the
				// daemon or the container may simply not be up yet (boot
				// ordering). Inconclusive: stay alive on the blind default
				// rather than permanently self-disabling, and say how to
				// re-resolve.
				*unit, *container = "", ""
				*path = postfixLogFiles[1] // /var/log/mail.log
				logging.Logf("[detectors][%s] no postfix found but docker is present (container may not be up yet); tailing default %s provisionally — `cfm detector reload` re-resolves (%s)", section, *path, res.Reason)
				return false
			}
			logging.Logf("[detectors][%s] postfix not present (no binary/unit/container/log); detector disabled (auto) — %s", section, res.Reason)
			return true
		}
		// Postfix runs but nothing was confirmed: tail the historical stock
		// default blind — self-heals the moment the log appears.
		*unit, *container = "", ""
		*path = postfixLogFiles[1] // /var/log/mail.log
		logging.Logf("[detectors][%s] no log source confirmed (%s); tailing default %s provisionally", section, res.Reason, *path)
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

		// JOURNAL_MATCHES is a raw journalctl match expression the resolver has
		// no notion of — explicit journal config, passed through verbatim.
		if cfg.JournalMatch == "" {
			mode := strings.ToLower(kvStrClean(kv, "MODE", "auto"))
			if applyPostfixSourceResolution(section, mode, &cfg.JournalUnit, &cfg.DockerContainer, &cfg.LogPath) {
				return nil, nil
			}
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

		// Queue commands: explicit values are the operator's word, used
		// verbatim. With both absent, resolve the environment: host postfix →
		// leave them empty so postfix.NewQueues fills its exact header-count
		// defaults; postfix only in a discovered container (mailcow) → the
		// same commands wrapped in `docker exec` (only the first pipeline
		// segment runs in the container; the pipes stay host-side); neither →
		// the section self-disables instead of failing `mailq` every tick —
		// unless the docker CLI exists (daemon/container may not be up yet at
		// boot: inconclusive, keep the section alive on the host defaults and
		// let `cfm detector reload` re-resolve).
		totalCmd := kvStrClean(kv, "TOTAL_CMD", "")
		listCmd := kvStrClean(kv, "LIST_CMD", "")
		if totalCmd == "" && listCmd == "" && !postfixPresent() {
			name, ok, why := srcresolve.DiscoverContainer(postfixDockerPatterns, srcresolve.DefaultProbes())
			switch {
			case ok:
				totalCmd, listCmd = dockerizePostfixQueueCmds(name)
				logging.Logf("[detectors][%s] using docker container %s for queue commands (%s)", section, name, why)
			case dockerCLIPresent():
				logging.Logf("[detectors][%s] no postfix found but docker is present (container may not be up yet; %s); keeping host defaults — `cfm detector reload` re-resolves", section, why)
			default:
				logging.Logf("[detectors][%s] postfix not present (no binary/unit; %s); detector disabled (auto)", section, why)
				return nil, nil
			}
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

		// Same source resolution as postfix_security (JOURNAL_MATCHES passes
		// through verbatim; nil,nil = postfix absent, section auto-disabled).
		if cfg.JournalMatch == "" {
			mode := strings.ToLower(kvStrClean(kv, "MODE", "auto"))
			if applyPostfixSourceResolution(section, mode, &cfg.JournalUnit, &cfg.DockerContainer, &cfg.LogPath) {
				return nil, nil
			}
		}

		rr := postfix.NewRelays(cfg)
		rr.SetName(section)
		return rr, nil
	})

}
