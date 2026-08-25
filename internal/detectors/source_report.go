package detectors

// source_report.go — the per-detector source PLANNERS plus the dry-run
// "source resolution report" built on them.
//
// The planners are the single source of truth for how each srcresolve-adopted
// detector picks its log source (resolution + self-disable + provisional
// policy). The registers call them to wire real tailers; SourceReport calls
// the SAME functions to answer "which source would each section use on THIS
// host, and why?" without starting anything — the preview surface behind
// GET /api/v1/detectors/source-resolution, `cfm detectors-srcresolve`, the
// cfm-admin card and the detectors_srcresolve MCP tool. One logic, two
// consumers: the report can never drift from what the registers actually do
// (CLAUDE.md §5).

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cfm/internal/apiserver"
	"cfm/internal/detectors/exim"
	"cfm/internal/detectors/srcresolve"
)

// sourcePlan is one section's resolution outcome, shared by register wiring
// and the dry-run report.
type sourcePlan struct {
	res         srcresolve.Result
	passthrough bool // keep configured keys / package-internal resolution as-is
	disable     bool // section self-disables (register returns nil, nil)
	provisional bool // blind default in use; self-heals when the source appears
	note        string
}

// Presence probes as swappable vars so planner tests never exec
// systemctl/docker on CI.
var (
	eximPresentFn      = eximPresent
	postfixPresentFn   = postfixPresent
	dockerCLIPresentFn = dockerCLIPresent
)

// ── per-detector planners ─────────────────────────────────────────────────────

func planSSHSource(section string, kv KV, p srcresolve.Probes) sourcePlan {
	mode := strings.ToLower(kvStrClean(kv, "MODE", "auto"))
	res := srcresolve.Resolve(srcresolve.Spec{
		Service:           section,
		Mode:              mode,
		JournalUnit:       kvStrClean(kv, "JOURNAL_UNIT", ""),
		LogPath:           kvStrClean(kv, "LOG_PATH", ""),
		JournalCandidates: sshJournalUnits,
		FileCandidates:    sshLogFiles,
	}, p)
	if res.Kind != srcresolve.KindNone {
		return sourcePlan{res: res}
	}
	// Blind historical default: an explicit MODE=file keeps its old default
	// (/var/log/secure); everything else falls back to the journal default.
	why := res.Reason
	pl := sourcePlan{provisional: true, note: "nothing confirmed (" + why + "); tailing the historical default provisionally"}
	if mode == "file" {
		pl.res = srcresolve.Result{Kind: srcresolve.KindFile, Path: sshLogFiles[0], Reason: "provisional default (nothing confirmed)"}
	} else {
		pl.res = srcresolve.Result{Kind: srcresolve.KindJournal, Unit: sshJournalUnits[0], Reason: "provisional default (nothing confirmed)"}
	}
	return pl
}

func planDovecotSource(section string, kv KV, p srcresolve.Probes) sourcePlan {
	mode := strings.ToLower(kvStrClean(kv, "MODE", "auto"))
	res := srcresolve.Resolve(srcresolve.Spec{
		Service:           section,
		Mode:              mode,
		JournalUnit:       kvStrClean(kv, "JOURNAL_UNIT", ""),
		LogPath:           kvStrClean(kv, "LOG_PATH", ""),
		DockerContainer:   kvStrClean(kv, "DOCKER_CONTAINER", ""),
		JournalCandidates: dovecotJournalUnits,
		FileCandidates:    dovecotLogFiles,
		DockerPatterns:    dovecotDockerPatterns,
	}, p)
	if res.Kind != srcresolve.KindNone {
		return sourcePlan{res: res}
	}
	return sourcePlan{
		res:         srcresolve.Result{Kind: srcresolve.KindFile, Path: dovecotLogFiles[0], Reason: "provisional default (nothing confirmed)"},
		provisional: true,
		note:        "nothing confirmed (" + res.Reason + "); tailing the historical default mail log provisionally",
	}
}

// planEximLogSource: file-only (docs/detectors-config-unification.md §3a —
// exim never syslogs its mainlog, so journald is not a candidate).
func planEximLogSource(section string, kv KV, p srcresolve.Probes) sourcePlan {
	res := srcresolve.Resolve(srcresolve.Spec{
		Service:        section,
		Mode:           "auto",
		LogPath:        kvStrClean(kv, "LOG_PATH", ""),
		FileCandidates: exim.MainlogCandidates,
	}, p)
	if res.Kind == srcresolve.KindFile {
		return sourcePlan{res: res}
	}
	if !eximPresentFn() {
		return sourcePlan{res: res, disable: true,
			note: "exim not present (no binary/unit) and no mainlog found; detector disabled (auto)"}
	}
	return sourcePlan{res: res, passthrough: true, provisional: true,
		note: "no mainlog confirmed at the standard locations; deferring to the detector's internal autodetect (provisional)"}
}

func planEximQueues(section string, kv KV) sourcePlan {
	if kvStrClean(kv, "TOTAL_CMD", "") == "" && kvStrClean(kv, "LIST_CMD", "") == "" && !eximPresentFn() {
		return sourcePlan{
			res:     srcresolve.Result{Kind: srcresolve.KindNone, Reason: "exim not present (no binary/unit)"},
			disable: true, note: "exim not present (no binary/unit); detector disabled (auto)",
		}
	}
	return sourcePlan{
		res:         srcresolve.Result{Kind: srcresolve.KindNone, Reason: "command-based section (exim -bpc / exim -bp)"},
		passthrough: true, note: "queue commands run on the host",
	}
}

func planPostfixLogSource(section string, kv KV, p srcresolve.Probes) sourcePlan {
	unit := kvStrClean(kv, "JOURNAL_UNIT", "")
	container := kvStrClean(kv, "DOCKER_CONTAINER", "")
	path := kvStrClean(kv, "LOG_PATH", "")
	mode := strings.ToLower(kvStrClean(kv, "MODE", "auto"))

	// JOURNAL_MATCHES is a raw journalctl match expression the resolver has no
	// notion of — explicit journal config, passed through verbatim.
	if kvStrClean(kv, "JOURNAL_MATCHES", "") != "" {
		return sourcePlan{
			res:         srcresolve.Result{Kind: srcresolve.KindNone, Reason: "explicit JOURNAL_MATCHES"},
			passthrough: true, note: "explicit JOURNAL_MATCHES; journald config used verbatim",
		}
	}
	// More than one explicit source key: the package's historical precedence
	// (journald > docker > file) decides, exactly as before the resolver —
	// never silently reorder an existing config's source choice.
	if explicitSourceKeys(unit, container, path) > 1 {
		return sourcePlan{
			res:         srcresolve.Result{Kind: srcresolve.KindNone, Reason: "multiple explicit source keys"},
			passthrough: true, note: "multiple explicit source keys set; used as-is (journald > docker > file)",
		}
	}

	res := srcresolve.Resolve(srcresolve.Spec{
		Service:           section,
		Mode:              mode,
		JournalUnit:       unit,
		LogPath:           path,
		DockerContainer:   container,
		JournalCandidates: postfixJournalUnits,
		JournalSignature:  postfixJournalSignature,
		FileCandidates:    postfixLogFiles,
		DockerPatterns:    postfixDockerPatterns,
	}, p)
	if res.Kind != srcresolve.KindNone {
		return sourcePlan{res: res}
	}
	if mode != "auto" && mode != "" {
		// Explicit mode that resolved nothing: never cross modes and never
		// self-disable — keep the operator's config exactly as written.
		return sourcePlan{res: res, passthrough: true,
			note: res.Reason + "; keeping explicit config as-is"}
	}
	if !postfixPresentFn() {
		if dockerCLIPresentFn() {
			// Docker exists but no postfix container was discovered — the
			// daemon or container may simply not be up yet (boot ordering).
			// Inconclusive: stay alive on the blind default.
			return sourcePlan{
				res:         srcresolve.Result{Kind: srcresolve.KindFile, Path: postfixLogFiles[1], Reason: "provisional default (docker present, container not found yet)"},
				provisional: true,
				note:        "no postfix found but docker is present (container may not be up yet); `cfm detector reload` re-resolves (" + res.Reason + ")",
			}
		}
		return sourcePlan{res: res, disable: true,
			note: "postfix not present (no binary/unit/container/log); detector disabled (auto)"}
	}
	return sourcePlan{
		res:         srcresolve.Result{Kind: srcresolve.KindFile, Path: postfixLogFiles[1], Reason: "provisional default (nothing confirmed)"},
		provisional: true,
		note:        "no log source confirmed (" + res.Reason + "); tailing the default provisionally",
	}
}

// planPostfixQueues also returns the effective queue commands ("" = let
// postfix.NewQueues fill its exact header-count defaults).
func planPostfixQueues(section string, kv KV, p srcresolve.Probes) (pl sourcePlan, totalCmd, listCmd string) {
	totalCmd = kvStrClean(kv, "TOTAL_CMD", "")
	listCmd = kvStrClean(kv, "LIST_CMD", "")
	if totalCmd != "" || listCmd != "" {
		return sourcePlan{
			res:         srcresolve.Result{Kind: srcresolve.KindNone, Reason: "explicit queue commands"},
			passthrough: true, note: "explicit TOTAL_CMD/LIST_CMD used verbatim",
		}, totalCmd, listCmd
	}
	if postfixPresentFn() {
		return sourcePlan{
			res:         srcresolve.Result{Kind: srcresolve.KindNone, Reason: "host postfix; stock mailq commands"},
			passthrough: true, note: "host postfix; stock mailq commands",
		}, "", ""
	}
	name, ok, why := srcresolve.DiscoverContainer(postfixDockerPatterns, p)
	switch {
	case ok:
		t, l := dockerizePostfixQueueCmds(name)
		return sourcePlan{
			res:  srcresolve.Result{Kind: srcresolve.KindDocker, Container: name, Reason: why},
			note: "queue commands wrapped in docker exec",
		}, t, l
	case dockerCLIPresentFn():
		return sourcePlan{
			res:         srcresolve.Result{Kind: srcresolve.KindNone, Reason: why},
			passthrough: true, provisional: true,
			note: "no postfix found but docker is present (container may not be up yet); keeping host defaults — `cfm detector reload` re-resolves",
		}, "", ""
	default:
		return sourcePlan{
			res:     srcresolve.Result{Kind: srcresolve.KindNone, Reason: "postfix not present (no binary/unit; " + why + ")"},
			disable: true, note: "postfix not present (no binary/unit); detector disabled (auto)",
		}, "", ""
	}
}

// ── the dry-run report ────────────────────────────────────────────────────────

// sourceConfiguredKeys are the source-relevant keys echoed into report rows.
var sourceConfiguredKeys = []string{
	"MODE", "LOG_PATH", "REJECT_LOG_PATH", "JOURNAL_UNIT", "JOURNAL_MATCHES",
	"DOCKER_CONTAINER", "TOTAL_CMD", "LIST_CMD",
}

// legacyAutoTypes still carry their own pre-srcresolve autodetect.
var legacyAutoTypes = map[string]string{
	"ftpd":        "own autodetect (journal probe + file scoring); resolution in its startup log",
	"modsec":      "own autodetect (LOG_PATH=auto candidates); resolution in its startup log",
	"mysql":       "own autodetect (LOG_PATH=auto error-log discovery); resolution in its startup log",
	"webdetector": "edge log configured/derived (MODE=file|folder); see its startup log",
}

// SourceReport answers "which log source would every section in cfgPath use
// on THIS host right now, and why?" by running the SAME planners the
// registers use — probes run (journalctl/systemctl/docker/stat), nothing is
// started or changed. Sections with ENABLED=0 are still planned so the
// operator previews what enabling would do.
func SourceReport(cfgPath string) ([]apiserver.DetectorSourceRow, error) {
	// Layered read — the report must preview the same merged view the manager
	// runs on, overlays included.
	secs, err := ReadLayeredFile(cfgPath)
	if err != nil {
		return nil, err
	}
	// One memoized probe set for the whole report: sections share host-global
	// questions (docker ps, the same journal units), and re-exec'ing them per
	// section would multiply probe timeouts on a wedged docker/systemd.
	probes := srcresolve.MemoProbes(srcresolve.DefaultProbes())

	names := make([]string, 0, len(secs.ByName))
	for name := range secs.ByName {
		if name == "global" || strings.HasSuffix(name, ".leniency") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]apiserver.DetectorSourceRow, 0, len(names))
	for _, name := range names {
		kv := secs.ByName[name]
		typ, _ := SplitTypeInstance(name)
		row := apiserver.DetectorSourceRow{
			Section: name,
			Type:    typ,
			Enabled: kvBool(kv, "ENABLED", true),
		}
		for _, k := range sourceConfiguredKeys {
			if v := kvStrClean(kv, k, ""); v != "" {
				if row.Configured == nil {
					row.Configured = map[string]string{}
				}
				row.Configured[k] = v
			}
		}

		var plan sourcePlan
		switch typ {
		case "ssh_auth":
			plan = planSSHSource(name, kv, probes)
		case "dovecot_auth":
			plan = planDovecotSource(name, kv, probes)
		case "exim_security", "exim_relays":
			plan = planEximLogSource(name, kv, probes)
		case "exim_queues":
			plan = planEximQueues(name, kv)
		case "postfix_security", "postfix_relays":
			plan = planPostfixLogSource(name, kv, probes)
		case "postfix_queues":
			var total string
			plan, total, _ = planPostfixQueues(name, kv, probes)
			if total != "" {
				plan.note = strings.TrimSpace(plan.note + " · total_cmd: " + total)
			}
		default:
			if note, ok := legacyAutoTypes[typ]; ok {
				row.Engine, row.Kind, row.Note = "legacy-auto", "unreported", note
			} else {
				row.Engine, row.Kind, row.Note = "n/a", "none", "no log-source resolution (command/API/collector-based section)"
			}
			rows = append(rows, row)
			continue
		}

		row.Engine = "srcresolve"
		row.Reason = plan.res.Reason
		row.Provisional = plan.provisional
		row.WouldDisable = plan.disable
		row.Note = plan.note
		switch {
		case plan.disable:
			row.Kind = "disabled"
		case plan.passthrough:
			row.Kind = "as-configured"
		default:
			row.Kind = string(plan.res.Kind)
		}
		switch plan.res.Kind {
		case srcresolve.KindJournal:
			row.Target = plan.res.Unit
		case srcresolve.KindFile:
			row.Target = plan.res.Path
		case srcresolve.KindDocker:
			row.Target = plan.res.Container
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func init() {
	apiserver.SetDetectorSourceReport(func(cfgDir string) ([]apiserver.DetectorSourceRow, time.Time, error) {
		rows, err := SourceReport(filepath.Join(cfgDir, "detectors.conf"))
		return rows, time.Now(), err
	})
}
