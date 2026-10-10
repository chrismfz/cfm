package detectors

import (
	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	"strings"
)

type OutcomeLoggerSink struct{}

func (OutcomeLoggerSink) Publish(a core.Alert) {

	// WEB/CHALLENGE can be extremely noisy. We already log challenge activity
	// to cfm.challenges.log, so keep cfm.detector.log focused on real outcomes.
	//
	// Suppress ONLY the "plain challenge" outcome (no escalation). If the
	// challenge escalates to a block, we still log it here.
	if a.Kind == "WEB/CHALLENGE" && a.Extra != nil && a.Extra["blocked"] == "challenge" && a.Extra["escalated"] == "" {
		return
	}

	lim := ""
	if a.Extra != nil {
		lim = a.Extra["limit"]
	}
	blocked := outcomeBlocked(a.Extra)

	format := "\nTime:  %s\nType:  %s, %s\nCount: %d"
	if lim != "" {
		format += " (limit: %s)"
	}
	format += "\nBlocked: %s\n\nSample of the first %d lines:\n\n%s\n"

	if lim != "" {
		logging.LogfDETECTOR(
			format,
			a.When.Format("Mon Jan 2 15:04:05 2006 -0700"),
			a.Kind, a.Key, a.Count, lim,
			blocked,
			len(a.Samples),
			joinLines(a.Samples),
		)
		return
	}
	logging.LogfDETECTOR(
		format,
		a.When.Format("Mon Jan 2 15:04:05 2006 -0700"),
		a.Kind, a.Key, a.Count,
		blocked,
		len(a.Samples),
		joinLines(a.Samples),
	)
}

// outcomeBlocked is the "Blocked:" value of the detector log line, from the
// outcome Extra the section sink set.
func outcomeBlocked(extra map[string]string) string {
	blocked := "No"
	if extra != nil {
		switch extra["blocked"] {
		case "dryrun":
			blocked = "DryRun"

		case "challenge":
			// show challenge result
			if t := extra["ttl"]; t != "" {
				blocked = "Challenged (ttl=" + t + ")"
			} else {
				blocked = "Challenged"
			}
			if esc := extra["escalated"]; esc != "" {
				if bt := extra["block_ttl"]; bt != "" {
					blocked += " -> Escalated: " + esc + " (ttl=" + bt
					if extra["block_kept"] == "longer" {
						blocked += "; longer ban kept"
					}
					blocked += ")"
				} else {
					blocked += " -> Escalated: " + esc
				}
			}

		case "yes":
			switch extra["block_mode"] {
			case "permanent":
				blocked = "Yes (permanent)"
			case "ttl":
				if t := extra["ttl"]; t != "" {
					blocked = "Yes (ttl=" + t + ")"
				} else {
					blocked = "Yes (ttl)"
				}
				// A longer (or permanent) ban was already in place and stays.
				if extra["block_kept"] == "longer" {
					blocked = strings.TrimSuffix(blocked, ")") + "; longer ban kept)"
				}
			default:
				blocked = "Yes"
			}

		case "":
			// The firewall refused the block (autoblock_sink sets block_err).
			if e := extra["block_err"]; e != "" {
				if len(e) > 160 {
					e = e[:160] + "…"
				}
				blocked = "No (block failed: " + e + ")"
			}
		}
	}
	return blocked
}
