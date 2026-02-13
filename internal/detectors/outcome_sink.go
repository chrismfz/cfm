package detectors

import (
	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
)

type OutcomeLoggerSink struct{}

func (OutcomeLoggerSink) Publish(a core.Alert) {
	lim := ""
	if a.Extra != nil {
		lim = a.Extra["limit"]
	}
	// Determine outcome from Extra (set by sectionSink)
	blocked := "No"
	if a.Extra != nil {
		switch a.Extra["blocked"] {
		case "dryrun":
			blocked = "DryRun"

               case "challenge":
                        // show challenge result
                        if t := a.Extra["ttl"]; t != "" {
                                blocked = "Challenged (ttl=" + t + ")"
                        } else {
                                blocked = "Challenged"
                        }
                        if esc := a.Extra["escalated"]; esc != "" {
                                if bt := a.Extra["block_ttl"]; bt != "" {
                                        blocked += " -> Escalated: " + esc + " (ttl=" + bt + ")"
                                } else {
                                        blocked += " -> Escalated: " + esc
                                }
                        }


		case "yes":
			switch a.Extra["block_mode"] {
			case "permanent":
				blocked = "Yes (permanent)"
			case "ttl":
				if t := a.Extra["ttl"]; t != "" {
					blocked = "Yes (ttl=" + t + ")"
				} else {
					blocked = "Yes (ttl)"
				}
			default:
				blocked = "Yes"
			}
		}
	}

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
