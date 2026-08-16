package mcpserver

import (
	"encoding/json"
	"fmt"
	"strings"
)

// evalProcessHealth maps the already-classified process-health endpoint into
// whats_wrong findings. Threshold policy stays in procstat.EvaluateHealth; this
// layer deliberately does not re-classify raw process counts.
func evalProcessHealth(body json.RawMessage, sources map[string]string) []finding {
	var p struct {
		Evaluation *struct {
			Status   string `json:"status"`
			Reliable bool   `json:"reliable"`
			Reason   string `json:"reason"`
			Findings []struct {
				Code        string `json:"code"`
				Severity    string `json:"severity"`
				State       string `json:"state"`
				Count       int    `json:"count"`
				Percent     float64 `json:"percent"`
				TopFamilies []struct {
					Comm  string `json:"comm"`
					Count int    `json:"count"`
				} `json:"top_families"`
				Detail string `json:"detail"`
			} `json:"findings"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Evaluation == nil {
		return processHealthDegradedFinding(sources, "process-health response has no valid evaluation")
	}

	e := p.Evaluation
	if e.Status == "degraded" || !e.Reliable {
		reason := strings.TrimSpace(e.Reason)
		if reason == "" {
			reason = "process-health evaluation is not reliable"
		}
		return processHealthDegradedFinding(sources, reason)
	}

	switch e.Status {
	case "ok":
		if len(e.Findings) != 0 {
			return processHealthDegradedFinding(sources, "process-health evaluation is inconsistent: status=ok with findings")
		}
		return nil
	case "issues":
		if len(e.Findings) == 0 {
			return processHealthDegradedFinding(sources, "process-health evaluation is inconsistent: status=issues without findings")
		}
	default:
		return processHealthDegradedFinding(sources, fmt.Sprintf("process-health evaluation has unknown status %q", e.Status))
	}

	out := make([]finding, 0, len(e.Findings))
	for _, pf := range e.Findings {
		sev := pf.Severity
		if sev != sevCritical && sev != sevWarning {
			sev = sevWarning
		}

		title := "process-health anomaly"
		switch pf.Code {
		case "process_d_state_pileup":
			title = "D-state process pileup"
		case "process_zombie_accumulation":
			title = "zombie processes accumulating"
		case "":
			// Keep the generic title.
		default:
			title += ": " + pf.Code
		}

		detail := strings.TrimSpace(pf.Detail)
		if detail == "" {
			detail = fmt.Sprintf("state=%s count=%d (%.1f%% of readable processes)", pf.State, pf.Count, pf.Percent)
		}

		tool := "process_health"
		var args map[string]any
		if len(pf.TopFamilies) > 0 {
			if comm := strings.TrimSpace(pf.TopFamilies[0].Comm); comm != "" {
				tool = "process_list"
				args = map[string]any{"match": comm, "details": true}
			}
		}

		out = append(out, finding{sev, "process", title, detail, tool, args})
	}
	return out
}

func processHealthDegradedFinding(sources map[string]string, reason string) []finding {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "process-health evaluation is not reliable"
	}
	sources["process_health"] = "degraded: " + reason
	return []finding{{
		Severity: sevWarning,
		Category: "process",
		Title:    "process-health snapshot degraded",
		Detail:   reason,
		Tool:     "process_health",
	}}
}
