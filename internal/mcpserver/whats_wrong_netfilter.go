package mcpserver

import (
	"encoding/json"
	"strings"
)

func evalNetfilterPath(body json.RawMessage, sources map[string]string) []finding {
	var report struct {
		Status    string `json:"status"`
		Truncated bool   `json:"truncated"`
		Findings  []struct {
			Level   string `json:"level"`
			Code    string `json:"code"`
			Message string `json:"message"`
			Hook    string `json:"hook"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &report); err != nil || strings.TrimSpace(report.Status) == "" {
		sources["netfilter_path"] = "degraded: invalid netfilter-path evaluation"
		return []finding{{Severity: sevWarning, Category: "firewall", Title: "netfilter diagnostics are degraded", Detail: "the host-wide hook-order report could not be evaluated", Tool: "netfilter_path"}}
	}
	if report.Truncated {
		sources["netfilter_path"] = "degraded: report output was capped"
	}
	out := make([]finding, 0, len(report.Findings))
	for _, nf := range report.Findings {
		level := strings.ToLower(strings.TrimSpace(nf.Level))
		if level != sevWarning && level != sevCritical {
			continue
		}
		title := "netfilter hook-order conflict"
		if nf.Code == "cfm_priority_drift" {
			title = "CFM netfilter priority drift"
		}
		f := finding{Severity: level, Category: "firewall", Title: title, Detail: nf.Message, Tool: "netfilter_path"}
		if nf.Hook != "" {
			f.Args = map[string]any{"hook": nf.Hook}
		}
		out = append(out, f)
	}
	return out
}
