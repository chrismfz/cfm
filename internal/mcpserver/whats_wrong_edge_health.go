package mcpserver

import (
	"encoding/json"
	"strings"
)

// whats_wrong_edge_health.go maps the edge_health report
// (/api/v1/system/edge-health) into whats_wrong findings.
//
// Why this section exists: whats_wrong evaluated the edge's *liveness*
// (edge_status / frontend_working, via evalHealth) but nothing about the
// edge→origin HOP. In a 2026-09 incident an Angie node's Apache workers were
// segfaulting in mod_brotli — ~900 requests a day across dozens of vhosts died
// with `upstream prematurely closed connection` — and whats_wrong returned
// "2 warning", neither of them this. The edge was up, the origin unit was
// "active", every host metric was green, so the only symptom was 502s that a
// human had to stumble into. edge_health already had the log access to see it;
// it just was not wired into triage. Now it is.
//
// Mapping policy — this layer adds NO thresholds of its own. The endpoint has
// the logs and the calibrated rates; here we only rank an already-classified
// severity:
//
//   - critical → a critical finding
//   - warn     → a warning finding
//   - ok / unknown → NO finding. `unknown` means a signal could not be read
//     (no access log, unparseable engine version), which is not evidence of a
//     problem; emitting it would fire on every node that merely hides its
//     version string. It stays visible via the edge_health tool, and a section
//     that fails outright is recorded in whats_wrong's `sources`.
func evalEdgeHealth(body json.RawMessage) []finding {
	var p struct {
		Findings []struct {
			Check    string `json:"check"`
			Severity string `json:"severity"`
			Summary  string `json:"summary"`
			Next     string `json:"next"`
		} `json:"findings"`
	}
	if json.Unmarshal(body, &p) != nil {
		return nil
	}
	var fs []finding
	for _, f := range p.Findings {
		var sev string
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "critical":
			sev = sevCritical
		case "warn":
			sev = sevWarning
		default:
			continue // ok / unknown → not a finding (see policy above)
		}
		detail := strings.TrimSpace(f.Summary)
		if n := strings.TrimSpace(f.Next); n != "" {
			detail += " → " + n
		}
		fs = append(fs, finding{
			Severity: sev,
			Category: "edge",
			Title:    edgeHealthTitle(f.Check),
			Detail:   detail,
			Tool:     "edge_health",
		})
	}
	return fs
}

// edgeHealthCheckTitles gives each edge_health check a human title. It is a
// presentation nicety ONLY: an unmapped check falls back to its own check name
// rather than being dropped, so a check added to the endpoint still reaches
// triage without this map having to be updated in lockstep (CLAUDE.md §5 — no
// second copy of a list that can silently drift).
var edgeHealthCheckTitles = map[string]string{
	"origin-premature-close": "origin dropping connections",
	"origin-421-fingerprint": "cross-SNI 421 origin reuse",
	"engine-version-trap":    "edge upstream-keepalive trap",
	"origin-ka-tier":         "origin keepalive degraded",
}

func edgeHealthTitle(check string) string {
	if t, ok := edgeHealthCheckTitles[check]; ok {
		return t
	}
	if c := strings.TrimSpace(check); c != "" {
		return c
	}
	return "edge health"
}
