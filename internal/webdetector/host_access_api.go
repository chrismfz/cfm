// internal/webdetector/host_access_api.go
//
// GET /api/v1/webdet/host-access-history — on-demand, bounded ARCHIVAL traffic
// profile of ONE vhost, built straight from the edge access log (live file +
// rotated siblings, OpenResty and Angie alike). This is the historical
// complement to host_drilldown / edge_access_tail (both limited to their live
// retention windows): it answers "how much did this domain serve over the last
// N hours, from which IPs, with which user-agents, and when were the peaks?"
// even when the answer lives in rotated .gz files.
//
// The heavy lifting is edgelog.ScanHost (same bounded-scan discipline as
// ip_forensics: shared line budget, timeout, key-capped accumulators, no raw
// lines retained). The optional `combine` section joins the detector-side
// history store (challenge/WAF/block/suspicious events for the SAME host and
// window), so a single call gives the full picture: access-log volume +
// security events.
//
// Scope: scoped-allowed with `vhostAllowed` on ?host= — identical to the
// offline-scan sibling `/api/v1/webdet/analyze-host`. The result is keyed to a
// single vhost, so a scoped token may profile only its own hosts; out-of-scope
// and empty-scope requests fail closed with 403.
package webdetector

import (
	"net/http"
	"strconv"
	"strings"

	"cfm/internal/edgelog"
)

func (e *Engine) handleHostAccessHistory(w http.ResponseWriter, r *http.Request) {
	if err := validateScopedVhostQuery(r, "host"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	// Guard 2: scoped tokens may only profile their own vhosts.
	if !vhostAllowed(strings.ToLower(host), vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	hours, _ := strconv.Atoi(q.Get("hours"))
	maxFiles, _ := strconv.Atoi(q.Get("max_files"))
	tailLines, _ := strconv.Atoi(q.Get("lines"))
	maxLines, _ := strconv.Atoi(q.Get("max_lines"))
	topN, _ := strconv.Atoi(q.Get("top"))
	mergeWWW := q.Get("merge_www") == "1" || strings.EqualFold(q.Get("merge_www"), "true")
	includeRotated := q.Get("include_rotated") != "0" // archival reach is the point; opt OUT explicitly

	// MergeWWW folds the www./bare twin into the result — that twin is a
	// separate vhost key, so a scoped token must have it in scope too
	// (fail-closed; admins pass any pair).
	if mergeWWW {
		if twin := edgelog.WWWTwin(host); !vhostAllowed(twin, vhostScopeFromContext(r.Context())) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "www twin host not in scope"})
			return
		}
	}

	res, err := edgelog.ScanHost(r.Context(), host, edgelog.HostOpts{
		Hours:          hours,
		IncludeRotated: includeRotated,
		MaxFiles:       maxFiles,
		TailLines:      tailLines,
		MaxLines:       maxLines,
		TopN:           topN,
		MergeWWW:       mergeWWW,
		ClassifyUA:     NormalizeUA,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":             false,
			"error":          err.Error(),
			"available_logs": edgelog.AvailableLogs(),
		})
		return
	}

	out := map[string]any{
		"ok":     true,
		"schema": "webdet.host_access_history.v1",
		"host":   res.Host,
		"hours": func() int {
			if hours <= 0 {
				return edgelog.DefaultHostHours
			}
			return hours
		}(),
		"include_rotated": includeRotated,
		"access":          res,
	}

	// Combine section: the detector-side view of the SAME host/window from the
	// history store (challenge issued/solved, block triggers, WAF observed,
	// suspicious, plus the per-rule WAF breakdown). Absent when the store is
	// off or combine=0 — the access section stands alone.
	if q.Get("combine") != "0" && e.history != nil {
		hh := hours
		if hh <= 0 {
			hh = edgelog.DefaultHostHours
		}
		if summary, serr := e.history.Summarize(host, "", hh); serr == nil {
			out["detector_summary"] = summary
		}
		if rules, rerr := e.history.WAFByRule(host, hh); rerr == nil {
			out["detector_waf_by_rule"] = map[string]any{"rules": rules}
		}
	}

	writeJSON(w, http.StatusOK, out)
}
