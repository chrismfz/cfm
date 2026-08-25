// internal/webdetector/host_access_api.go
//
// GET /api/v1/webdet/host-access-history — on-demand, bounded ARCHIVAL traffic
// profile of ONE vhost, built straight from the edge access log (live file +
// rotated siblings, OpenResty and Angie alike). This is the historical
// complement to host_drilldown / edge_access_tail (both limited to their live
// retention windows): it answers "how much did this domain actually serve over
// the last N hours, from which IPs, with which user-agents, and when were the
// peaks?" even when the answer lives in rotated .gz files.
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
// and empty-scope requests fail closed with 403. With merge_www=1 the www/bare
// TWIN is a separate vhost key and must also be in scope.
//
// Admission control: one call may decompress tens of millions of log lines for
// up to two minutes, so concurrent archive scans are capped node-wide
// (hostAccessScanSlots); beyond the cap callers get 429 + Retry-After instead
// of queueing behind minutes-long scans.
package webdetector

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"cfm/internal/edgelog"
)

// hostAccessScanSlots caps concurrent archive scans NODE-WIDE (admin or
// scoped alike — the cost is identical). Sized 2: enough overlap for a couple
// of operators/tools, small enough that scans cannot starve the box's I/O.
var hostAccessScanSlots = make(chan struct{}, 2)

const hostAccessRetryAfterSec = "30"

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
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Guard 2: scoped tokens may only profile their own vhosts.
	scope := vhostScopeFromContext(r.Context())
	if !vhostAllowed(strings.ToLower(host), scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

	// hours is normalized EXACTLY ONCE here and feeds every section below
	// (access scan, detector history, response field), so they can never
	// disagree about the window. Malformed values are a client error, not a
	// silent default.
	hh := edgelog.DefaultHostHours
	if raw := strings.TrimSpace(q.Get("hours")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid hours (positive integer)"})
			return
		}
		hh = n
	}
	if hh > edgelog.MaxHostHours {
		hh = edgelog.MaxHostHours
	}

	mergeWWW := q.Get("merge_www") == "1" || strings.EqualFold(q.Get("merge_www"), "true")
	// MergeWWW folds the www./bare twin into the result — that twin is a
	// separate vhost key, so a scoped token must have it in scope too
	// (fail-closed; admins pass any pair).
	if mergeWWW {
		if twin := edgelog.WWWTwin(host); !vhostAllowed(twin, scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "www twin host not in scope"})
			return
		}
	}
	includeRotated := q.Get("include_rotated") != "0" // archival reach is the point; opt OUT explicitly

	maxFiles, _ := strconv.Atoi(q.Get("max_files"))
	tailLines, _ := strconv.Atoi(q.Get("lines"))
	maxLines, _ := strconv.Atoi(q.Get("max_lines"))
	topN, _ := strconv.Atoi(q.Get("top"))

	// Admission: never queue behind another multi-minute scan — fail fast.
	select {
	case hostAccessScanSlots <- struct{}{}:
		defer func() { <-hostAccessScanSlots }()
	default:
		w.Header().Set("Retry-After", hostAccessRetryAfterSec)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "another archival host scan is running on this node; retry shortly",
		})
		return
	}

	res, err := edgelog.ScanHost(r.Context(), host, edgelog.HostOpts{
		Hours:          hh,
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
			"available_logs": edgelog.AvailableFullLogs(),
		})
		return
	}

	out := map[string]any{
		"ok":              true,
		"schema":          "webdet.host_access_history.v1",
		"host":            res.Host,
		"hours":           hh,
		"include_rotated": includeRotated,
		"access":          res,
	}

	// Combine section: the detector-side view of the SAME host/window from the
	// history store. With merge_www the twins are queried SEPARATELY and both
	// a combined view and a per-host breakdown are returned — merging only the
	// traffic side while leaving security events single-host would make
	// "crawlers or attack?" answers misleading. Absent when the store is off
	// or combine=0 — the access section stands alone.
	if q.Get("combine") == "0" || e.history == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}

	hostLower := strings.ToLower(res.Host)
	hosts := []string{hostLower}
	if mergeWWW {
		hosts = append(hosts, strings.ToLower(edgelog.WWWTwin(hostLower)))
		sort.Strings(hosts)
	}

	type histView struct {
		summary HistorySummary
		rules   []WAFRuleHit
		failed  bool
	}
	views := make(map[string]histView, len(hosts))
	for _, h := range hosts {
		var v histView
		// Range-aware queries over EXACTLY the access scan's absolute window
		// ([from,to)) — never an independently-sampled time.Now() — so the
		// detector counts describe the same seconds as the traffic profile.
		// The rule breakdown uses the OBSERVATION-only universe so its total
		// reconciles with summary.waf_observed (a physical hit that emitted
		// trigger+observation is not counted twice).
		s, serr := e.history.SummarizeRange(h, "", res.WindowFromUnix, res.WindowToUnix)
		rs, rerr := e.history.WAFObservedByRuleRange(h, res.WindowFromUnix, res.WindowToUnix)
		if serr != nil || rerr != nil {
			v.failed = true
			views[h] = v
			continue
		}
		v.summary, v.rules = s, rs
		views[h] = v
	}

	started := false
	anyFailed := false
	var combined HistorySummary
	var combinedRules []WAFRuleHit
	byHost := make(map[string]any, len(hosts))
	for _, h := range hosts {
		v := views[h]
		if v.failed {
			anyFailed = true
			byHost[h] = map[string]any{"unavailable": true}
			continue
		}
		if !started {
			combined = v.summary
			combinedRules = append([]WAFRuleHit(nil), v.rules...)
			started = true
		} else {
			combined = sumHistorySummaries(combined, v.summary)
			combinedRules = mergeWAFRuleHits(combinedRules, v.rules)
		}
		byHost[h] = map[string]any{
			"summary":     v.summary,
			"waf_by_rule": map[string]any{"rules": v.rules},
		}
	}
	if !started {
		// History completely unavailable — omit the detector numbers but say
		// so explicitly; combine=1 must never degrade into a silent
		// access-only response.
		out["detector_unavailable"] = true
		writeJSON(w, http.StatusOK, out)
		return
	}

	out["detector_summary"] = combined
	out["detector_waf_by_rule"] = map[string]any{"rules": combinedRules}

	// Coverage honesty: the history store prunes on its own retention clock,
	// so a 90-day request against a 30-day store would otherwise return
	// partial counts that LOOK complete. Report the real retained span and a
	// proven flag next to every detector number. NB the flag is conservative
	// in one direction: false means "completeness cannot be PROVEN from the
	// retained rows" (e.g. the first-ever event is newer than the window's
	// start) — it is evidence of coverage, not a definite gap assertion.
	oldest := e.history.OldestEventUnix()
	out["detector_coverage"] = map[string]any{
		"requested_from_unix": res.WindowFromUnix,
		"requested_to_unix":   res.WindowToUnix,
		"retention_days":      e.history.RetentionDays(),
		"oldest_event_unix":   oldest,
		"coverage_proven":     oldest > 0 && oldest <= res.WindowFromUnix,
	}

	if len(hosts) > 1 {
		out["detector_by_host"] = byHost
	}
	if anyFailed {
		// At least one twin's history query failed: the top-level "combined"
		// view is really combined-over-available. Never let it pass as full.
		out["detector_partial"] = true
	}

	writeJSON(w, http.StatusOK, out)
}

// sumHistorySummaries adds b into a field-by-field (same query window, so the
// time bounds carry over unchanged).
func sumHistorySummaries(a, b HistorySummary) HistorySummary {
	a.TotalEvents += b.TotalEvents
	a.ChallengeIssued += b.ChallengeIssued
	a.ChallengeSolved += b.ChallengeSolved
	a.ChallengeExpiredUnsolved += b.ChallengeExpiredUnsolved
	a.ChallengeEscalated += b.ChallengeEscalated
	a.BlockTriggers += b.BlockTriggers
	a.WAFObserved += b.WAFObserved
	a.Suspicious += b.Suspicious
	return a
}

// mergeWAFRuleHits merges per-rule hit counts, highest count first (name asc
// tiebreak) — same ranking discipline as the top lists.
func mergeWAFRuleHits(lists ...[]WAFRuleHit) []WAFRuleHit {
	counts := map[string]int{}
	for _, l := range lists {
		for _, rh := range l {
			counts[rh.Rule] += rh.Count
		}
	}
	out := make([]WAFRuleHit, 0, len(counts))
	for rule, c := range counts {
		out = append(out, WAFRuleHit{Rule: rule, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}
