package webdetector

import (
	"net/http"
	"strconv"
	"strings"
)

// scopeCheckHost enforces that scoped tokens can only query their own vhosts.
// For admin requests (nil scope) it is a no-op.
// Returns false and writes the error response if the check fails.
func scopeCheckHost(w http.ResponseWriter, r *http.Request, host string) bool {
	if IsAdminRequest(r) {
		return true
	}
	// Scoped token: host is required.
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "host parameter required for scoped tokens",
		})
		return false
	}
	if !vhostAllowed(host, vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "host not in token scope",
		})
		return false
	}
	return true
}

// historyEventView is a HistoryEvent plus GeoIP context, returned when the
// caller asks for enrich=1. Country/ASN come from the enricher at read time
// (bounded: one lookup per unique IP in the returned page), so the forensics
// table can show where an IP is from without storing it per event.
type historyEventView struct {
	HistoryEvent
	Country string `json:"country,omitempty"`
	ASN     uint   `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
}

// redactScopedHistoryRows strips admin-only payload keys from history rows
// before they leave the endpoint for a SCOPED (cPanel) caller. Admin callers
// see the rows untouched.
//
// Today that is exactly payload.sig — the ChallengeV2 Rung-1 device readings
// (hardwareConcurrency, deviceMemory, devicePixelRatio, pointer/touch/key
// counts) collected by CFM's own challenge page. A tenant could measure the
// same things from their own site's JS, so this is not a secret; it is
// nonetheless per-visitor browser-fingerprinting material that CFM gathered,
// and the scoped surface previously exposed nothing of the kind (the UA was
// the most it carried). Scoped-vs-admin is a hard boundary in this repo and
// new categories of data cross it only deliberately, so the default here is
// closed. Nothing is lost operationally: the burn-in readout that sig exists
// for is admin/MCP.
//
// Rows come fresh from QueryEvents (one JSON unmarshal per row), but the
// payload is a reference type, so the key is removed from a COPY — a future
// caching layer in QueryEvents must not find its map mutated by a read.
// Keep the list in sync with docs/endpoint_scope_inventory.md.
func redactScopedHistoryRows(r *http.Request, rows []HistoryEvent) {
	if IsAdminRequest(r) {
		return
	}
	const adminOnlyKey = "sig"
	for i := range rows {
		if _, present := rows[i].Payload[adminOnlyKey]; !present {
			continue
		}
		clean := make(map[string]interface{}, len(rows[i].Payload))
		for k, v := range rows[i].Payload {
			if k == adminOnlyKey {
				continue
			}
			clean[k] = v
		}
		rows[i].Payload = clean
	}
}

func (e *Engine) handleHistoryEvents(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, []HistoryEvent{})
		return
	}
	q := r.URL.Query()
	host := q.Get("host")
	if !scopeCheckHost(w, r, host) {
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	rows, err := e.history.QueryEvents(host, q.Get("ip"), q.Get("type"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	redactScopedHistoryRows(r, rows)
	enrichEnabled := strings.EqualFold(strings.TrimSpace(q.Get("enrich")), "1") || strings.EqualFold(strings.TrimSpace(q.Get("enrich")), "true")
	if !enrichEnabled || e.enr == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"rows": rows})
		return
	}
	type geo struct {
		country string
		asn     uint
		asnName string
	}
	cache := map[string]geo{}
	out := make([]historyEventView, 0, len(rows))
	for _, ev := range rows {
		v := historyEventView{HistoryEvent: ev}
		ip := strings.TrimSpace(ev.IP)
		if ip != "" {
			g, ok := cache[ip]
			if !ok {
				res := e.enr.LookupGeoFast(ip) // per-request loop; Country/ASN only, PTR unused → skip blocking rDNS
				g = geo{country: res.Country, asn: res.ASN, asnName: res.ASNName}
				cache[ip] = g
			}
			v.Country = g.country
			v.ASN = g.asn
			v.ASNName = g.asnName
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rows": out})
}

func (e *Engine) handleHistorySummary(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, HistorySummary{})
		return
	}
	q := r.URL.Query()
	host := q.Get("host")
	if !scopeCheckHost(w, r, host) {
		return
	}
	hours, _ := strconv.Atoi(q.Get("hours"))
	res, err := e.history.Summarize(host, q.Get("ip"), hours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (e *Engine) handleHistoryChallengeOutcomes(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string][]HistoryEvent{"solved": {}, "unsolved": {}})
		return
	}
	q := r.URL.Query()
	host := q.Get("host")
	if !scopeCheckHost(w, r, host) {
		return
	}
	rawLimit, _ := strconv.Atoi(q.Get("limit"))
	if rawLimit <= 0 {
		rawLimit = 200
	}
	const maxChallengeOutcomeLimit = 500
	boundedLimit := rawLimit
	if boundedLimit > maxChallengeOutcomeLimit {
		boundedLimit = maxChallengeOutcomeLimit
	}
	queryLimit := boundedLimit * 4
	maxQueryLimit := maxChallengeOutcomeLimit * 4
	if queryLimit > maxQueryLimit {
		queryLimit = maxQueryLimit
	}
	issued, err := e.history.QueryEvents(host, q.Get("ip"), "challenge_issued", queryLimit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	solvedRows, _ := e.history.QueryEvents(host, q.Get("ip"), "challenge_solved", queryLimit)
	solvedSet := make(map[string]struct{}, len(solvedRows))
	for _, ev := range solvedRows {
		k := strings.TrimSpace(ev.IP) + "|" + cleanHost(ev.Host)
		solvedSet[k] = struct{}{}
	}
	// boundedLimit is clamped above (line 94-97) to maxChallengeOutcomeLimit
	// so these allocations are at most a small fixed constant. CodeQL #562
	// and #563 (2026-05-09 triage) flag these as excessive-size make calls
	// because the interprocedural constant propagation does not track the
	// upstream clamp.
	solved := make([]HistoryEvent, 0, boundedLimit)
	unsolved := make([]HistoryEvent, 0, boundedLimit)
	for _, ev := range issued {
		k := strings.TrimSpace(ev.IP) + "|" + cleanHost(ev.Host)
		if _, ok := solvedSet[k]; ok {
			if len(solved) < boundedLimit {
				solved = append(solved, ev)
			}
		} else if len(unsolved) < boundedLimit {
			unsolved = append(unsolved, ev)
		}
		if len(solved) >= boundedLimit && len(unsolved) >= boundedLimit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"solved": solved, "unsolved": unsolved})
}

// handleHistoryWAFByRule serves:
//
//	GET /api/v1/webdet/history/waf-by-rule?host=X&hours=24
//
// Admin: ?host= optional — omit for global breakdown across all vhosts.
// Scoped token: ?host= required and must be in token scope.
func (e *Engine) handleHistoryWAFByRule(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"rules": []WAFRuleHit{}})
		return
	}
	q := r.URL.Query()
	host := q.Get("host")
	if !scopeCheckHost(w, r, host) {
		return
	}
	hours, _ := strconv.Atoi(q.Get("hours"))
	rules, err := e.history.WAFByRule(host, hours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host": host,
		"hours": func() int {
			if hours <= 0 {
				return 24
			}
			return hours
		}(),
		"rules": rules,
	})
}

// handleHistoryVhostOverview serves:
//
//	GET /api/v1/webdet/history/vhost-overview?host=X&hours=24
//
// Returns the combined Security Overview card data:
// challenge issued/solved/rate + WAF hits + top rule + per-rule breakdown.
// Admin: ?host= optional.
// Scoped token: ?host= required and must be in token scope.
func (e *Engine) handleHistoryVhostOverview(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, VhostOverview{})
		return
	}
	q := r.URL.Query()
	host := q.Get("host")
	if !scopeCheckHost(w, r, host) {
		return
	}
	hours, _ := strconv.Atoi(q.Get("hours"))
	ov, err := e.history.VhostOverviewQuery(host, hours)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (e *Engine) handleHistoryPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !RequireAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string]int64{"rows_deleted": 0})
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 30
	}
	n, err := e.history.Prune(days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rows_deleted": n, "days": days})
}

func (e *Engine) handleHistoryTruncate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if r.URL.Query().Get("confirm") != "yes" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing confirm=yes"})
		return
	}
	if !RequireAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, map[string]int64{"rows_deleted": 0})
		return
	}
	n, err := e.history.Truncate()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"rows_deleted": n})
}

func (e *Engine) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	if e == nil || e.history == nil {
		writeJSON(w, http.StatusOK, HistoryStats{})
		return
	}
	st, err := e.history.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}
