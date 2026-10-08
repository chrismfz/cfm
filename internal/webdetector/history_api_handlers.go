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

// scopedRedactedPayloadKeys are the history payload keys a scoped caller never
// sees on this surface, and scopedRedactedPayloadPrefix the one key family
// stripped by prefix. The ONE list — docs/endpoint_scope_inventory.md mirrors
// it; redactScopedHistoryRows explains each entry.
var scopedRedactedPayloadKeys = map[string]struct{}{
	"sig":   {},
	"ptr":   {},
	"src":   {},
	"scope": {},
	// The ChallengeV2 arm family (with scopedRedactedPayloadPrefix) and the
	// verify time that times a waiver — the fifth entry in
	// redactScopedHistoryRows: any one of them re-derives the grain.
	"v2": {},
	"ms": {},
	// The solver_farm address sample — the sixth entry: on a cross-host
	// finding it spans every vhost the fingerprint dominates, other tenants'
	// visitors. Generic names, withheld on EVERY row type: a future
	// tenant-facing row that needs an "ips" list must use another key.
	"ips":       {},
	"good_bots": {},
}

// scopedRedactedPayloadPrefix strips every v2_* key (v2_via, v2_waived,
// v2_rescued, v2_waiver_miss, and any added later) by construction, so a new
// member of the family cannot cross the boundary by being left off a list.
const scopedRedactedPayloadPrefix = "v2_"

// isScopedRedactedKey reports whether a payload key is withheld from scoped
// callers: listed in scopedRedactedPayloadKeys or in the v2_* family.
func isScopedRedactedKey(k string) bool {
	if _, ok := scopedRedactedPayloadKeys[k]; ok {
		return true
	}
	return strings.HasPrefix(k, scopedRedactedPayloadPrefix)
}

// hasScopedRedactedKey reports whether a payload carries any withheld key, so
// rows without one are passed through uncopied.
func hasScopedRedactedKey(p map[string]interface{}) bool {
	for k := range p {
		if isScopedRedactedKey(k) {
			return true
		}
	}
	return false
}

// redactScopedHistoryRows strips the payload keys scoped callers never see
// (scopedRedactedPayloadKeys) from history rows before they leave the endpoint
// for a SCOPED (cPanel) caller. Admin callers see the rows untouched.
//
// Six entries today (the fifth and sixth are families of keys). The first is payload.sig — the ChallengeV2 Rung-1 device readings
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
// The second is payload.ptr — the solving client's reverse DNS, on
// challenge_solved and challenge_v2_reject rows. This one is defence in depth,
// NOT a boundary: scoped callers already get a per-IP PTR for their own vhosts
// from /api/v1/webdet/drilldown (HostDetail) and /analyze-host, and anyone
// holding the IP can resolve it. It is stripped here only so the scoped view
// of history rows stays what it was before these rows carried one; nothing
// operational depends on it (FP hunting is admin/MCP). Don't read it as "PTR
// is admin-only". Country and ASN are NOT stripped: enrich=1 already hands
// them to scoped callers. Note the name clash — sig.ptr (a pointer-event
// count, inside sig) goes with sig; this is the top-level payload.ptr.
//
// The third is payload.src — the challenge provenance snapshot on
// challenge_solved and challenge_v2_reject rows (challenge_src.go). Most of
// it a tenant could piece together for its own vhost (its vhost challenge
// state, the challenge_issued rows' detector rule), but two tokens are the
// OPERATOR's fleet policy, not tenant data: `fp` / `geo` say that an
// admin-armed fingerprint or country/ASN policy covers this visitor, and
// `rule:<id>` names an operator traffic rule. Closed by default for the same
// reason as sig; the sizing readout it exists for is admin/MCP.
//
// The fourth is payload.scope — the surface the solve was verified on (web /
// panel:<port>). On a tenant's row a `panel:2087` says the visitor IP used
// WHM through the tenant's hostname: in practice the operator's or a
// reseller's admin address, not tenant data. Closed by default like the
// others; telling panel solves apart is an admin/MCP readout.
//
// The fifth is the ChallengeV2 arm family on challenge_solved and
// challenge_v2_reject rows: v2 (the grain: fp / geo / vhost / mark) and every
// v2_* key (v2_via, v2_waived, v2_rescued, v2_waiver_miss — by prefix), plus
// ms, the server verify time. v2=fp and v2=geo are the same
// operator fleet policy src is stripped for: an admin-armed fingerprint or
// country/ASN policy covered this visitor. The whole family goes because
// each member narrows the grain: v2_via is written only for vhost, a waiver
// (v2_waived, or any v2_waiver_miss but "grain") only happens under geo or
// vhost, and v2_rescued only under an arm — so "v2_waived without v2_via"
// was an exact v2=geo, and with enrich=1 the row's country/ASN then named
// the armed country (the 2026-09-29 review of the first cut, which stripped
// v2 alone). Dropping only fp/geo values would make their absence the tell
// for the same reason. ms goes with them because it times the waiver: it is
// re-measured after the inline good-bot forward-confirm, which runs only
// under geo/vhost, so a waived solve's ms is tens of milliseconds against
// ~0 everywhere else — "waived" again, by the clock (the second review of
// the cut). The tenant loses a tooltip line (cfm-admin's "Server verify
// time") and its own vhost's tier is on the challenge status surfaces. The
// residual is AGGREGATE, not per row: a challenge_v2_reject row still says,
// by existing, that SOME arm covered the visitor, so on a vhost the tenant
// knows is not at v2 its rejects are fp / geo / mark, and if they cluster on
// one country across many fingerprints they point at a country policy (with
// today's armed US policy, they would all say US); a cluster sharing one
// tls_fp across many IPs points at a fingerprint policy. Hiding
// challenge_v2_reject rows from scoped callers altogether would close it, at
// the cost of the tenant's own false-reject view — an operator decision, not
// made here.
//
// The sixth is the solver_farm address sample: payload.ips and the good_bots
// map keyed by those addresses. A solver_farm row is written for ONE vhost
// (its Host, which scopeCheckHost lets that vhost's tenant query), but on a
// cross-host finding (tracks containing cross_host) the sample is drawn from
// the convicted fingerprint's addresses on EVERY vhost it dominates, up to
// 128 (solverfarm.Finding.IPs, xh.ipSample): visitors of OTHER tenants'
// vhosts — and a fingerprint is a population, so a real browser sharing the
// coarse TLS bucket can be among them. That crossed the tenant boundary. A
// per-host finding's sample is the tenant's own solvers, but the keys go
// whole: one rule, and a row reads the same whichever track convicted it.
// The counts stay (distinct_ips / distinct_subnets / distinct_countries,
// hosts, host_share): on a cross-host row they are aggregates, numbers with
// no identity. So does the fingerprint id: evidence, not operator policy,
// and the tenant sees tls_fp on its own solve rows anyway. The fleet store
// pulls these rows with an admin token, so ingestion is unchanged.
//
// The payload map is copied rather than edited so the caller's own map is
// never mutated, but note the LIMIT of that: the slice element is reassigned
// in place, so this is safe only because QueryEvents builds a fresh
// []HistoryEvent with one JSON unmarshal per row on every call. If it ever
// returns a shared or cached slice, this must copy the slice too — otherwise
// the first scoped request would strip sig from the cached row for every
// later admin/MCP read. Keep the key list in sync with
// docs/endpoint_scope_inventory.md.
func redactScopedHistoryRows(r *http.Request, rows []HistoryEvent) {
	if IsAdminRequest(r) {
		return
	}
	for i := range rows {
		if !hasScopedRedactedKey(rows[i].Payload) {
			continue
		}
		clean := make(map[string]interface{}, len(rows[i].Payload))
		for k, v := range rows[i].Payload {
			if isScopedRedactedKey(k) {
				continue
			}
			clean[k] = v
		}
		rows[i].Payload = clean
	}
}

// serverOnlyTypePrefixes are node-fault rows about the whole server, written
// under the node's own hostname: mail abuse (other tenants' subjects, script
// directories, recipients) and backups (other accounts' names). A scoped
// caller whose scope happens to include the hostname must still not read
// them; they are admin (and cfm-web, admin token) only.
var serverOnlyTypePrefixes = []string{"mail_", "backup_"}

func dropServerOnlyRows(r *http.Request, rows []HistoryEvent) []HistoryEvent {
	if IsAdminRequest(r) {
		return rows
	}
	out := rows[:0]
	for _, ev := range rows {
		drop := false
		for _, p := range serverOnlyTypePrefixes {
			if strings.HasPrefix(ev.Type, p) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, ev)
		}
	}
	return out
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
	rows = dropServerOnlyRows(r, rows)
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
	// Same redaction as handleHistoryEvents: `issued` rows are returned to the
	// caller verbatim below, so they pass through the one helper rather than
	// relying on challenge_issued happening not to carry an admin-only key
	// today. `solvedRows` is only read for its (ip,host) keys and never
	// returned, so it needs none.
	redactScopedHistoryRows(r, issued)
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
