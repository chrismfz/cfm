// internal/webdetector/challenge_api_handlers.go
package webdetector

import (
	"net/http"
	"strconv"
	"time"
)

// handleChallengeSummary returns global challenge counts.
// Guard 3: global data — admin/loopback only.
func (e *Engine) handleChallengeSummary(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	var sum ChallengeSummary
	if e != nil && e.chalAPI != nil {
		sum = e.chalAPI.Summary()
	}
	// Stamp Under-Attack status even when the challenge store is not wired yet
	// (early startup / chalAPI==nil), so under_attack_enabled never falsely
	// reads disabled. The count is a single locked pass (underAttackHosts is
	// nil-safe, so len() is fine even if the tracker was never created).
	if e != nil {
		sum.UnderAttackEnabled = e.cfg.UnderAttack
		if e.cfg.UnderAttack {
			sum.UnderAttackVhosts = len(e.attack.underAttackHosts())
		}
	}
	writeJSON(w, http.StatusOK, sum)
}

// handleChallengeVhosts lists all currently challenged vhosts.
// Guard 3: lists cross-tenant vhost data — admin/loopback only.
// deriveVhostState places a vhost on the escalation ladder for the API `state`
// field: under_attack (the under-attack tracker has escalated it, incl. an
// operator override) > challenged (a challenge is effectively armed) >
// suspicious (score crossed the arm threshold but not yet armed) > normal.
// Effectiveness is recomputed from the row (Status/Mode/ExpiresAt) via
// vhostEffectivelyActive, so the helper works on a raw stored row and does not
// depend on the caller pre-folding Status. Single-sourced on purpose — every
// surface that reports `state` (handleChallengeVhosts, handleChallengeVhost,
// deriveVhostStateForHost) calls this one helper so they can never drift
// (CLAUDE.md §5).
func (e *Engine) deriveVhostState(v *ChallengeVhostState, now time.Time) string {
	if v == nil {
		return "normal"
	}
	if e != nil {
		if on, _, _ := e.VhostAttackState(v.Host); on {
			return "under_attack"
		}
	}
	if vhostEffectivelyActive(v, now) {
		return "challenged"
	}
	if v.OnThresh > 0 && v.Score >= v.OnThresh {
		return "suspicious"
	}
	return "normal"
}

// deriveVhostStateForHost resolves a host's escalation state from the challenge
// store, for surfaces that have only a host name (the drilldown, the scoped
// status endpoint). Normalizes the host so the exact-key store/tracker lookups
// match how the rows are keyed (a "?host=Example.com:443" must resolve like the
// stored "example.com"). Falls back to a bare row so an under-attack override
// still shows even when the store has no challenge row for the host.
func (e *Engine) deriveVhostStateForHost(host string, now time.Time) string {
	host = normalizeHost(host)
	cv := ChallengeVhostState{Host: host}
	if e != nil && e.chalAPI != nil {
		if v, ok := e.chalAPI.GetVhost(host); ok {
			cv = v
		}
	}
	return e.deriveVhostState(&cv, now)
}

func (e *Engine) handleChallengeVhosts(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	status := r.URL.Query().Get("status")
	mode := r.URL.Query().Get("mode")
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if e == nil || e.chalAPI == nil {
		writeJSON(w, http.StatusOK, []ChallengeVhostState{})
		return
	}
	// This list is store-driven, so a vhost forced UNDER_ATTACK by an operator
	// override that has no challenge store row (never auto/manually challenged)
	// does not appear here — it is still visible via the single-vhost endpoint
	// and the drilldown. The normal path (auto escalation) always has a row.
	rows := e.chalAPI.ListVhosts(status, mode, limit)
	now := time.Now()
	for i := range rows {
		rows[i].SolverFarm = IsSolverFarm(rows[i].Host)
		rows[i].ShadowOutliers = AbuseShadowOutliers(rows[i].Host)
		rows[i].QueryCardinality = FacetShadowCardinality(rows[i].Host)
		rows[i].CostPressure = CostShadowPressure(rows[i].Host)
		rows[i].DCFraction = DCFracShadowPercent(rows[i].Host)
		rows[i].State = e.deriveVhostState(&rows[i], now)
		// Rung rides from the manual store (the verify gate's source), not the
		// row — see ChallengeVhostState.Rung.
		rows[i].Rung = e.manualChallengeRung(rows[i].Host)
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleChallengeVhost returns the challenge state for a single vhost.
// Guard 2: scoped tokens may only query their own vhosts.
func (e *Engine) handleChallengeVhost(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	// Normalise once via the store's own keying function (normalizeHost:
	// trim + lowercase + strip :port), so the lookup stays in lock-step with
	// how RecordVhost* keys the row. The lookup used to run on the raw case
	// while only the scope check lowercased, so a live challenge on
	// "example.com" was missed for a "?host=Example.com" query.
	host := normalizeHost(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	if !vhostAllowed(host, vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	if e == nil || e.chalAPI == nil {
		// Distinct from a genuine not-found: the CLI treats 404 as the normal
		// "no active challenge" answer, so a disabled store must not read as
		// "unchallenged" — surface it.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "challenge API unavailable"})
		return
	}
	v, ok := e.chalAPI.GetVhost(host)
	if !ok {
		// A vhost forced UNDER_ATTACK by an operator override may have no challenge
		// store row (it was never auto/manually challenged). Report it rather than
		// 404 so this surface agrees with the drilldown; otherwise it is a genuine
		// "no active challenge" (the CLI relies on 404 for that).
		if on, since, _ := e.VhostAttackState(host); on {
			writeJSON(w, http.StatusOK, ChallengeVhostState{
				Host: host, Status: "inactive", Mode: "auto", Since: since, State: "under_attack",
			})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	// Report the EFFECTIVE status, matching the list endpoint. The store has no
	// TTL sweeper, so a manual challenge that lapsed with no later auto tick to
	// rewrite the row keeps Status=="active" with a past ExpiresAt. ListVhosts
	// filters those out via vhostEffectivelyActive; without the same fold here
	// the two endpoints disagree and a caller sees status=active / left=expired.
	now := time.Now()
	if !vhostEffectivelyActive(&v, now) {
		v.Status = "inactive"
	}
	v.SolverFarm = IsSolverFarm(v.Host)
	v.ShadowOutliers = AbuseShadowOutliers(v.Host)
	v.QueryCardinality = FacetShadowCardinality(v.Host)
	v.CostPressure = CostShadowPressure(v.Host)
	v.DCFraction = DCFracShadowPercent(v.Host)
	v.State = e.deriveVhostState(&v, now)
	v.Rung = e.manualChallengeRung(v.Host)
	writeJSON(w, http.StatusOK, v)
}

// handleChallengeIPs lists all challenged IPs across the server.
// Guard 3: IP data is inherently cross-tenant — admin/loopback only.
func (e *Engine) handleChallengeIPs(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	state := r.URL.Query().Get("state")
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if e == nil || e.chalAPI == nil {
		writeJSON(w, http.StatusOK, []ChallengeIPState{})
		return
	}
	writeJSON(w, http.StatusOK, e.chalAPI.ListIPs(host, state, limit))
}

// handleChallengeIP returns the challenge state for a single IP.
// Guard 3: IPs are global — admin/loopback only.
func (e *Engine) handleChallengeIP(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ip"})
		return
	}
	if e == nil || e.chalAPI == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	v, ok := e.chalAPI.GetIP(ip)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleChallengeEvents returns recent challenge events.
// Scoped tokens must supply ?host= and it must be within their allowlist.
// Without a host param a scoped token gets 403 — unfiltered events span all tenants.
func (e *Engine) handleChallengeEvents(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	// Normalize to the store's keying (events are recorded under the canonical
	// host), so a mixed-case or port-bearing ?host= filters events instead of
	// silently returning none — the same fix applied to the vhost endpoints.
	host := normalizeHost(r.URL.Query().Get("host"))
	scope := vhostScopeFromContext(r.Context())
	if scope != nil {
		// Scoped token: host is mandatory, and must be in allowlist.
		if host == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "host param required for scoped tokens"})
			return
		}
		if !vhostAllowed(host, scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
			return
		}
	}
	ip := r.URL.Query().Get("ip")
	rule := r.URL.Query().Get("rule")
	typ := r.URL.Query().Get("type")
	limit := challengeEventsDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	limit = clampChallengeEventsLimit(limit)
	if e == nil || e.chalAPI == nil {
		writeJSON(w, http.StatusOK, []ChallengeEvent{})
		return
	}
	writeJSON(w, http.StatusOK, e.chalAPI.Events(host, ip, rule, typ, limit))
}
