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
	if e == nil || e.chalAPI == nil {
		writeJSON(w, http.StatusOK, ChallengeSummary{})
		return
	}
	writeJSON(w, http.StatusOK, e.chalAPI.Summary())
}

// handleChallengeVhosts lists all currently challenged vhosts.
// Guard 3: lists cross-tenant vhost data — admin/loopback only.
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
	rows := e.chalAPI.ListVhosts(status, mode, limit)
	for i := range rows {
		rows[i].SolverFarm = IsSolverFarm(rows[i].Host)
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
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	// Report the EFFECTIVE status, matching the list endpoint. The store has no
	// TTL sweeper, so a manual challenge that lapsed with no later auto tick to
	// rewrite the row keeps Status=="active" with a past ExpiresAt. ListVhosts
	// filters those out via vhostEffectivelyActive; without the same fold here
	// the two endpoints disagree and a caller sees status=active / left=expired.
	if !vhostEffectivelyActive(&v, time.Now()) {
		v.Status = "inactive"
	}
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
