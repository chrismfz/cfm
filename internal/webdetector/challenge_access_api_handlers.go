// internal/webdetector/challenge_access_api_handlers.go
//
// HTTP handlers for the Challenge Access-Control CRUD API (challenge exemption
// allow-list; see challenge_access.go).
//
// Security model — identical to the traffic-rules handlers:
//   - Admin token / loopback → vhostScopeFromContext returns nil → full access.
//   - Scoped token (cPanel/DA plugin) → allowlist map; every vhost in an
//     entry's scope must be inside the token's allowlist (scopeAllowsVhosts),
//     and list results are filtered to the caller's own vhosts. Unlike the
//     host-only challenge-exclude API, a scoped caller MAY use the richer match
//     dimensions (path/ua/country/ip/asn) — but always pinned under a vhost in
//     its own scope, so it can never affect another tenant.
//
// Body size: POST handlers cap at maxRuleBodyBytes (shared with traffic rules).

package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
)

type challengeAccessListResponse struct {
	Rows []ChallengeAccessEntry `json:"rows"`
}

type challengeAccessResultResponse struct {
	Entry ChallengeAccessEntry `json:"entry,omitempty"`
	Error string               `json:"error,omitempty"`
}

// scopeFilterChallengeAccess returns only entries whose scope.vhosts intersect
// the token's allowlist. nil scope (admin / loopback) returns all entries.
func scopeFilterChallengeAccess(entries []ChallengeAccessEntry, r *http.Request) []ChallengeAccessEntry {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return entries
	}
	out := make([]ChallengeAccessEntry, 0, len(entries))
	for _, e := range entries {
		for _, h := range e.Scope.Vhosts {
			if vhostAllowed(strings.ToLower(h), scope) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// GET /api/v1/challenge/access
func (e *Engine) handleChallengeAccessList(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, challengeAccessListResponse{Rows: nil})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	rows := scopeFilterChallengeAccess(e.ChallengeAccessList(), r)
	writeJSON(w, http.StatusOK, challengeAccessListResponse{Rows: rows})
}

// GET /api/v1/challenge/access/get?id=<id>
func (e *Engine) handleChallengeAccessGet(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusNotFound, challengeAccessResultResponse{Error: "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, challengeAccessResultResponse{Error: "missing id"})
		return
	}
	entry, ok := e.ChallengeAccessGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, challengeAccessResultResponse{Error: "entry not found"})
		return
	}
	if !scopeAllowsVhosts(r, entry.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, challengeAccessResultResponse{Error: "entry not in scope"})
		return
	}
	writeJSON(w, http.StatusOK, challengeAccessResultResponse{Entry: entry})
}

// POST /api/v1/challenge/access/add
func (e *Engine) handleChallengeAccessAdd(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, challengeAccessResultResponse{Error: "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	var req ChallengeAccessEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, challengeAccessResultResponse{Error: "invalid json: " + err.Error()})
		return
	}
	// Scope check before any write: all target vhosts must be in token allowlist.
	if !scopeAllowsVhosts(r, req.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, challengeAccessResultResponse{Error: "vhost not in scope"})
		return
	}
	entry, err := e.ChallengeAccessAdd(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, challengeAccessResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, challengeAccessResultResponse{Entry: entry})
}

// POST /api/v1/challenge/access/update?id=<id>
func (e *Engine) handleChallengeAccessUpdate(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, challengeAccessResultResponse{Error: "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, challengeAccessResultResponse{Error: "missing id"})
		return
	}
	existing, ok := e.ChallengeAccessGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, challengeAccessResultResponse{Error: "entry not found"})
		return
	}
	// Must have access to the current entry.
	if !scopeAllowsVhosts(r, existing.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, challengeAccessResultResponse{Error: "entry not in scope"})
		return
	}
	var req ChallengeAccessEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, challengeAccessResultResponse{Error: "invalid json: " + err.Error()})
		return
	}
	// Must also be allowed to write to the new vhosts (prevents scope escalation).
	if !scopeAllowsVhosts(r, req.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, challengeAccessResultResponse{Error: "target vhost not in scope"})
		return
	}
	entry, err := e.ChallengeAccessUpdate(id, req)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			code = http.StatusNotFound
		}
		writeJSON(w, code, challengeAccessResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, challengeAccessResultResponse{Entry: entry})
}

// POST /api/v1/challenge/access/remove?id=<id>
func (e *Engine) handleChallengeAccessRemove(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}
	existing, ok := e.ChallengeAccessGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}
	if !scopeAllowsVhosts(r, existing.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "entry not in scope"})
		return
	}
	if !e.ChallengeAccessRemove(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "entry not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
