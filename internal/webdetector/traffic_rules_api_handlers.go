// internal/webdetector/traffic_rules_api_handlers.go
//
// HTTP handlers for the traffic rules CRUD API.
//
// Security model:
//   - Admin token / loopback bypass → vhostScopeFromContext returns nil → full access.
//   - Scoped token (cPanel/DA plugin) → vhostScopeFromContext returns allowlist map.
//
// Three guards used throughout:
//   scopeFilterRules  – for list: returns only rules whose scope intersects token allowlist.
//   scopeAllowsVhosts – for write/read single: all named vhosts must be in allowlist.
//   (implicit nil check) – callers use vhostScopeFromContext directly for host params.
//
// Body size: all POST handlers cap at maxRuleBodyBytes (64 KiB) to prevent
// memory exhaustion from oversized payloads.

package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
)

const maxRuleBodyBytes = 64 << 10 // 64 KiB — generous for any rule payload

// ── Scope helpers ────────────────────────────────────────────────────────────

// scopeAllowsVhosts returns true when the request carries no scope restriction
// (admin / loopback) OR when every vhost in the list is within the token's
// allowlist. An empty vhosts list always returns false.
func scopeAllowsVhosts(r *http.Request, vhosts []string) bool {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return true // admin token or loopback — unrestricted
	}
	if len(vhosts) == 0 {
		return false
	}
	for _, h := range vhosts {
		if !vhostAllowed(strings.ToLower(h), scope) {
			return false
		}
	}
	return true
}

// scopeFilterRules returns only rules whose scope.vhosts intersect the token's
// allowlist. When scope is nil (admin / loopback) all rules are returned as-is.
func scopeFilterRules(rules []TrafficRule, r *http.Request) []TrafficRule {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return rules
	}
	out := make([]TrafficRule, 0, len(rules))
	for _, rule := range rules {
		for _, h := range rule.Scope.Vhosts {
			if vhostAllowed(strings.ToLower(h), scope) {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}

// ── Response types ───────────────────────────────────────────────────────────

type trafficRuleListResponse struct {
	Rows []TrafficRule `json:"rows"`
}

type trafficRuleResultResponse struct {
	Rule  TrafficRule `json:"rule,omitempty"`
	Error string      `json:"error,omitempty"`
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// GET /api/v1/webdet/rules
// Scoped tokens receive only rules that touch their allowed vhosts.
func (e *Engine) handleWebdetRulesList(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, trafficRuleListResponse{Rows: nil})
		return
	}
	rows := scopeFilterRules(e.TrafficRuleList(), r)
	writeJSON(w, http.StatusOK, trafficRuleListResponse{Rows: rows})
}

// GET /api/v1/webdet/rules/get?id=<id>
// Scoped tokens may only retrieve rules that belong to their vhosts.
func (e *Engine) handleWebdetRulesGet(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusNotFound, trafficRuleResultResponse{Error: "engine unavailable"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "missing id"})
		return
	}
	rule, ok := e.TrafficRuleGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, trafficRuleResultResponse{Error: "rule not found"})
		return
	}
	// Scope check: does this rule touch any vhost the caller is allowed to see?
	if !scopeAllowsVhosts(r, rule.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, trafficRuleResultResponse{Error: "rule not in scope"})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleResultResponse{Rule: rule})
}

// POST /api/v1/webdet/rules/add
// Scoped tokens may only create rules whose scope.vhosts are all in their allowlist.
func (e *Engine) handleWebdetRulesAdd(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, trafficRuleResultResponse{Error: "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, trafficRuleResultResponse{Error: "method not allowed"})
		return
	}

	var req TrafficRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "invalid json: " + err.Error()})
		return
	}

	// Scope check before any write: all target vhosts must be in token allowlist.
	if !scopeAllowsVhosts(r, req.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, trafficRuleResultResponse{Error: "vhost not in scope"})
		return
	}

	rule, err := e.TrafficRuleAdd(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleResultResponse{Rule: rule})
}

// POST /api/v1/webdet/rules/update?id=<id>
// Scoped tokens may only update rules they can see AND must keep vhosts in scope.
func (e *Engine) handleWebdetRulesUpdate(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, trafficRuleResultResponse{Error: "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, trafficRuleResultResponse{Error: "method not allowed"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "missing id"})
		return
	}

	// Fetch existing rule first — we need its vhosts for scope check.
	existing, ok := e.TrafficRuleGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, trafficRuleResultResponse{Error: "rule not found"})
		return
	}
	// Must have access to the current rule.
	if !scopeAllowsVhosts(r, existing.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, trafficRuleResultResponse{Error: "rule not in scope"})
		return
	}

	var req TrafficRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, trafficRuleResultResponse{Error: "invalid json: " + err.Error()})
		return
	}

	// Must also be allowed to write to the new vhosts (prevents scope escalation).
	if !scopeAllowsVhosts(r, req.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, trafficRuleResultResponse{Error: "target vhost not in scope"})
		return
	}

	rule, err := e.TrafficRuleUpdate(id, req)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			code = http.StatusNotFound
		}
		writeJSON(w, code, trafficRuleResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, trafficRuleResultResponse{Rule: rule})
}

// POST /api/v1/webdet/rules/remove?id=<id>
// Scoped tokens may only remove rules that belong to their vhosts.
func (e *Engine) handleWebdetRulesRemove(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	// Fetch first so we can scope-check before deleting.
	existing, ok := e.TrafficRuleGet(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	if !scopeAllowsVhosts(r, existing.Scope.Vhosts) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "rule not in scope"})
		return
	}

	if !e.TrafficRuleRemove(id) {
		// Tiny race window between Get and Remove — handle gracefully.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/webdet/rules/simulate
// Scoped tokens may only simulate against hosts in their allowlist.
func (e *Engine) handleWebdetRulesSimulate(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "traffic rules store unavailable"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req TrafficRuleEvalInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	// Scope check: scoped token may only simulate against its own vhosts.
	if !scopeAllowsVhosts(r, []string{host}) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

	res := e.TrafficRuleSimulateForAPI(r.Context(), req)
	writeJSON(w, http.StatusOK, res)
}
