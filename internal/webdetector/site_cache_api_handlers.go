// internal/webdetector/site_cache_api_handlers.go
//
// HTTP handlers for the Site Cache per-vhost CRUD API (see site_cache.go and
// docs/site-cache-design.md).
//
// Security model — identical to the http3 / challenge-access handlers:
//   - Admin token / loopback → vhostScopeFromContext returns nil → full access.
//   - Scoped token (cPanel plugin) → allowlist map; a write's target host must
//     be inside the token's allowlist (scopeAllowsVhosts), and list results are
//     filtered to the caller's own hosts. A scoped cPanel user gets the SAME
//     power as an admin over their OWN vhosts (any recipe, custom TTL, OFF,
//     per-host purge) — but never another tenant's host. Purge-all is
//     admin-only.
//
// Endpoints:
//   GET  /api/v1/site-cache/list                 — policies (scope-filtered)
//   GET  /api/v1/site-cache/get?host=            — one vhost's policy
//   POST /api/v1/site-cache/set                  — upsert (body = SiteCacheEntry)
//   POST /api/v1/site-cache/remove?host=         — turn caching OFF for a vhost
//   POST /api/v1/site-cache/purge?host= | ?all=1 — bump generation (all=admin)

package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
)

type siteCacheListResponse struct {
	Rows []SiteCacheEntry `json:"rows"`
}

type siteCacheResultResponse struct {
	Entry SiteCacheEntry `json:"entry,omitempty"`
	Error string         `json:"error,omitempty"`
}

// scopeFilterSiteCache returns only the policies a scoped token may see/manage
// (host inside the token allowlist). nil scope (admin/loopback) returns all.
func scopeFilterSiteCache(entries []SiteCacheEntry, r *http.Request) []SiteCacheEntry {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return entries
	}
	out := make([]SiteCacheEntry, 0, len(entries))
	for _, e := range entries {
		if vhostAllowed(strings.ToLower(e.Host), scope) {
			out = append(out, e)
		}
	}
	return out
}

// GET /api/v1/site-cache/list
func (e *Engine) handleSiteCacheList(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, siteCacheListResponse{Rows: nil})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, siteCacheListResponse{Rows: scopeFilterSiteCache(e.SiteCacheList(), r)})
}

// GET /api/v1/site-cache/get?host=<host>
func (e *Engine) handleSiteCacheGet(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusNotFound, siteCacheResultResponse{Error: "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, siteCacheResultResponse{Error: "missing host"})
		return
	}
	if !scopeAllowsVhosts(r, []string{host}) {
		writeJSON(w, http.StatusForbidden, siteCacheResultResponse{Error: "host not in scope"})
		return
	}
	entry, ok := e.SiteCacheGet(host)
	if !ok {
		writeJSON(w, http.StatusNotFound, siteCacheResultResponse{Error: "no cache policy for host"})
		return
	}
	writeJSON(w, http.StatusOK, siteCacheResultResponse{Entry: entry})
}

// POST /api/v1/site-cache/set  (upsert; host carried in the JSON body)
func (e *Engine) handleSiteCacheSet(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, siteCacheResultResponse{Error: "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	var req SiteCacheEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleBodyBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, siteCacheResultResponse{Error: "invalid json: " + err.Error()})
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, siteCacheResultResponse{Error: "missing host"})
		return
	}
	// Scope check before any write: the target host must be in the token scope.
	if !scopeAllowsVhosts(r, []string{host}) {
		writeJSON(w, http.StatusForbidden, siteCacheResultResponse{Error: "host not in scope"})
		return
	}
	// Stamp WHO added it (audit) from the token scope; the client value is
	// ignored so a caller cannot forge a foreign audit trail. Admin (nil scope)
	// records no scope_hosts (global/admin-added).
	req.ScopeHosts = scopeMapToHosts(vhostScopeFromContext(r.Context()))
	entry, err := e.SiteCacheSet(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, siteCacheResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, siteCacheResultResponse{Entry: entry})
}

// POST /api/v1/site-cache/remove?host=<host>
func (e *Engine) handleSiteCacheRemove(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	if !scopeAllowsVhosts(r, []string{host}) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	if !e.SiteCacheRemove(host) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no cache policy for host"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/site-cache/purge?host=<host>   (per-vhost; admin or owning scoped)
// POST /api/v1/site-cache/purge?all=1         (global; admin only)
func (e *Engine) handleSiteCachePurge(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if isTruthyParam(r.URL.Query().Get("all")) {
		// Global purge spans every tenant → admin only.
		if !RequireAdmin(w, r) {
			return
		}
		n := e.SiteCachePurgeAll()
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "purged": n})
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host (or all=1)"})
		return
	}
	if !scopeAllowsVhosts(r, []string{host}) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	entry, ok := e.SiteCachePurge(host)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no cache policy for host"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "generation": entry.Generation})
}

// isTruthyParam treats 1/true/yes/on (case-insensitive) as true.
func isTruthyParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
