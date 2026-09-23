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
//   POST /api/v1/site-cache/set                  — merge-upsert (body = SiteCachePatch);
//                                                  both tiers off = an explicit opt-out
//                                                  (also under a broader armed wildcard)
//   POST /api/v1/site-cache/remove?host=         — DELETE a vhost's policy (the host
//                                                  then follows a covering *.suffix)
//   POST /api/v1/site-cache/purge?host= | ?all=1 — bump generation (all=admin)

package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
)

type siteCacheListResponse struct {
	Rows []SiteCacheEntry `json:"rows"`
	// Unloadable lists the hosts of stored policies this build cannot load (a
	// newer build's recipe or field, after a downgrade): they are not in Rows,
	// and the edge treats each as OPTED OUT (never cached), not as "no entry".
	// Scope-filtered like Rows.
	Unloadable []string `json:"unloadable,omitempty"`
}

type siteCacheResultResponse struct {
	// A pointer so an error response carries no entry at all (omitempty is a
	// no-op on a struct value, which used to marshal a zero entry beside the
	// error).
	Entry *SiteCacheEntry `json:"entry,omitempty"`
	Error string          `json:"error,omitempty"`
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
	var unloadable []string
	scope := vhostScopeFromContext(r.Context())
	for _, h := range e.SiteCacheFrozenHosts() {
		if vhostAllowed(h, scope) {
			unloadable = append(unloadable, h)
		}
	}
	writeJSON(w, http.StatusOK, siteCacheListResponse{Rows: scopeFilterSiteCache(e.SiteCacheList(), r), Unloadable: unloadable})
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
		msg := "no cache policy for host"
		if h, valid := e.siteCache.normalize(host); valid && e.siteCache != nil {
			for _, f := range e.SiteCacheFrozenHosts() {
				if f == h {
					msg = "this host has a stored policy this build cannot load (see the daemon log): it is treated as opted out (never cached); remove it, or upgrade"
					break
				}
			}
		}
		writeJSON(w, http.StatusNotFound, siteCacheResultResponse{Error: msg})
		return
	}
	writeJSON(w, http.StatusOK, siteCacheResultResponse{Entry: &entry})
}

// POST /api/v1/site-cache/set  (merge-upsert; host carried in the JSON body)
//
// The body is a SiteCachePatch: only the fields present are changed, the rest
// of the stored policy is kept. So `{"host":"x","micro":{"ttl":"30s"}}` retunes
// one TTL without touching the static tier or the cookie settings. A NEW host
// must enable a tier, or turn BOTH off explicitly (an opt-out — see Apply).
// Clearing takes an explicit value: `"strict_cookies":false`,
// `"auth_cookies":[]`, `"ttl":""`. A SiteCacheEntry as returned by get is
// accepted too, but its omitempty fields drop exactly those values, so posting
// an edited entry back cannot clear them (it keeps them — the safe direction);
// and it always carries both tiers' "enabled", so for a NEW host with both
// false it creates an opt-out.
// generation / created_at / scope_hosts in a body are ignored: server-managed.
func (e *Engine) handleSiteCacheSet(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, siteCacheResultResponse{Error: "engine unavailable"})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	var req SiteCachePatch
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
	// WHO first enabled it (audit) comes from the token, never the body: a
	// scoped caller creating the policy is recorded as scope_hosts=[host], an
	// admin as nothing (see SiteCacheEntry.ScopeHosts).
	scoped := vhostScopeFromContext(r.Context()) != nil
	entry, err := e.SiteCacheApply(req, scoped)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, siteCacheResultResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, siteCacheResultResponse{Entry: &entry})
}

// POST /api/v1/site-cache/remove?host=<host>
//
// DELETES the vhost's policy. With no entry the host is uncached — unless an
// armed "*.suffix" wildcard covers it, which then applies (its cache for the
// host included). To keep a host uncached under a wildcard, set BOTH tiers off
// instead: that stored opt-out is what the CLI's `off` does.
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
