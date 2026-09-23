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
//   GET  /api/v1/site-cache/list                 — policies (scope-filtered), plus
//                                                  `unloadable`: hosts whose stored
//                                                  policy this build cannot load
//   GET  /api/v1/site-cache/get?host=            — one vhost's policy
//   POST /api/v1/site-cache/set                  — merge-upsert (body = SiteCachePatch);
//                                                  both tiers off = an explicit opt-out
//                                                  (also under a broader armed wildcard)
//   POST /api/v1/site-cache/remove?host=         — DELETE a vhost's policy (the host
//                                                  then follows a covering *.suffix)
//   POST /api/v1/site-cache/purge?host= | ?all=1 — bump generation (all=admin)
//   GET  /api/v1/site-cache/stats[?host=]        — per-vhost cache verdict counts
//                                                  (site_cache_stats.go)

package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"cfm/internal/logging"
)

type siteCacheListResponse struct {
	Rows []SiteCacheEntry `json:"rows"`
	// Unloadable lists the hosts of stored policies this build cannot load (a
	// newer build's recipe or field after a downgrade, or a host this version
	// no longer accepts) that have no row in Rows: the edge treats each as
	// OPTED OUT (never cached), not as "no entry". Scope-filtered like Rows.
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
		writeJSON(w, http.StatusNotFound, siteCacheResultResponse{Error: e.siteCacheNoPolicyMsg(host)})
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
		logSiteCacheAudit(r, "set", host, "denied", "host not in scope")
		writeJSON(w, http.StatusForbidden, siteCacheResultResponse{Error: "host not in scope"})
		return
	}
	// WHO first enabled it (audit) comes from the token, never the body: a
	// scoped caller creating the policy is recorded as scope_hosts=[host], an
	// admin as nothing (see SiteCacheEntry.ScopeHosts).
	scoped := vhostScopeFromContext(r.Context()) != nil
	entry, err := e.SiteCacheApply(req, scoped)
	if err != nil {
		logSiteCacheAudit(r, "set", host, "rejected", err.Error())
		writeJSON(w, http.StatusBadRequest, siteCacheResultResponse{Error: err.Error()})
		return
	}
	logSiteCacheAudit(r, "set", entry.Host, "ok", siteCacheAuditState(entry))
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
		logSiteCacheAudit(r, "remove", host, "denied", "host not in scope")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	if !e.SiteCacheRemove(host) {
		logSiteCacheAudit(r, "remove", host, "notfound", "")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no cache policy for host"})
		return
	}
	logSiteCacheAudit(r, "remove", siteCacheCanonHost(host), "ok", "")
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
		if !IsAdminRequest(r) {
			logSiteCacheAudit(r, "purge-all", "*", "denied", "admin only")
		}
		if !RequireAdmin(w, r) {
			return
		}
		n := e.SiteCachePurgeAll()
		logSiteCacheAudit(r, "purge-all", "*", "ok", fmt.Sprintf("purged=%d", n))
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "purged": n})
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host (or all=1)"})
		return
	}
	if !scopeAllowsVhosts(r, []string{host}) {
		logSiteCacheAudit(r, "purge", host, "denied", "host not in scope")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	entry, ok := e.SiteCachePurge(host)
	if !ok {
		logSiteCacheAudit(r, "purge", host, "notfound", "")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": e.siteCacheNoPolicyMsg(host)})
		return
	}
	logSiteCacheAudit(r, "purge", entry.Host, "ok", fmt.Sprintf("gen=%d", entry.Generation))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "generation": entry.Generation})
}

// logSiteCacheAudit writes the Site Cache lifecycle trail to cfm.log: every
// authenticated set / remove / purge / purge-all that names a host (or all) —
// including those refused for scope, admin-only or validation — with WHO
// (admin, or the scoped token's vhosts), from where and what resulted. Not
// logged: unauthenticated calls (no identity to record) and bodies that fail
// before naming a host (invalid JSON, no host). result=notfound is also what
// a failed save of a remove/purge reports (the store logs the failure itself). A policy decides what the edge caches, a scoped
// tenant may change its own, and an opt-out or an edit of a `*.x` pattern a
// token's scope holds changes what an admin wildcard does, so each change
// must be reconstructable afterwards (the exclude/clam precedent). The CLI
// goes through this API, and the MCP tools only read, so the handlers are the
// single choke point. result: ok | notfound | rejected | denied.
func logSiteCacheAudit(r *http.Request, action, host, result, detail string) {
	logging.Logf("%s", formatSiteCacheAudit(r, action, host, result, detail))
}

// formatSiteCacheAudit renders the audit line (split out for tests).
func formatSiteCacheAudit(r *http.Request, action, host, result, detail string) string {
	actor := "admin"
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		hosts := make([]string, 0, len(scope))
		for h := range scope {
			// a scope host is admin-minted, but keep it one field anyway
			hosts = append(hosts, strings.Map(func(r rune) rune {
				if r <= ' ' || r == '"' || r == 0x7f {
					return '_'
				}
				return r
			}, h))
		}
		sort.Strings(hosts)
		if len(hosts) > 5 { // a large token scope must not balloon every line
			hosts = append(hosts[:5], fmt.Sprintf("…(+%d)", len(hosts)-5))
		}
		actor = "scoped:" + strings.Join(hosts, ",")
	}
	line := fmt.Sprintf("[site_cache] action=%s host=%q result=%s actor=%s remote=%s", action, siteCacheAuditClip(host, 256), result, actor, r.RemoteAddr)
	if detail != "" {
		line += fmt.Sprintf(" detail=%q", siteCacheAuditClip(detail, 512))
	}
	return line
}

// siteCacheAuditClip bounds a caller-supplied audit field: a request can carry
// a host of up to the header limit (~1 MiB), and a scoped token may repeat it.
func siteCacheAuditClip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("…(+%d bytes)", len(s)-max)
}

// siteCacheAuditState summarises a stored policy for the audit line.
func siteCacheAuditState(e SiteCacheEntry) string {
	tier := func(t SiteCacheTier) string {
		if !t.Enabled {
			return "off"
		}
		if t.TTL != "" {
			return t.Recipe + "/" + t.TTL
		}
		return t.Recipe
	}
	return fmt.Sprintf("static=%s micro=%s strict_cookies=%t auth_cookies=%d gen=%d",
		tier(e.Static), tier(e.Micro), e.StrictCookies, len(e.AuthCookies), e.Generation)
}

// siteCacheNoPolicyMsg explains a 404 for host: plainly "no policy", or — when
// the host's stored policy is one this build cannot load — why it has none.
// Callers have already scope-checked host.
func (e *Engine) siteCacheNoPolicyMsg(host string) string {
	if h := siteCacheCanonHost(host); h != "" {
		for _, f := range e.SiteCacheFrozenHosts() {
			if f != h {
				continue
			}
			if siteCacheHostError(h) != nil {
				// `off` would be rejected (an invalid host for a new policy),
				// and a newer build would not read it either.
				return siteCacheUnloadableMsg + "; its host is not valid in this version: remove it"
			}
			return siteCacheUnloadableMsg + "; remove it, turn it off (which replaces it), or — if a newer version wrote it — upgrade"
		}
	}
	return "no cache policy for host"
}

// isTruthyParam treats 1/true/yes/on (case-insensitive) as true.
func isTruthyParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
