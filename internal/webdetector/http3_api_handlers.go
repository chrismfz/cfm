// internal/webdetector/http3_api_handlers.go
//
// HTTP/3 per-vhost opt-in REST endpoints. Counterpart to
// exclude_api_handlers.go but with opposite semantics:
//
//   * Default for every vhost is "HTTP/3 DISABLED" (no Alt-Svc).
//   * This API manages the OPT-IN list.
//
// Endpoints:
//   GET    /api/v1/http3/list                       — current opt-in list
//   POST   /api/v1/http3/enable?host=example.com    — opt-in a host
//   POST   /api/v1/http3/disable?host=example.com   — remove opt-in
//
// Scope model: identical to challenge/waf exclude endpoints. Admin tokens
// can manage any host; scoped tokens are limited to hosts inside their
// token scope. Wildcard opt-ins (e.g. "*.cdn.example.com") follow the
// same scopedExcludeHostAllowed rules.

package webdetector

import (
	"net/http"
	"sort"
	"strings"
)

type http3CLIEntry struct {
	Host      string `json:"host"`
	CreatedAt string `json:"created_at"`
}

// filterHTTP3ListForScope returns only the opt-ins a scoped token is
// allowed to see/manage. Admin (scope == nil) gets the full list.
func filterHTTP3ListForScope(entries []http3OverrideEntry, scope map[string]struct{}) []http3OverrideEntry {
	if scope == nil {
		// admin / unscoped — return as-is, already sorted by store.
		return entries
	}
	out := make([]http3OverrideEntry, 0, len(entries))
	for _, e := range entries {
		if scopedExcludeHostAllowed(e.Host, scope) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func validateScopedHTTP3Write(r *http.Request, host string) bool {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return true
	}
	return scopedExcludeHostAllowed(host, scope)
}

// GET /api/v1/http3/list
func (e *Engine) handleHTTP3List(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusOK, []http3OverrideEntry{})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	writeJSON(w, http.StatusOK, filterHTTP3ListForScope(e.HTTP3OverrideList(), scope))
}

// POST /api/v1/http3/enable?host=example.com
//
// Method is enforced as POST (via requirePOST in the apiRoutes table, which
// also emits Allow: POST on a non-POST request) so credentialed cross-origin
// GETs (e.g. <img src=...> on a third-party page loaded by a logged-in admin)
// cannot silently toggle opt-ins.
func (e *Engine) handleHTTP3Enable(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	if !validateScopedHTTP3Write(r, host) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host outside token scope"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if ok := e.HTTP3OverrideAdd(host, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to enable HTTP/3 (invalid host or already enabled)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/http3/disable?host=example.com
//
// See handleHTTP3Enable for the POST-only rationale.
func (e *Engine) handleHTTP3Disable(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	if !validateScopedHTTP3Write(r, host) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host outside token scope"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if ok := e.HTTP3OverrideRemove(host, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to disable HTTP/3 (host not in opt-in list)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
