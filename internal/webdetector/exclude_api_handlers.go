// internal/webdetector/exclude_api_handlers.go
//
// Challenge and WAF exclude endpoints.
//
// These excludes are GLOBAL — they affect the entire server, not a single vhost.
// A "host" exclude suppresses challenge/WAF for that hostname across all requests;
// a "path" exclude suppresses it for a URL path across all vhosts.
//
// Scope model:
//   - list endpoints: admin + scoped tokens can read.
//   - add/remove endpoints:
//       * admin: unrestricted global management.
//       * scoped: host excludes only, and value must stay within token scope.

package webdetector

import (
	"net/http"
	"path/filepath"
	"strings"
)

func readExcludeParams(r *http.Request) (string, string) {
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	if typ == "" {
		typ = "host"
	}
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	return typ, value
}

func containsWildcard(s string) bool {
	return strings.ContainsAny(s, "*?")
}

func scopedExcludeHostAllowed(value string, scope map[string]struct{}) bool {
	v := normalizeControlHost(value)
	if v == "" {
		return false
	}
	vWildcard := containsWildcard(v)

	for allowed := range scope {
		a := normalizeControlHost(allowed)
		if a == "" {
			continue
		}
		aWildcard := containsWildcard(a)
		if v == a {
			return true
		}
		// Exact host exclude may target a host matched by scoped wildcard entries.
		if !vWildcard && aWildcard {
			if ok, err := filepath.Match(a, v); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func validateScopedExcludeWrite(r *http.Request, typ, value string) bool {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(typ), "host") {
		return false
	}
	return scopedExcludeHostAllowed(value, scope)
}

// GET /api/v1/challenge/exclude/list
func (e *Engine) handleChallengeExcludeList(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	writeJSON(w, http.StatusOK, e.ChallengeExcludeList())
}

// POST /api/v1/challenge/exclude/add?type=host&value=example.com
func (e *Engine) handleChallengeExcludeAdd(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "exclude value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ChallengeExcludeAdd(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/challenge/exclude/remove?type=host&value=example.com
func (e *Engine) handleChallengeExcludeRemove(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "exclude value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ChallengeExcludeRemove(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/v1/waf/exclude/list
func (e *Engine) handleWAFExcludeList(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	writeJSON(w, http.StatusOK, e.WAFExcludeList())
}

// POST /api/v1/waf/exclude/add?type=host&value=example.com
func (e *Engine) handleWAFExcludeAdd(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "exclude value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.WAFExcludeAdd(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/waf/exclude/remove?type=host&value=example.com
func (e *Engine) handleWAFExcludeRemove(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "exclude value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.WAFExcludeRemove(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
