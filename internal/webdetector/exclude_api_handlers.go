// internal/webdetector/exclude_api_handlers.go
//
// Challenge and WAF exclude endpoints.
//
// These excludes are GLOBAL — they affect the entire server, not a single vhost.
// A "host" exclude suppresses challenge/WAF for that hostname across all requests;
// a "path" exclude suppresses it for a URL path across all vhosts.
//
// Because of this global scope, all endpoints (list, add, remove) are Guard 3:
// admin token or loopback bypass required. Scoped cPanel/DA tokens cannot
// manipulate global excludes.

package webdetector

import (
	"net/http"
	"strings"
)

// adminRequired returns true and writes 403 when the request carries a scoped
// token. Inline helper used by every handler in this file.
func adminRequired(w http.ResponseWriter, r *http.Request) bool {
	if vhostScopeFromContext(r.Context()) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin token required"})
		return true
	}
	return false
}

func readExcludeParams(r *http.Request) (string, string) {
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	if typ == "" {
		typ = "host"
	}
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	return typ, value
}

// GET /api/v1/challenge/exclude/list
func (e *Engine) handleChallengeExcludeList(w http.ResponseWriter, r *http.Request) {
	if adminRequired(w, r) {
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
	if adminRequired(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ChallengeExcludeAdd(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/challenge/exclude/remove?type=host&value=example.com
func (e *Engine) handleChallengeExcludeRemove(w http.ResponseWriter, r *http.Request) {
	if adminRequired(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ChallengeExcludeRemove(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/v1/waf/exclude/list
func (e *Engine) handleWAFExcludeList(w http.ResponseWriter, r *http.Request) {
	if adminRequired(w, r) {
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
	if adminRequired(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.WAFExcludeAdd(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/waf/exclude/remove?type=host&value=example.com
func (e *Engine) handleWAFExcludeRemove(w http.ResponseWriter, r *http.Request) {
	if adminRequired(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.WAFExcludeRemove(typ, value); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
