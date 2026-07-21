package webdetector

import (
	"net/http"
	"sort"
	"strings"

	"cfm/internal/logging"
)

// Per-signature ClamAV exclude endpoints (sig-ignore). A matching entry
// downgrades an infected verdict to log-only — no CLAM/INFECTED notification,
// no quarantine (see internal/clam/sigignore.go).
//
// Scope model (deliberately tighter than the on/off override):
//   - GLOBAL entries (host = "") weaken detection for every tenant → admin-only.
//   - HOST entries: admin any host; a scoped token only hosts inside its vhost
//     scope (vhostAllowed), so a cPanel user can neutralise an FP on their own
//     vhost and nothing else.
//   - list: admin sees everything; scoped tokens see ONLY their own hosts'
//     entries (global entries are admin policy, not tenant data).
//
// Every write and every denied attempt is audit-logged to cfm.clam.log —
// same reconstructability requirement as the scan override.

func clamSigIgnoreParams(r *http.Request) (host, pattern string) {
	host = strings.TrimSpace(r.URL.Query().Get("host"))
	pattern = strings.TrimSpace(r.URL.Query().Get("pattern"))
	return host, pattern
}

func logClamSigIgnoreAudit(r *http.Request, action, host, pattern, result string) {
	if host == "" {
		host = "(global)"
	}
	actor := "admin"
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		hosts := make([]string, 0, len(scope))
		for h := range scope {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		actor = "scoped:" + strings.Join(hosts, ",")
	}
	logging.LogfCLAM("[clam_sigignore] action=%s host=%q pattern=%q result=%s actor=%s remote=%s",
		action, host, pattern, result, actor, r.RemoteAddr)
}

// validateScopedSigIgnoreWrite enforces the write rules above. Fail-closed:
// a scoped token gets true only for a non-empty host inside its scope.
func validateScopedSigIgnoreWrite(r *http.Request, host string) bool {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return true // admin: any host, or global (host == "")
	}
	if host == "" {
		return false // global entries are admin-only
	}
	return vhostAllowed(host, scope)
}

// GET /api/v1/clam/sigignore/list
func (e *Engine) handleClamSigIgnoreList(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	entries := e.ClamSigIgnoreList()
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		filtered := make([]clamSigIgnoreEntry, 0, len(entries))
		for _, en := range entries {
			if en.Host != "" && vhostAllowed(en.Host, scope) {
				filtered = append(filtered, en)
			}
		}
		entries = filtered
	}
	if entries == nil {
		entries = []clamSigIgnoreEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// POST /api/v1/clam/sigignore/add?pattern=<glob>[&host=<vhost>]
func (e *Engine) handleClamSigIgnoreAdd(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	host, pattern := clamSigIgnoreParams(r)
	host = normalizeControlHost(host)
	if pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing pattern"})
		return
	}
	if !validateScopedSigIgnoreWrite(r, host) {
		logClamSigIgnoreAudit(r, "add", host, pattern, "denied_out_of_scope")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host outside token scope (global entries are admin-only)"})
		return
	}
	var scopeHosts []string
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		for h := range scope {
			scopeHosts = append(scopeHosts, h)
		}
	}
	if ok := e.ClamSigIgnoreAdd(host, pattern, scopeHosts); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add (invalid pattern or exists)"})
		return
	}
	logClamSigIgnoreAudit(r, "add", host, pattern, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/clam/sigignore/remove?pattern=<glob>[&host=<vhost>]
func (e *Engine) handleClamSigIgnoreRemove(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	host, pattern := clamSigIgnoreParams(r)
	host = normalizeControlHost(host)
	if pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing pattern"})
		return
	}
	if !validateScopedSigIgnoreWrite(r, host) {
		logClamSigIgnoreAudit(r, "remove", host, pattern, "denied_out_of_scope")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host outside token scope (global entries are admin-only)"})
		return
	}
	if ok := e.ClamSigIgnoreRemove(host, pattern); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove (invalid or not found)"})
		return
	}
	logClamSigIgnoreAudit(r, "remove", host, pattern, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
