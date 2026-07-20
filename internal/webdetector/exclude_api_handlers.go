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
	"sort"
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

// readWAFRuleIDsParam parses the rule_ids query parameter. The parameter
// accepts a comma-separated list of: bare ints (320), group prefixes (3xx),
// and inclusive ranges (310-317). An absent or empty parameter returns
// (nil, nil) meaning "no rule scoping" — falls through to legacy whole-WAF
// exclude semantics.
func readWAFRuleIDsParam(r *http.Request) ([]int, error) {
	return parseRuleIDs(r.URL.Query().Get("rule_ids"))
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

func filterExcludeListForScope(entries []excludeEntry, scope map[string]struct{}) []excludeEntry {
	if len(entries) == 0 || scope == nil {
		return entries
	}
	out := make([]excludeEntry, 0, len(entries))
	for _, entry := range entries {
		if !strings.EqualFold(strings.TrimSpace(entry.Type), "host") {
			// Scoped users can only manage host excludes; hide global/path entries.
			continue
		}
		if !scopedExcludeHostAllowed(entry.Value, scope) {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if strings.Join(out[i].ScopeHosts, ",") != strings.Join(out[j].ScopeHosts, ",") {
			return strings.Join(out[i].ScopeHosts, ",") < strings.Join(out[j].ScopeHosts, ",")
		}
		return out[i].Value < out[j].Value
	})
	return out
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
	scope := vhostScopeFromContext(r.Context())
	writeJSON(w, http.StatusOK, filterExcludeListForScope(e.ChallengeExcludeList(), scope))
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
	scope := vhostScopeFromContext(r.Context())
	writeJSON(w, http.StatusOK, filterExcludeListForScope(e.WAFExcludeList(), scope))
}

// POST /api/v1/waf/exclude/add?type=host&value=example.com[&rule_ids=320,3xx,310-317]
//
// rule_ids is optional. When absent/empty the legacy whole-WAF exclude is
// added. When present the entry only suppresses hits whose waf_rule_id is in
// the expanded set; the WAF still runs and other rules can still fire.
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
	ruleIDs, err := readWAFRuleIDsParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rule_ids: " + err.Error()})
		return
	}
	if ok := e.WAFExcludeAddRules(typ, value, scope, ruleIDs); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/waf/exclude/remove?type=host&value=example.com[&rule_ids=320]
//
// rule_ids must match the entry being removed exactly. Absent/empty targets
// the legacy whole-WAF entry; present targets the rule-scoped entry whose
// expanded rule-id set equals this one.
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
	ruleIDs, err := readWAFRuleIDsParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rule_ids: " + err.Error()})
		return
	}
	if ok := e.WAFExcludeRemoveRules(typ, value, scope, ruleIDs); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Per-vhost ClamAV upload-scan override. A listed host is FLIPPED relative to
// the global CLAM_SCAN_DEFAULT (opt-out when the default is ON, opt-in when it
// is OFF) — the XOR is applied at the edge; these handlers just edit the raw
// override set. They reuse the identical scoped-vs-admin auth as the
// WAF/Challenge handlers above (RequireScopedOrAdmin + validateScopedExcludeWrite
// + filterExcludeListForScope), so a scoped cPanel token can toggle only its own
// vhost. HOST type only — upload scanning is a whole-vhost on/off, there is no
// per-path/per-rule clam override.

// GET /api/v1/clam/override/list
func (e *Engine) handleClamOverrideList(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	writeJSON(w, http.StatusOK, filterExcludeListForScope(e.ClamOverrideList(), scope))
}

// POST /api/v1/clam/override/add?type=host&value=example.com
func (e *Engine) handleClamOverrideAdd(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if typ != "host" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clam override supports type=host only"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "exclude value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ClamOverrideAdd(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/clam/override/remove?type=host&value=example.com
func (e *Engine) handleClamOverrideRemove(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if typ != "host" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clam override supports type=host only"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "exclude value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := e.ClamOverrideRemove(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
