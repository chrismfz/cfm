// internal/webdetector/exclude_api_handlers.go
//
// Challenge and WAF exclude endpoints.
//
// A "host" exclude suppresses challenge/WAF for that hostname across all
// requests. A WAF "path" exclude suppresses the WAF (or some of its rules) for a
// URL path, on every vhost or only on its scope_hosts. A challenge "path"
// exclude is always host-scoped and only stops the malpath checks (below).
//
// Scope model:
//   - list endpoints: admin + scoped tokens can read.
//   - add/remove endpoints:
//       * admin: unrestricted global management.
//       * scoped: host excludes only, and value must stay within token scope.
//   - challenge PATH excludes (challengePathExcludeWrite) are the exception:
//     they carve a path out of the log-driven malpath checks on named hosts
//     only, so they always carry scope_hosts (an admin must name them; a
//     scoped token names a subset of its own vhosts or gets its whole set),
//     and a scoped token may manage them on its own vhosts.

package webdetector

import (
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"cfm/internal/logging"
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
	// The unscoped-write role must be the EXPLICIT admin role, never merely a
	// nil/empty vhost scope. A scoped token with no vhosts (e.g. a DB-only
	// viewer token) also has a nil context scope, so keying on `scope == nil`
	// misclassified it as admin and let it create global / out-of-scope
	// excludes (and, via the shared clam override/mode handlers, flip global
	// scan state). Key on IsAdminRequest and fail closed for everyone else —
	// same posture as waf_hit_rates / scopedMySQLFilterHandler (audit F02).
	if IsAdminRequest(r) {
		return true
	}
	scope := vhostScopeFromContext(r.Context())
	if len(scope) == 0 {
		// Non-admin with no vhost scope: nothing is in scope, so deny.
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(typ), "host") {
		return false
	}
	return scopedExcludeHostAllowed(value, scope)
}

// effectiveExcludeScope resolves the ScopeHosts qualifier an exclude write
// should carry. This is a HARD tenant boundary:
//
//   - A scoped caller is ALWAYS pinned to its own context vhost set. The
//     request cannot widen it, narrow it, or point it elsewhere — any
//     `scope_hosts` query param from a non-admin caller is ignored — so a
//     cPanel tenant can never author an exclude that reaches another tenant's
//     vhost. (A vhost-less scoped token gets a nil scope here, but
//     validateScopedExcludeWrite already rejected its write before this value
//     is used.)
//   - Only an EXPLICIT admin (IsAdminRequest — not merely a nil context scope)
//     may pass a `scope_hosts` qualifier, used to NARROW an otherwise
//     admin-global entry to specific vhosts (e.g. suppress one WAF rule on
//     /wp-admin/admin-ajax.php for a single site). Absent/empty => nil =>
//     admin-global, identical to the behaviour before this param existed.
//
// Because the param can only ever add a host filter, it never broadens an
// exclude beyond what the caller could already create without it.
func effectiveExcludeScope(r *http.Request) map[string]struct{} {
	if !IsAdminRequest(r) {
		return vhostScopeFromContext(r.Context())
	}
	return parseQueryVhostSet(r, "scope_hosts")
}

// scopeHostsSeenBy narrows an entry's scope_hosts (the writing token's whole
// vhost set) to the caller's own vhosts: a scoped caller must not see the
// other domains of whichever account wrote the entry. A new slice; the
// store's copy is untouched.
func scopeHostsSeenBy(hosts []string, scope map[string]struct{}) []string {
	if scope == nil || len(hosts) == 0 {
		return hosts
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if vhostAllowed(strings.ToLower(h), scope) {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
		entry.ScopeHosts = scopeHostsSeenBy(entry.ScopeHosts, scope)
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
//
// A scoped caller sees its in-scope host entries (filterExcludeListForScope)
// and every path entry with at least one scope host it holds, with
// scope_hosts cut to its own vhosts (filterChallengePathExcludesForScope).
func (e *Engine) handleChallengeExcludeList(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	all := e.ChallengeExcludeList()
	if scope == nil {
		writeJSON(w, http.StatusOK, all)
		return
	}
	out := append(filterExcludeListForScope(all, scope), filterChallengePathExcludesForScope(all, scope)...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	writeJSON(w, http.StatusOK, out)
}

// filterChallengePathExcludesForScope returns the challenge path entries a
// scoped caller may see: those with at least one scope host the caller holds
// literally, with scope_hosts cut to those hosts (the writer's other domains
// are not the caller's to see). A path entry without scope_hosts is inert
// (MatchChallengePath) and hidden.
func filterChallengePathExcludesForScope(entries []excludeEntry, scope map[string]struct{}) []excludeEntry {
	var out []excludeEntry
	for _, entry := range entries {
		if !strings.EqualFold(strings.TrimSpace(entry.Type), "path") || len(entry.ScopeHosts) == 0 {
			continue
		}
		seen := scopeHostsSeenBy(entry.ScopeHosts, scope)
		if len(seen) == 0 {
			continue
		}
		entry.ScopeHosts = seen
		out = append(out, entry)
	}
	return out
}

// challengePathExcludeScope resolves the scope_hosts of a challenge path
// exclude write. The entry is ALWAYS host-scoped:
//
//   - admin: `scope_hosts` is required to add (400 without it); a bare `*` is
//     refused, it would exempt the path on every site. A remove without it
//     targets an unscoped entry left by an older version (inert, but listed).
//   - scoped: its vhost set (403 when it has none); a `scope_hosts` param may
//     only NARROW it to vhosts the token holds literally (403 otherwise), so a
//     tenant can never write or remove an entry that reaches another tenant.
func challengePathExcludeScope(r *http.Request, add bool) (map[string]struct{}, int, string) {
	asked := parseQueryVhostSet(r, "scope_hosts")
	if h, wide := matchAllScopeHost(asked); wide {
		return nil, http.StatusBadRequest, "scope_hosts must name hosts, not match (nearly) every host: " + h
	}
	if IsAdminRequest(r) {
		if len(asked) == 0 && add {
			return nil, http.StatusBadRequest, "a path exclude needs scope_hosts (--scope <host>): without it the path would be exempt on every site"
		}
		return asked, 0, ""
	}
	scope := vhostScopeFromContext(r.Context())
	if len(scope) == 0 {
		return nil, http.StatusForbidden, "exclude value outside token scope"
	}
	if len(asked) == 0 {
		// The token's own set becomes the entry's scope: it must not hold a
		// match-all glob either (a `*` vhost would exempt every site).
		if h, wide := matchAllScopeHost(scope); wide {
			return nil, http.StatusForbidden, "token scope matches (nearly) every host (" + h + "): name hosts with scope_hosts"
		}
		return scope, 0, ""
	}
	for h := range asked {
		if !vhostAllowed(h, scope) {
			return nil, http.StatusForbidden, "scope_hosts outside token scope"
		}
	}
	return asked, 0, ""
}

// matchAllScopeHost reports a scope host that is a glob with no literal label
// (`*`, `*.*`, `?*.*`, `[a-z]*`): compileScopeMatcher would match (nearly)
// every host with it. `*.example.gr` keeps a literal label and is fine.
func matchAllScopeHost(hosts map[string]struct{}) (string, bool) {
	for h := range hosts {
		if !strings.ContainsAny(h, "*?[]") {
			continue
		}
		bare := h
		if i := strings.IndexByte(bare, '['); i >= 0 {
			bare = bare[:i] // a class is no literal label
		}
		if strings.Trim(bare, "*?.") == "" || !strings.ContainsAny(strings.Trim(bare, "*?"), "abcdefghijklmnopqrstuvwxyz0123456789-") {
			return h, true
		}
	}
	return "", false
}

// validChallengePathExcludeValue refuses a value with no literal part (`/`,
// `/*`, `/*/*`): it would carve (nearly) the whole site out, which is a host
// exclude and says so. Everything else is a path-segment prefix or an
// anchored glob (compileValueMatcher; `*` stays within one segment), e.g.
// `/images/.tmb/` or `/*/.tmb/*`.
func validChallengePathExcludeValue(value string) bool {
	literal := strings.Map(func(r rune) rune {
		switch r {
		case '/', '*', '?', '[', ']':
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	return literal != ""
}

// challengePathExcludeShared reports a path entry on value that the caller
// can see (one of its hosts is in scope) but not remove (another is not).
func challengePathExcludeShared(entries []excludeEntry, value string, scope map[string]struct{}) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	for _, e := range filterChallengePathExcludesForScope(entries, scope) {
		if e.Value == v {
			return true
		}
	}
	return false
}

// POST /api/v1/challenge/exclude/add|remove?type=path&value=/images/.tmb/[&scope_hosts=a.gr,b.gr]
//
// A host-scoped path carve-out of the log-driven malpath checks
// (CHALLENGE_PATHS and the MALPATH flood counter): a request on one of the
// scope hosts whose path is under value is not counted. The same path on any
// other host, and every other path on these hosts, still is. Scope rules:
// challengePathExcludeScope. Remove targets the entry written with the same
// scope; without an exact match a scoped caller removes every entry on value
// whose scope hosts its token holds all of (its vhost set may have changed
// since the write, and the list shows it scope_hosts cut to its own vhosts;
// removing a carve-out only restores protection).
func (e *Engine) challengePathExcludeWrite(w http.ResponseWriter, r *http.Request, add bool, value string) {
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if add && !validChallengePathExcludeValue(value) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a path exclude must name a path below the site root (use a host exclude for the whole site)"})
		return
	}
	scope, code, msg := challengePathExcludeScope(r, add)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine not ready"})
		return
	}
	if add {
		if !e.ChallengeExcludeAdd("path", value, scope) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to add exclude (invalid or exists)"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	ok := e.ChallengeExcludeRemove("path", value, scope)
	if !ok && !IsAdminRequest(r) {
		token := vhostScopeFromContext(r.Context())
		ok = e.ChallengePathExcludeRemoveWithin(value, token)
		if !ok && challengePathExcludeShared(e.ChallengeExcludeList(), value, token) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this path exclude also covers hosts outside your scope; ask the server administrator to remove it"})
			return
		}
	}
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to remove exclude (invalid or not found)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/challenge/exclude/add?type=host&value=example.com
func (e *Engine) handleChallengeExcludeAdd(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if strings.EqualFold(typ, "path") {
		e.challengePathExcludeWrite(w, r, true, value)
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
	if strings.EqualFold(typ, "path") {
		e.challengePathExcludeWrite(w, r, false, value)
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
	scope := effectiveExcludeScope(r)
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
	scope := effectiveExcludeScope(r)
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

// logClamHostAudit writes the per-vhost clam change trail to the CLAM log:
// who (admin or the token's vhost scope) flipped which host, from where, and
// whether it took. Both the scan override (tag clam_override) and the mode
// override (tag clam_mode) are protection knobs a scoped token may flip for
// its own vhost, so every flip (and every out-of-scope attempt) must be
// reconstructable from cfm.clam.log after the fact.
func logClamHostAudit(r *http.Request, tag, action, value, result string) {
	actor := "admin"
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		hosts := make([]string, 0, len(scope))
		for h := range scope {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		actor = "scoped:" + strings.Join(hosts, ",")
	}
	logging.LogfCLAM("[%s] action=%s host=%q result=%s actor=%s remote=%s",
		tag, action, value, result, actor, r.RemoteAddr)
}

func logClamOverrideAudit(r *http.Request, action, value, result string) {
	logClamHostAudit(r, "clam_override", action, value, result)
}

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
		logClamOverrideAudit(r, "add", value, "denied_out_of_scope")
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
	logClamOverrideAudit(r, "add", value, "ok")
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
		logClamOverrideAudit(r, "remove", value, "denied_out_of_scope")
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
	logClamOverrideAudit(r, "remove", value, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Per-vhost ClamAV scan-MODE override (async vs inline). Same scoped-auth and
// XOR-flip shape as the scan override above, against the SEPARATE mode store:
// a listed host is flipped relative to the global CLAM_SCAN_MODE. A scoped
// token flipping its own vhost to inline blocks only that vhost's uploads —
// self-inflicted and self-serviceable, same trust model as the scan toggle.

// GET /api/v1/clam/mode/list
func (e *Engine) handleClamModeList(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusOK, []excludeEntry{})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	writeJSON(w, http.StatusOK, filterExcludeListForScope(e.ClamModeOverrideList(), scope))
}

// POST /api/v1/clam/mode/add?type=host&value=example.com
func (e *Engine) handleClamModeAdd(w http.ResponseWriter, r *http.Request) {
	e.handleClamModeWrite(w, r, "add", e.ClamModeOverrideAdd)
}

// POST /api/v1/clam/mode/remove?type=host&value=example.com
func (e *Engine) handleClamModeRemove(w http.ResponseWriter, r *http.Request) {
	e.handleClamModeWrite(w, r, "remove", e.ClamModeOverrideRemove)
}

func (e *Engine) handleClamModeWrite(w http.ResponseWriter, r *http.Request, action string, op func(string, string, map[string]struct{}) bool) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	typ, value := readExcludeParams(r)
	if typ != "host" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clam mode override supports type=host only"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if !validateScopedExcludeWrite(r, typ, value) {
		logClamHostAudit(r, "clam_mode", action, value, "denied_out_of_scope")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "value outside token scope"})
		return
	}
	if strings.TrimSpace(value) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing value"})
		return
	}
	if ok := op(typ, value, scope); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to " + action + " mode override"})
		return
	}
	logClamHostAudit(r, "clam_mode", action, value, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
