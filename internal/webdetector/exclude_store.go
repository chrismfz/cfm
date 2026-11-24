package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type excludeEntry struct {
	Type       string   `json:"type"` // host | path
	Value      string   `json:"value"`
	ScopeHosts []string `json:"scope_hosts,omitempty"` // nil/empty => admin-global
	// RuleIDs limits this exclude to specific WAF rule IDs. nil/empty means
	// "whole-WAF skip" (back-compat). When set, the WAF still runs but any
	// hit whose waf_rule_id is in this set is suppressed. Two entries with
	// the same (type, value, scope) but different RuleIDs are distinct.
	RuleIDs   []int     `json:"rule_ids,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type excludeStore struct {
	mu               sync.RWMutex
	path             string
	entries          map[string]excludeEntry // key = type:value
	challengeEntries []compiledExcludeEntry
	wafEntries       []compiledExcludeEntry
	pathEntries      []compiledExcludeEntry
	// Lock-free count of challengeEntries, so the hot MatchChallenge path (called
	// for every host every reconcile) can short-circuit the common zero-excludes
	// case without taking mu / normalising the host. Written under mu in
	// rebuildCompiledLocked, read atomically. Int64 so the len(int)->count store
	// is a safe widening conversion (no gosec G115 narrowing); the count is tiny.
	challengeCount atomic.Int64
	// Lock-free count of the SCOPED path entries (MatchChallengePath's fast
	// path: it runs for every malpath hit under the engine lock).
	pathCount atomic.Int64
}

type compiledExcludeEntry struct {
	Type    string
	Scope   compiledScopeMatcher
	Value   compiledValueMatcher
	RuleIDs []int  // nil/empty => whole-WAF skip
	Raw     string // the stored value, for log lines
	Scoped  bool   // ScopeHosts non-empty
	Entry   excludeEntry
}

type compiledScopeMatcher struct {
	// scoped: the entry named scope hosts. Without it the matcher takes every
	// host; with it, only the hosts below, so a scope whose every glob failed
	// to compile takes no host (it once read as "no scope" = every host).
	scoped bool
	exact  map[string]struct{}
	wild   []*regexp.Regexp
}

type compiledValueMatcher struct {
	literal string // non-glob literal, matched at a domain/path boundary (NOT substring)
	kind    string // "host" or "path" — boundary semantics for a literal
	wild    *regexp.Regexp
}

var hostScopeMatcherCache sync.Map // key(string) -> compiledScopeMatcher

func newExcludeStore(path string) *excludeStore {
	s := &excludeStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]excludeEntry),
	}
	s.load()
	return s
}

func (s *excludeStore) normalize(t, v string) (string, string, bool) {
	t = strings.ToLower(strings.TrimSpace(t))
	v = strings.ToLower(strings.TrimSpace(v))
	if t != "host" && t != "path" {
		return "", "", false
	}
	if v == "" {
		return "", "", false
	}
	if t == "path" && !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return t, v, true
}

func (s *excludeStore) key(t, v string, scopeHosts []string, ruleIDs []int) string {
	scope := strings.Join(scopeHosts, ",")
	return t + ":" + v + "|" + scope + "|" + ruleIDsKey(ruleIDs)
}

func normalizeScopeHosts(scopeHosts []string) []string {
	if len(scopeHosts) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(scopeHosts))
	out := make([]string, 0, len(scopeHosts))
	for _, h := range scopeHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, exists := set[h]; exists {
			continue
		}
		set[h] = struct{}{}
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func scopeMapToHosts(scope map[string]struct{}) []string {
	if len(scope) == 0 {
		return nil
	}
	out := make([]string, 0, len(scope))
	for h := range scope {
		out = append(out, h)
	}
	return normalizeScopeHosts(out)
}

func (s *excludeStore) Add(t, v string, scope map[string]struct{}) bool {
	return s.AddWithRuleIDs(t, v, scope, nil)
}

// AddWithRuleIDs is the rule-scoped variant of Add. ruleIDs is normalized
// (sorted, deduplicated, clipped to 100..999); empty/nil means whole-WAF
// skip (legacy semantics, identical to Add). Two entries on the same
// (type, value, scope) tuple but with different RuleIDs are independent.
func (s *excludeStore) AddWithRuleIDs(t, v string, scope map[string]struct{}, ruleIDs []int) bool {
	t, v, ok := s.normalize(t, v)
	if !ok {
		return false
	}
	scopeHosts := scopeMapToHosts(scope)
	ruleIDs = normalizeRuleIDs(ruleIDs)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(t, v, scopeHosts, ruleIDs)
	if _, exists := s.entries[k]; exists {
		return false
	}
	s.entries[k] = excludeEntry{
		Type: t, Value: v, ScopeHosts: scopeHosts, RuleIDs: ruleIDs,
		CreatedAt: time.Now(),
	}
	s.rebuildCompiledLocked()
	_ = s.saveLocked()
	return true
}

func (s *excludeStore) Remove(t, v string, scope map[string]struct{}) bool {
	return s.RemoveWithRuleIDs(t, v, scope, nil)
}

// RemoveWithRuleIDs targets the entry with the matching (type, value, scope,
// rule-id-set) tuple. nil/empty ruleIDs targets the legacy whole-WAF entry.
func (s *excludeStore) RemoveWithRuleIDs(t, v string, scope map[string]struct{}, ruleIDs []int) bool {
	t, v, ok := s.normalize(t, v)
	if !ok {
		return false
	}
	scopeHosts := scopeMapToHosts(scope)
	ruleIDs = normalizeRuleIDs(ruleIDs)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(t, v, scopeHosts, ruleIDs)
	if _, exists := s.entries[k]; exists {
		delete(s.entries, k)
	} else if !s.removeHostAnyScopeLocked(t, v, scope, ruleIDs) {
		return false
	}
	s.rebuildCompiledLocked()
	_ = s.saveLocked()
	return true
}

// removeHostAnyScopeLocked removes every TENANT-written host exclude on
// (value, ruleIDs), whatever scope_hosts it was written with. An entry the
// operator wrote (no scope_hosts) is never removed this way: on the ClamAV
// stores a host entry turns scanning on for that host, which its owner must
// not be able to undo. A host exclude acts on its own
// host only, and its scope_hosts is the writer's vhost set at the time, so an
// exact-scope match fails once that set changes (a domain moved to another
// account, or the writer's account gained one): the entry kept applying and
// nobody could remove it. The caller has already checked that it may manage
// this host (validateScopedExcludeWrite). A scoped caller (non-nil scope)
// must also hold the host itself, not only a wildcard alias that matches it:
// another account may own that name. Path excludes keep the exact match:
// their scope_hosts is the set of sites the exclude applies to.
func (s *excludeStore) removeHostAnyScopeLocked(t, v string, scope map[string]struct{}, ruleIDs []int) bool {
	if t != "host" {
		return false
	}
	if scope != nil {
		if _, own := scope[v]; !own {
			return false
		}
	}
	want := ruleIDsKey(ruleIDs)
	removed := false
	for k, e := range s.entries {
		if e.Type == "host" && e.Value == v && len(e.ScopeHosts) > 0 && ruleIDsKey(e.RuleIDs) == want {
			delete(s.entries, k)
			removed = true
		}
	}
	return removed
}

// RemovePathHosts takes the hosts in strip out of every path entry on value
// that names at least one of them: an entry left with no host is deleted, the
// others keep applying to their remaining hosts. A scoped caller's remove: it
// acts on its own hosts only, so an entry shared with another tenant (or one a
// domain move left behind) stops applying to the caller's sites without
// touching anyone else's. An unscoped entry is never changed this way.
// Returns whether anything changed.
func (s *excludeStore) RemovePathHosts(v string, strip map[string]struct{}) bool {
	t, v, ok := s.normalize("path", v)
	if !ok || len(strip) == 0 {
		return false
	}
	drop := make(map[string]struct{}, len(strip))
	for h := range strip {
		drop[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for k, e := range s.entries {
		if e.Type != t || e.Value != v || len(e.ScopeHosts) == 0 {
			continue
		}
		keep := make([]string, 0, len(e.ScopeHosts))
		for _, h := range e.ScopeHosts {
			if _, gone := drop[h]; !gone {
				keep = append(keep, h)
			}
		}
		if len(keep) == len(e.ScopeHosts) {
			continue
		}
		delete(s.entries, k)
		changed = true
		if len(keep) == 0 {
			continue
		}
		e.ScopeHosts = keep
		nk := s.key(e.Type, e.Value, e.ScopeHosts, e.RuleIDs)
		if _, dup := s.entries[nk]; !dup {
			s.entries[nk] = e
		}
	}
	if changed {
		s.rebuildCompiledLocked()
		_ = s.saveLocked()
	}
	return changed
}

func (s *excludeStore) List() []excludeEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]excludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sortExcludeEntries(out)
	return out
}

// sortExcludeEntries is List's order: type, scope, value, rule ids.
func sortExcludeEntries(out []excludeEntry) {
	sort.Slice(out, func(i, j int) bool { return excludeEntryLess(out[i], out[j]) })
}

func excludeEntryLess(a, b excludeEntry) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if sa, sb := strings.Join(a.ScopeHosts, ","), strings.Join(b.ScopeHosts, ","); sa != sb {
		return sa < sb
	}
	if a.Value != b.Value {
		return a.Value < b.Value
	}
	return ruleIDsKey(a.RuleIDs) < ruleIDsKey(b.RuleIDs)
}

func hostInScope(host string, scopeHosts []string) bool {
	start, profEnabled := globalExcludeProfiler.start()
	defer globalExcludeProfiler.end("host_in_scope", start, profEnabled)
	if len(scopeHosts) == 0 {
		return true
	}
	key := strings.Join(scopeHosts, "\x00")
	if cached, ok := hostScopeMatcherCache.Load(key); ok {
		return cached.(compiledScopeMatcher).Match(host)
	}
	compiled := compileScopeMatcher(scopeHosts)
	hostScopeMatcherCache.Store(key, compiled)
	return compiled.Match(host)
}

func compileScopeMatcher(scopeHosts []string) compiledScopeMatcher {
	if len(scopeHosts) == 0 {
		return compiledScopeMatcher{}
	}
	m := compiledScopeMatcher{
		scoped: true,
		exact:  make(map[string]struct{}),
		wild:   make([]*regexp.Regexp, 0),
	}
	for _, scopeHost := range scopeHosts {
		if strings.ContainsAny(scopeHost, "*?[]") {
			if re := compileGlob(scopeHost); re != nil {
				m.wild = append(m.wild, re)
			}
			continue
		}
		m.exact[scopeHost] = struct{}{}
	}
	return m
}

// Match reports whether an entry with this scope applies on host (lowercased
// by the caller). The in-path WAF runs the same semantics
// (cfm_waf_excl.lua scope_takes); both run
// scripts/tests/fixtures/waf_exclude_scope.txt.
func (m compiledScopeMatcher) Match(host string) bool {
	if !m.scoped {
		return true
	}
	if _, ok := m.exact[host]; ok {
		return true
	}
	for _, re := range m.wild {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// compileValueMatcher builds a matcher for one exclude value. kind is the
// entry Type ("host"/"path") and selects the boundary semantics for a non-glob
// (literal) value:
//
//   - host: exact host, or a dot-boundary subdomain suffix — `shop.gr` matches
//     `shop.gr` and `www.shop.gr`, NOT `myshop.gr` / `shop.gr.evil.com`. (The
//     vhost controls' old reporting-side matcher used these semantics while
//     the old enforcement matcher silently disagreed; both now use this one.)
//   - path: exact path, or a path-segment prefix — `/admin` matches `/admin`
//     and `/admin/x`, NOT `/administrator`. Path values carry a leading `/`
//     (added at store time by normalize).
//
// A glob value (`* ? [ ]`) keeps anchored wildcard matching for both kinds.
// Previously a non-glob value was matched with strings.Contains — a plain
// SUBSTRING — so a `shop.gr` host exclude also disabled the WAF (or challenge)
// on `myshop.gr` / `shop.gr.evil.com`, and a `/api` path exclude on `/therapy`:
// an unbounded, silent widening of an exclude across unintended vhosts/paths.
func compileValueMatcher(kind, rule string) compiledValueMatcher {
	if strings.ContainsAny(rule, "*?[]") {
		return compiledValueMatcher{kind: kind, wild: compileGlob(rule)}
	}
	return compiledValueMatcher{kind: kind, literal: rule}
}

func (m compiledValueMatcher) Match(value string) bool {
	if m.wild != nil && m.wild.MatchString(value) {
		return true
	}
	if m.literal == "" {
		return false
	}
	if value == m.literal {
		return true
	}
	switch m.kind {
	case "host":
		// exact (above) or dot-boundary subdomain suffix.
		return strings.HasSuffix(value, "."+m.literal)
	case "path":
		// exact (above) or path-segment prefix. A literal ending in `/` is a
		// pure prefix; otherwise require the next byte to be a `/` boundary.
		if strings.HasSuffix(m.literal, "/") {
			return strings.HasPrefix(value, m.literal)
		}
		return strings.HasPrefix(value, m.literal+"/")
	default:
		// Unknown kind: exact-only (already handled above).
		return false
	}
}

func (s *excludeStore) MatchChallenge(host string) bool {
	// Fast path: no challenge excludes configured (the common case) — skip the
	// profiler, host normalisation, and RLock entirely.
	if s.challengeCount.Load() == 0 {
		return false
	}
	start, profEnabled := globalExcludeProfiler.start()
	defer globalExcludeProfiler.end("match_challenge", start, profEnabled)
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.challengeEntries {
		if e.challengeHostCovers(host) {
			return true
		}
	}
	return false
}

// challengeHostCovers is MatchChallenge's per-entry test.
func (e compiledExcludeEntry) challengeHostCovers(host string) bool {
	return e.Scope.Match(host) && e.Value.Match(host)
}

// MatchWAF reports whether the (host, path) request should skip the WAF
// entirely. Only whole-WAF entries (RuleIDs empty) count — rule-scoped
// entries don't trigger this, since their semantics is "skip these rules"
// rather than "skip the WAF". Callers that need the full picture should use
// MatchWAFRules.
func (s *excludeStore) MatchWAF(host, path string) bool {
	skipAll, _ := s.MatchWAFRules(host, path)
	return skipAll
}

// MatchWAFRules returns the WAF-skip decision for (host, path):
//
//   - skipAll=true  the whole WAF is excluded (legacy semantics; one or more
//     matching entries had RuleIDs empty)
//   - skipIDs       set of waf_rule_id values to suppress when WAF runs
//     (union of RuleIDs from matching rule-scoped entries)
//
// When skipAll is true skipIDs is irrelevant. host and path are lower-cased
// before matching. A nil/empty skipIDs and skipAll=false means "no exclude
// applies".
func (s *excludeStore) MatchWAFRules(host, path string) (skipAll bool, skipIDs map[int]struct{}) {
	start, profEnabled := globalExcludeProfiler.start()
	defer globalExcludeProfiler.end("match_waf", start, profEnabled)
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(strings.TrimSpace(path))
	if host == "" || path == "" {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.wafEntries {
		if !e.wafCovers(host, path) {
			continue
		}
		if len(e.RuleIDs) == 0 {
			// Whole-WAF skip: short-circuit. A rule-scoped exclude can never
			// "un-skip" what a whole-WAF exclude already covers.
			return true, nil
		}
		if skipIDs == nil {
			skipIDs = make(map[int]struct{}, len(e.RuleIDs))
		}
		for _, id := range e.RuleIDs {
			skipIDs[id] = struct{}{}
		}
	}
	return false, skipIDs
}

// MatchChallengePath reports whether a request on host under path is carved
// out of the log-driven malpath checks (CHALLENGE_PATHS and the MALPATH flood
// counter) by a path entry of this store, and returns the entry's value for
// the log line. Only SCOPED path entries count: a path entry without
// scope_hosts would exempt that path on every site, which is the same as
// deleting the malpath list entry silently, so the API refuses to write one
// and an unscoped entry left in an older store stays inert here (the WAF
// store's own path entries are a different store and keep their meaning).
// path is the ingest-normalised path (query cut); both sides are lower-cased.
func (s *excludeStore) MatchChallengePath(host, path string) (string, bool) {
	if s == nil || s.pathCount.Load() == 0 {
		return "", false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(strings.TrimSpace(path))
	if host == "" || path == "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.pathEntries {
		if !e.challengePathScopeCovers(host) {
			continue
		}
		if e.Value.Match(path) {
			return e.Raw, true
		}
	}
	return "", false
}

// wafCovers is MatchWAFRules' per-entry test: the entry's scope takes host,
// and its value matches host (a host entry) or path (a path entry).
func (e compiledExcludeEntry) wafCovers(host, path string) bool {
	if !e.Scope.Match(host) {
		return false
	}
	switch e.Type {
	case "host":
		return e.Value.Match(host)
	case "path":
		return e.Value.Match(path)
	}
	return false
}

// challengePathScopeCovers is MatchChallengePath's scope test: only a SCOPED
// path entry counts, and a literal scope host also covers its www. alias
// (cPanel lists a domain without it, a tenant's token cannot name it, and
// nginx serves both).
func (e compiledExcludeEntry) challengePathScopeCovers(host string) bool {
	if !e.Scoped {
		return false
	}
	if e.Scope.Match(host) {
		return true
	}
	apex, ok := strings.CutPrefix(host, "www.")
	return ok && apex != "" && e.Scope.matchExact(apex)
}

// WAFEntriesForHost lists the WAF excludes the in-path WAF applies to a
// request on host: every entry whose scope_hosts take host (empty = every
// vhost) and whose value covers it (a host entry) or that can cover one of its
// paths (a path entry). The scope test is MatchWAFRules' and the edge's
// (cfm_waf_excl.lua skip_for), so the profile lists what both apply.
// Read-only, for the vhost profile.
func (s *excludeStore) WAFEntriesForHost(host string) []excludeEntry {
	host = strings.ToLower(strings.TrimSpace(host))
	if s == nil || host == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []excludeEntry
	for _, e := range s.wafEntries {
		if !e.Scope.Match(host) {
			continue
		}
		if e.Type == "path" || (e.Type == "host" && e.Value.Match(host)) {
			out = append(out, e.Entry)
		}
	}
	sortExcludeEntries(out)
	return out
}

// ChallengeEntriesForHost lists the challenge excludes that can apply on
// host: the host entries MatchChallenge would match, and the scoped path
// entries MatchChallengePath would consider for it.
func (s *excludeStore) ChallengeEntriesForHost(host string) []excludeEntry {
	host = strings.ToLower(strings.TrimSpace(host))
	if s == nil || host == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []excludeEntry
	for _, e := range s.challengeEntries {
		if e.challengeHostCovers(host) {
			out = append(out, e.Entry)
		}
	}
	for _, e := range s.pathEntries {
		if e.challengePathScopeCovers(host) {
			out = append(out, e.Entry)
		}
	}
	sortExcludeEntries(out)
	return out
}

// FirstChallengeHostMatch is the host entry MatchChallenge excludes host by
// (the first in List order when several do); ok=false when none does.
func (s *excludeStore) FirstChallengeHostMatch(host string) (excludeEntry, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if s == nil || host == "" {
		return excludeEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best excludeEntry
	found := false
	for _, e := range s.challengeEntries {
		if e.challengeHostCovers(host) && (!found || excludeEntryLess(e.Entry, best)) {
			best, found = e.Entry, true
		}
	}
	return best, found
}

// FirstWAFHostMatch is the vhost controls' WAF column test: the first
// (List order) WHOLE-WAF host entry that MatchWAFRules would apply on host,
// scope_hosts included. Rule-scoped entries leave the WAF on, so they do not
// count.
func (s *excludeStore) FirstWAFHostMatch(host string) (excludeEntry, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if s == nil || host == "" {
		return excludeEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best excludeEntry
	found := false
	for _, e := range s.wafEntries {
		if e.Type != "host" || len(e.RuleIDs) > 0 || !e.Scope.Match(host) || !e.Value.Match(host) {
			continue
		}
		if !found || excludeEntryLess(e.Entry, best) {
			best, found = e.Entry, true
		}
	}
	return best, found
}

// matchExact reports host among the literal (non-glob) scope hosts.
func (m compiledScopeMatcher) matchExact(host string) bool {
	_, ok := m.exact[host]
	return ok
}

func (s *excludeStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []excludeEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range arr {
		t, v, ok := s.normalize(e.Type, e.Value)
		if !ok {
			continue
		}
		if e.CreatedAt.IsZero() {
			e.CreatedAt = time.Now()
		}
		e.Type, e.Value = t, v
		e.ScopeHosts = normalizeScopeHosts(e.ScopeHosts)
		e.RuleIDs = normalizeRuleIDs(e.RuleIDs)
		s.entries[s.key(t, v, e.ScopeHosts, e.RuleIDs)] = e
	}
	s.rebuildCompiledLocked()
}

func (s *excludeStore) rebuildCompiledLocked() {
	challenge := make([]compiledExcludeEntry, 0, len(s.entries))
	waf := make([]compiledExcludeEntry, 0, len(s.entries))
	pathEntries := make([]compiledExcludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		compiled := compiledExcludeEntry{
			Type:    e.Type,
			Scope:   compileScopeMatcher(e.ScopeHosts),
			Value:   compileValueMatcher(e.Type, e.Value),
			RuleIDs: append([]int(nil), e.RuleIDs...),
			Raw:     e.Value,
			Scoped:  len(e.ScopeHosts) > 0,
			Entry:   e,
		}
		switch e.Type {
		case "host":
			challenge = append(challenge, compiled)
			waf = append(waf, compiled)
		case "path":
			pathEntries = append(pathEntries, compiled)
			waf = append(waf, compiled)
		}
	}
	s.challengeEntries = challenge
	s.wafEntries = waf
	s.pathEntries = pathEntries
	s.challengeCount.Store(int64(len(challenge)))
	scoped := int64(0)
	for _, e := range pathEntries {
		if e.Scoped {
			scoped++
		}
	}
	s.pathCount.Store(scoped)
}

func compileGlob(pattern string) *regexp.Regexp {
	reStr, ok := globToRegex(pattern)
	if !ok {
		return nil
	}
	re, err := regexp.Compile(reStr)
	if err != nil {
		return nil
	}
	return re
}

func globToRegex(pattern string) (string, bool) {
	var b strings.Builder
	b.WriteString("^")
	inClass := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if inClass {
			switch c {
			case ']':
				inClass = false
				b.WriteByte(']')
			case '\\':
				if i+1 >= len(pattern) {
					return "", false
				}
				i++
				b.WriteString(regexp.QuoteMeta(string(pattern[i])))
			default:
				if c == '^' {
					b.WriteString(`\\^`)
				} else {
					b.WriteByte(c)
				}
			}
			continue
		}
		switch c {
		case '*':
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		case '[':
			inClass = true
			b.WriteByte('[')
			if i+1 < len(pattern) && (pattern[i+1] == '!' || pattern[i+1] == '^') {
				i++
				b.WriteByte('^')
			}
			if i+1 < len(pattern) && pattern[i+1] == ']' {
				i++
				b.WriteString(`\\]`)
			}
		case '\\':
			if i+1 >= len(pattern) {
				return "", false
			}
			i++
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if inClass {
		return "", false
	}
	b.WriteString("$")
	return b.String(), true
}

func (s *excludeStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	arr := make([]excludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Type != arr[j].Type {
			return arr[i].Type < arr[j].Type
		}
		if arr[i].Value != arr[j].Value {
			return arr[i].Value < arr[j].Value
		}
		return ruleIDsKey(arr[i].RuleIDs) < ruleIDsKey(arr[j].RuleIDs)
	})
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}
