package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type excludeEntry struct {
	Type       string    `json:"type"` // host | path
	Value      string    `json:"value"`
	ScopeHosts []string  `json:"scope_hosts,omitempty"` // nil/empty => admin-global
	CreatedAt  time.Time `json:"created_at"`
}

type excludeStore struct {
	mu               sync.RWMutex
	path             string
	entries          map[string]excludeEntry // key = type:value
	challengeEntries []compiledExcludeEntry
	wafEntries       []compiledExcludeEntry
	pathEntries      []compiledExcludeEntry
}

type compiledExcludeEntry struct {
	Type  string
	Scope compiledScopeMatcher
	Value compiledValueMatcher
}

type compiledScopeMatcher struct {
	exact map[string]struct{}
	wild  []*regexp.Regexp
}

type compiledValueMatcher struct {
	exactContains string
	wild          *regexp.Regexp
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

func (s *excludeStore) key(t, v string, scopeHosts []string) string {
	scope := strings.Join(scopeHosts, ",")
	return t + ":" + v + "|" + scope
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
	t, v, ok := s.normalize(t, v)
	if !ok {
		return false
	}
	scopeHosts := scopeMapToHosts(scope)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(t, v, scopeHosts)
	if _, exists := s.entries[k]; exists {
		return false
	}
	s.entries[k] = excludeEntry{Type: t, Value: v, ScopeHosts: scopeHosts, CreatedAt: time.Now()}
	s.rebuildCompiledLocked()
	_ = s.saveLocked()
	return true
}

func (s *excludeStore) Remove(t, v string, scope map[string]struct{}) bool {
	t, v, ok := s.normalize(t, v)
	if !ok {
		return false
	}
	scopeHosts := scopeMapToHosts(scope)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(t, v, scopeHosts)
	if _, exists := s.entries[k]; !exists {
		return false
	}
	delete(s.entries, k)
	s.rebuildCompiledLocked()
	_ = s.saveLocked()
	return true
}

func (s *excludeStore) List() []excludeEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]excludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
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
		exact: make(map[string]struct{}),
		wild:  make([]*regexp.Regexp, 0),
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

func (m compiledScopeMatcher) Match(host string) bool {
	if len(m.exact) == 0 && len(m.wild) == 0 {
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

func matchExcludeValue(value, rule string) bool {
	return compileValueMatcher(rule).Match(value)
}

func compileValueMatcher(rule string) compiledValueMatcher {
	if strings.ContainsAny(rule, "*?[]") {
		return compiledValueMatcher{wild: compileGlob(rule)}
	}
	return compiledValueMatcher{exactContains: rule}
}

func (m compiledValueMatcher) Match(value string) bool {
	if m.wild != nil && m.wild.MatchString(value) {
		return true
	}
	if m.exactContains != "" && strings.Contains(value, m.exactContains) {
		return true
	}
	return false
}

func (s *excludeStore) MatchChallenge(host string) bool {
	start, profEnabled := globalExcludeProfiler.start()
	defer globalExcludeProfiler.end("match_challenge", start, profEnabled)
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.challengeEntries {
		if !e.Scope.Match(host) {
			continue
		}
		if e.Value.Match(host) {
			return true
		}
	}
	return false
}

func (s *excludeStore) MatchWAF(host, path string) bool {
	start, profEnabled := globalExcludeProfiler.start()
	defer globalExcludeProfiler.end("match_waf", start, profEnabled)
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(strings.TrimSpace(path))
	if host == "" || path == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.wafEntries {
		if !e.Scope.Match(host) {
			continue
		}
		switch e.Type {
		case "host":
			if e.Value.Match(host) {
				return true
			}
		case "path":
			if e.Value.Match(path) {
				return true
			}
		}
	}
	return false
}

// MatchHost is retained for backwards compatibility with existing call-sites.
func (s *excludeStore) MatchHost(host string) bool {
	return s.MatchChallenge(host)
}

// MatchPath is retained for backwards compatibility with existing call-sites.
func (s *excludeStore) MatchPath(host, path string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(strings.TrimSpace(path))
	if host == "" || path == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.pathEntries {
		if !e.Scope.Match(host) {
			continue
		}
		if e.Value.Match(path) {
			return true
		}
	}
	return false
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
		s.entries[s.key(t, v, e.ScopeHosts)] = e
	}
	s.rebuildCompiledLocked()
}

func (s *excludeStore) rebuildCompiledLocked() {
	challenge := make([]compiledExcludeEntry, 0, len(s.entries))
	waf := make([]compiledExcludeEntry, 0, len(s.entries))
	pathEntries := make([]compiledExcludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		compiled := compiledExcludeEntry{
			Type:  e.Type,
			Scope: compileScopeMatcher(e.ScopeHosts),
			Value: compileValueMatcher(e.Value),
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
		return arr[i].Value < arr[j].Value
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
