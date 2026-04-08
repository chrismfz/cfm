package webdetector

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	TrafficActionAllow     = "allow"
	TrafficActionBlock     = "block"
	TrafficActionChallenge = "challenge"
	TrafficActionThrottle  = "throttle"
)

const (
	maxRulesGlobal      = 500
	maxVhostsPerRule    = 32
	maxCountriesPerRule = 20
	maxPatternsPerField = 20
	maxRuleNoteLen      = 256
	defaultRulePriority = 1000
)

type TrafficRuleScope struct {
	Vhosts []string `json:"vhosts"`
}

type TrafficRuleMatch struct {
	CountryIn []string `json:"country_in,omitempty"`
	UAAny     []string `json:"ua_any,omitempty"`
	PathAny   []string `json:"path_any,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	// Query-string guards (both optional, evaluated only when set)
	HasQS    bool   `json:"has_qs,omitempty"`    // true → rule only fires when QS is present
	QSNotRx  string `json:"qs_not_rx,omitempty"` // if set, pass-through when QS matches this pattern
}

type TrafficRuleAction struct {
	Type    string `json:"type"`
	Profile string `json:"profile,omitempty"` // required when type=throttle
}

type TrafficRule struct {
	ID        string            `json:"id"`
	Enabled   bool              `json:"enabled"`
	Priority  int               `json:"priority"`
	Scope     TrafficRuleScope  `json:"scope"`
	Match     TrafficRuleMatch  `json:"match"`
	Action    TrafficRuleAction `json:"action"`
	Note      string            `json:"note,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type TrafficRuleEvalInput struct {
	Host    string `json:"host"`
	IP      string `json:"ip,omitempty"`
	UA      string `json:"ua,omitempty"`
	Path    string `json:"path,omitempty"`
	Method  string `json:"method,omitempty"`
	Country string `json:"country,omitempty"`
	QueryString string `json:"qs,omitempty"` // raw query string, no leading '?'
}

type TrafficRuleEvalResult struct {
	Matched bool        `json:"matched"`
	Rule    TrafficRule `json:"rule,omitempty"`
	Action  string      `json:"action,omitempty"`
	Profile string      `json:"profile,omitempty"`
}

type trafficRuleStore struct {
	mu    sync.RWMutex
	path  string
	rules map[string]TrafficRule // key=id
}

func newTrafficRuleStore(path string) *trafficRuleStore {
	s := &trafficRuleStore{
		path:  strings.TrimSpace(path),
		rules: make(map[string]TrafficRule),
	}
	s.load()
	return s
}

func (s *trafficRuleStore) Add(in TrafficRule) (TrafficRule, error) {
	norm, err := normalizeTrafficRule(in, true)
	if err != nil {
		return TrafficRule{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rules) >= maxRulesGlobal {
		return TrafficRule{}, fmt.Errorf("too many rules (max %d)", maxRulesGlobal)
	}
	if _, exists := s.rules[norm.ID]; exists {
		return TrafficRule{}, errors.New("rule id already exists")
	}
	s.rules[norm.ID] = norm
	if err := s.saveLocked(); err != nil {
		return TrafficRule{}, err
	}
	return norm, nil
}

func (s *trafficRuleStore) Update(id string, in TrafficRule) (TrafficRule, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return TrafficRule{}, errors.New("id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.rules[id]
	if !ok {
		return TrafficRule{}, errors.New("rule not found")
	}

	in.ID = id
	if in.CreatedAt.IsZero() {
		in.CreatedAt = cur.CreatedAt
	}
	norm, err := normalizeTrafficRule(in, false)
	if err != nil {
		return TrafficRule{}, err
	}
	s.rules[id] = norm
	if err := s.saveLocked(); err != nil {
		return TrafficRule{}, err
	}
	return norm, nil
}

func (s *trafficRuleStore) Remove(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return false
	}
	delete(s.rules, id)
	_ = s.saveLocked()
	return true
}

func (s *trafficRuleStore) Get(id string) (TrafficRule, bool) {
	id = strings.TrimSpace(id)
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return r, ok
}

func (s *trafficRuleStore) List() []TrafficRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TrafficRule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *trafficRuleStore) Simulate(in TrafficRuleEvalInput) TrafficRuleEvalResult {
	host := normalizeControlHost(in.Host)
	path := strings.TrimSpace(in.Path)
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	ua := strings.ToLower(strings.TrimSpace(in.UA))
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	country := strings.ToUpper(strings.TrimSpace(in.Country))

	s.mu.RLock()
	defer s.mu.RUnlock()

	rows := make([]TrafficRule, 0, len(s.rules))
	for _, r := range s.rules {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority < rows[j].Priority
		}
		return rows[i].ID < rows[j].ID
	})

	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		if !ruleHostMatch(r.Scope.Vhosts, host) {
			continue
		}
		if !ruleMatchFilters(r.Match, country, ua, path, method, in.QueryString) {
			continue
		}
		return TrafficRuleEvalResult{
			Matched: true,
			Rule:    r,
			Action:  r.Action.Type,
			Profile: r.Action.Profile,
		}
	}
	return TrafficRuleEvalResult{Matched: false}
}

func normalizeTrafficRule(in TrafficRule, generateID bool) (TrafficRule, error) {
	now := time.Now().UTC()
	r := in

	if generateID && strings.TrimSpace(r.ID) == "" {
		r.ID = newRuleID()
	}
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		return TrafficRule{}, errors.New("id is required")
	}

	if r.Priority <= 0 {
		r.Priority = defaultRulePriority
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	if strings.TrimSpace(r.Note) != "" {
		r.Note = strings.TrimSpace(r.Note)
		if len(r.Note) > maxRuleNoteLen {
			return TrafficRule{}, fmt.Errorf("note too long (max %d)", maxRuleNoteLen)
		}
	}

	if len(r.Scope.Vhosts) == 0 {
		return TrafficRule{}, errors.New("scope.vhosts is required")
	}
	if len(r.Scope.Vhosts) > maxVhostsPerRule {
		return TrafficRule{}, fmt.Errorf("too many vhosts in rule (max %d)", maxVhostsPerRule)
	}
	vhosts := make([]string, 0, len(r.Scope.Vhosts))
	seenVhosts := map[string]struct{}{}
	for _, h := range r.Scope.Vhosts {
		h = normalizeControlHost(h)
		if h == "" {
			continue
		}
		if _, ok := seenVhosts[h]; ok {
			continue
		}
		seenVhosts[h] = struct{}{}
		vhosts = append(vhosts, h)
	}
	if len(vhosts) == 0 {
		return TrafficRule{}, errors.New("scope.vhosts is required")
	}
	r.Scope.Vhosts = vhosts

	countries, err := normalizeCodeList(r.Match.CountryIn, maxCountriesPerRule, true)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("country_in: %w", err)
	}
	r.Match.CountryIn = countries

	uas, err := normalizePatternList(r.Match.UAAny, maxPatternsPerField, false)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("ua_any: %w", err)
	}
	r.Match.UAAny = uas

	paths, err := normalizePatternList(r.Match.PathAny, maxPatternsPerField, true)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("path_any: %w", err)
	}
	r.Match.PathAny = paths

	methods, err := normalizeMethods(r.Match.Methods, maxPatternsPerField)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("methods: %w", err)
	}
	r.Match.Methods = methods

if rx := strings.TrimSpace(r.Match.QSNotRx); rx != "" {
    if _, err := regexp.Compile("(?i)" + rx); err != nil {
        return TrafficRule{}, fmt.Errorf("qs_not_rx: invalid regexp: %w", err)
    }
    r.Match.QSNotRx = rx
}

	r.Action.Type = strings.ToLower(strings.TrimSpace(r.Action.Type))
	r.Action.Profile = strings.TrimSpace(r.Action.Profile)
	switch r.Action.Type {
	case TrafficActionAllow, TrafficActionBlock, TrafficActionChallenge:
		r.Action.Profile = ""
	case TrafficActionThrottle:
		if r.Action.Profile == "" {
			return TrafficRule{}, errors.New("action.profile is required for throttle")
		}
	default:
		return TrafficRule{}, fmt.Errorf("unsupported action type %q", r.Action.Type)
	}

	return r, nil
}

func normalizeCodeList(in []string, max int, forceUpper bool) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > max {
		return nil, fmt.Errorf("too many values (max %d)", max)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if forceUpper {
			v = strings.ToUpper(v)
		}
		if len(v) != 2 {
			return nil, fmt.Errorf("invalid country code %q", raw)
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

func normalizePatternList(in []string, max int, ensurePath bool) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > max {
		return nil, fmt.Errorf("too many values (max %d)", max)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if ensurePath && !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

func normalizeMethods(in []string, max int) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > max {
		return nil, fmt.Errorf("too many values (max %d)", max)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.ToUpper(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

func ruleHostMatch(vhosts []string, host string) bool {
	if host == "" {
		return false
	}
	for _, pat := range vhosts {
		pat = normalizeControlHost(pat)
		if pat == "" {
			continue
		}
		if ok, err := filepath.Match(pat, host); err == nil && ok {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			suf := strings.TrimPrefix(pat, "*")
			if strings.HasSuffix(host, suf) && len(host) > len(suf) {
				return true
			}
		}
		if !strings.ContainsAny(pat, "*?") && host == pat {
			return true
		}
	}
	return false
}




func ruleMatchFilters(m TrafficRuleMatch, country, ua, path, method, qs string) bool {
	if len(m.CountryIn) > 0 {
		ok := false
		for _, cc := range m.CountryIn {
			if country == cc {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.Methods) > 0 {
		ok := false
		for _, meth := range m.Methods {
			if method == meth {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.UAAny) > 0 {
		ok := false
		for _, pat := range m.UAAny {
			p := strings.ToLower(strings.TrimSpace(pat))
			if p == "" {
				continue
			}
			if wildcardMatch(p, ua) {
				ok = true
				break
			}
			if !strings.ContainsAny(p, "*?") && strings.Contains(ua, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(m.PathAny) > 0 {
		ok := false
		for _, pat := range m.PathAny {
			p := strings.TrimSpace(pat)
			if p == "" {
				continue
			}
			if wildcardMatch(p, path) {
				ok = true
				break
			}
			if !strings.ContainsAny(p, "*?") && strings.HasPrefix(path, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	// QS guards — evaluated last, after UA/path have already narrowed the candidate set
	if m.HasQS && qs == "" {
		return false
	}
	if m.QSNotRx != "" && qs != "" {
		if ok, _ := regexp.MatchString("(?i)"+m.QSNotRx, qs); ok {
			return false
		}
	}
	return true
}







// wildcardMatch matches pattern with '*' and '?' against s.
// Unlike filepath.Match, '*' can match '/' too (needed for UA/path matching).
func wildcardMatch(pattern, s string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}

	pi, si := 0, 0
	starIdx, match := -1, 0
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			pi++
			si++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			match = si
			pi++
			continue
		}
		if starIdx != -1 {
			pi = starIdx + 1
			match++
			si = match
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func (s *trafficRuleStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []TrafficRule
	if err := json.Unmarshal(b, &arr); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range arr {
		norm, err := normalizeTrafficRule(e, false)
		if err != nil {
			continue
		}
		if norm.CreatedAt.IsZero() {
			norm.CreatedAt = time.Now().UTC()
		}
		s.rules[norm.ID] = norm
	}
}

func (s *trafficRuleStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	arr := make([]TrafficRule, 0, len(s.rules))
	for _, e := range s.rules {
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Priority != arr[j].Priority {
			return arr[i].Priority < arr[j].Priority
		}
		return arr[i].ID < arr[j].ID
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

func newRuleID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("r_%d", time.Now().UnixNano())
	}
	return "r_" + hex.EncodeToString(b[:])
}
