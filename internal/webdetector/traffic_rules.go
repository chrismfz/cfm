package webdetector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
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
	// CountryNotIn matches when the request's country is known AND not one
	// of these. An empty country ("") is the edge's fail-open sentinel — geo
	// module down, DB mid-reload, enrich-cache miss, or cfm_panel.lua which
	// always sends "" — so it deliberately does NOT match (same fail-open
	// contract as CountryIn): a geo hiccup must never turn a not_in fence into
	// a block of every visitor. Mutually exclusive with CountryIn.
	CountryNotIn []string `json:"country_not_in,omitempty"`
	// IPAny matches when the client IP is inside any of these prefixes
	// (IPv4/IPv6 CIDR; a bare address is a /32 or /128). Stored canonical
	// (netip.Prefix.Masked().String()). An unparsable request IP never matches.
	IPAny []string `json:"ip_any,omitempty"`
	// VerifiedBot restricts the rule to requests from an FCrDNS-verified
	// CRAWLER (the goodBotPTRSuffixes registry — Googlebot, Bing, Yahoo,
	// Applebot, Yandex, Meta — minus the generic "google" verdict that also
	// covers Translate/AMP proxies; see verifiedBotForRules). "Verified" means the PTR forward-confirmed to the
	// requesting IP — a User-Agent string earns nothing. On the decision hot
	// path the verdict is CACHE-ONLY (a first-seen crawler IP kicks a bounded
	// async forward-confirm and matches on a later request), so a
	// verified_bot allow is eventual, never a DNS wait per request.
	VerifiedBot bool     `json:"verified_bot,omitempty"`
	UAAny       []string `json:"ua_any,omitempty"`
	PathAny     []string `json:"path_any,omitempty"`
	Methods     []string `json:"methods,omitempty"`
	// Query-string guards (both optional, evaluated only when set)
	HasQS   bool   `json:"has_qs,omitempty"`    // true → rule only fires when QS is present
	QSNotRx string `json:"qs_not_rx,omitempty"` // if set, pass-through when QS matches this pattern

	qsNotRxCompiled *regexp.Regexp // pre-compiled from QSNotRx; set by normalizeTrafficRule
	ipAnyCompiled   []netip.Prefix // parsed from IPAny; set by normalizeTrafficRule
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
	// Unsupported is set in memory only: the stored rule carries match/scope
	// keys this build does not understand (written by a newer cfm). Such a
	// rule is never evaluated, cannot be edited or enabled here, and is
	// written back to disk verbatim so nothing is lost for the upgrade.
	Unsupported bool `json:"unsupported,omitempty"`
}

type TrafficRuleEvalInput struct {
	Host        string `json:"host"`
	IP          string `json:"ip,omitempty"`
	UA          string `json:"ua,omitempty"`
	Path        string `json:"path,omitempty"`
	Method      string `json:"method,omitempty"`
	Country     string `json:"country,omitempty"`
	QueryString string `json:"qs,omitempty"` // raw query string, no leading '?'
	// VerifiedBot is the FCrDNS-verified good-bot name for IP ("" = none).
	// The bridge fills it from the good-bot verdict cache when at least one
	// rule uses verified_bot; the simulate API resolves it synchronously from
	// the IP, or accepts it verbatim as an override ("simulate as a crawler").
	VerifiedBot string `json:"verified_bot,omitempty"`
}

// TrafficRuleEvalResult is the verdict for one request shape. Matched/Rule/
// Action/Profile describe what the edge ENFORCES: only enabled rules are
// considered, first match by (priority, id). It is the same result the nginx
// bridge acts on, so what the simulator shows is what production does.
//
// DisabledMatch is simulator-only context: the highest-priority DISABLED rule
// that would have won had it been enabled (nil when none precedes the live
// verdict). It lets the "start disabled → test → enable" workflow show
// "rule X would match if enabled" without that rule ever being enforced. A
// disabled rule ranked below the live match is not reported — enabling it
// would change nothing.
type TrafficRuleEvalResult struct {
	Matched       bool         `json:"matched"`
	Rule          TrafficRule  `json:"rule,omitempty"`
	Action        string       `json:"action,omitempty"`
	Profile       string       `json:"profile,omitempty"`
	DisabledMatch *TrafficRule `json:"disabled_match,omitempty"`
	// VerifiedBot echoes the good-bot verdict the evaluation used ("" = the
	// request was not treated as a verified crawler), so the simulator can say
	// why a verified_bot rule did or did not match. VerifiedBotExcluded carries
	// a verdict that forward-confirmed but is deliberately NOT a crawler for
	// rules (the generic "google" — Translate/AMP proxies), so the UI can say
	// "verified, but excluded" instead of "did not forward-confirm".
	VerifiedBot         string `json:"verified_bot,omitempty"`
	VerifiedBotExcluded string `json:"verified_bot_excluded,omitempty"`
	// VerifiedBotInconclusive (simulate API only) says WHY the check did not
	// complete: "timeout" (no verify slot within the wait), "transient"
	// (resolver failure), "no_resolver" (enrichment off: verified_bot rules
	// cannot match live traffic either), "no_bridge", "not_checked" (no
	// verified_bot rule exists, so nothing was resolved). With a non-empty
	// VerifiedBot it means the verdict shown is a STALE cached one whose
	// inline re-verify did not complete. Empty with an empty VerifiedBot means
	// a definitive "not a verified crawler".
	VerifiedBotInconclusive string `json:"verified_bot_inconclusive,omitempty"`
}

type trafficRuleStore struct {
	mu    sync.RWMutex
	path  string
	rules map[string]TrafficRule // key=id
	// frozen holds the verbatim JSON of rules this build cannot fully decode
	// (unknown match/scope keys). They are persisted back byte-for-byte so a
	// downgrade never rewrites — and thereby widens — a newer rule.
	frozen map[string]json.RawMessage
	// verifiedBotScopes lists the vhost scopes of ENABLED verified_bot rules,
	// so the bridge spends a good-bot cache lookup only for a host such a rule
	// can apply to. verifiedBotAny counts every non-frozen verified_bot rule
	// (enabled or not) for the simulate API, which must also be able to test a
	// rule saved disabled.
	verifiedBotScopes [][]string
	verifiedBotAny    int
}

// NeedsVerifiedBotFor reports whether an ENABLED verified_bot rule is scoped to
// host — the bridge's per-decision gate. One RLock plus a few host matches.
func (s *trafficRuleStore) NeedsVerifiedBotFor(host string) bool {
	if s == nil {
		return false
	}
	host = normalizeControlHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, vhosts := range s.verifiedBotScopes {
		if ruleHostMatch(vhosts, host) {
			return true
		}
	}
	return false
}

// HasVerifiedBotRules reports whether ANY (enabled or disabled, non-frozen)
// rule uses verified_bot — the simulate API's gate for resolving the verdict,
// so a rule saved disabled can still be tested against a real crawler IP.
func (s *trafficRuleStore) HasVerifiedBotRules() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.verifiedBotAny > 0
}

// recountLocked refreshes the derived indexes after a mutation (caller holds mu).
func (s *trafficRuleStore) recountLocked() {
	scopes := make([][]string, 0, 4)
	total := 0
	for _, r := range s.rules {
		if r.Unsupported || !r.Match.VerifiedBot {
			continue
		}
		total++
		if r.Enabled {
			scopes = append(scopes, r.Scope.Vhosts)
		}
	}
	s.verifiedBotScopes = scopes
	s.verifiedBotAny = total
}

// verifiedBotForRules narrows an FCrDNS verdict to names a traffic rule may
// trust as a CRAWLER. The registry's generic ".google.com" suffix also covers
// Google's user-driven fetchers (Translate proxy, AMP cache, Feedfetcher,
// Gmail image proxy): fine for a challenge exemption, but as an ALLOW it would
// let anyone traverse a geo-fence via translate.google.com. Excluded here.
var verifiedBotExcludedForRules = map[string]bool{"google": true}

func verifiedBotForRules(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if verifiedBotExcludedForRules[name] {
		return ""
	}
	return name
}

func newTrafficRuleStore(path string) *trafficRuleStore {
	s := &trafficRuleStore{
		path:   strings.TrimSpace(path),
		rules:  make(map[string]TrafficRule),
		frozen: make(map[string]json.RawMessage),
	}
	s.load()
	return s
}

func (s *trafficRuleStore) Add(in TrafficRule) (TrafficRule, error) {
	in.Unsupported = false // in-memory marker only; never client-settable
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
	s.recountLocked()
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
	if cur.Unsupported {
		return TrafficRule{}, errors.New("rule uses match fields this cfm build does not understand; upgrade cfm to edit or enable it")
	}

	in.Unsupported = false
	in.ID = id
	if in.CreatedAt.IsZero() {
		in.CreatedAt = cur.CreatedAt
	}
	norm, err := normalizeTrafficRule(in, false)
	if err != nil {
		return TrafficRule{}, err
	}
	s.rules[id] = norm
	s.recountLocked()
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
	delete(s.frozen, id)
	s.recountLocked()
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
	// Parse the client IP once; Unmap so a v4-mapped v6 address ("::ffff:a.b.c.d")
	// matches v4 prefixes, mirroring normalizeIPList's canonical form.
	ipAddr, ipErr := netip.ParseAddr(strings.Trim(strings.TrimSpace(in.IP), "[]"))
	ipOK := ipErr == nil
	if ipOK {
		ipAddr = ipAddr.Unmap()
	}
	rawVerifiedBot := strings.ToLower(strings.TrimSpace(in.VerifiedBot))
	verifiedBot := verifiedBotForRules(rawVerifiedBot)
	verifiedBotExcluded := ""
	if rawVerifiedBot != "" && verifiedBot == "" {
		verifiedBotExcluded = rawVerifiedBot
	}

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

	var disabled *TrafficRule
	for _, r := range rows {
		if r.Unsupported {
			// Its real conditions are unknown to this build: neither a
			// verdict nor a "would match if enabled" can be stated honestly.
			continue
		}
		if !ruleHostMatch(r.Scope.Vhosts, host) {
			continue
		}
		if !ruleMatchFilters(r.Match, ipAddr, ipOK, country, ua, path, method, in.QueryString, verifiedBot) {
			continue
		}
		if !r.Enabled {
			// Never enforce a disabled rule (this function IS the bridge's
			// enforcement path). Remember the first one for the simulator and
			// keep looking for the live verdict.
			if disabled == nil {
				rr := r
				disabled = &rr
			}
			continue
		}
		return TrafficRuleEvalResult{
			Matched:             true,
			Rule:                r,
			Action:              r.Action.Type,
			Profile:             r.Action.Profile,
			DisabledMatch:       disabled,
			VerifiedBot:         verifiedBot,
			VerifiedBotExcluded: verifiedBotExcluded,
		}
	}
	return TrafficRuleEvalResult{Matched: false, DisabledMatch: disabled, VerifiedBot: verifiedBot, VerifiedBotExcluded: verifiedBotExcluded}
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

	countriesNot, err := normalizeCodeList(r.Match.CountryNotIn, maxCountriesPerRule, true)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("country_not_in: %w", err)
	}
	r.Match.CountryNotIn = countriesNot
	if len(r.Match.CountryIn) > 0 && len(r.Match.CountryNotIn) > 0 {
		return TrafficRule{}, errors.New("country_in and country_not_in are mutually exclusive")
	}

	ips, prefixes, err := normalizeIPList(r.Match.IPAny, maxPatternsPerField)
	if err != nil {
		return TrafficRule{}, fmt.Errorf("ip_any: %w", err)
	}
	r.Match.IPAny = ips
	r.Match.ipAnyCompiled = prefixes

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
		compiled, err := regexp.Compile("(?i)" + rx)
		if err != nil {
			return TrafficRule{}, fmt.Errorf("qs_not_rx: invalid regexp: %w", err)
		}
		r.Match.QSNotRx = rx
		r.Match.qsNotRxCompiled = compiled
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

// normalizeIPList parses IPv4/IPv6 addresses and CIDR prefixes into canonical
// masked prefixes ("1.2.3.4" → "1.2.3.4/32", "2a02:587::1/64" → "2a02:587::/64"),
// de-duplicated, capped at max. Returns both the strings to persist and the
// parsed prefixes for matching.
func normalizeIPList(in []string, max int) ([]string, []netip.Prefix, error) {
	if len(in) == 0 {
		return nil, nil, nil
	}
	if len(in) > max {
		return nil, nil, fmt.Errorf("too many values (max %d)", max)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	prefixes := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		var pfx netip.Prefix
		if strings.Contains(v, "/") {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid CIDR %q", raw)
			}
			pfx = p
			// A v4-mapped v6 prefix ("::ffff:203.0.113.0/120") can never match
			// (request addresses are Unmap()ed to v4): canonicalise it to the
			// v4 prefix when it covers whole v4 bits, else reject it.
			if pfx.Addr().Is4In6() {
				if pfx.Bits() < 96 {
					return nil, nil, fmt.Errorf("invalid CIDR %q: v4-mapped prefix shorter than /96", raw)
				}
				pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
			}
		} else {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid IP %q", raw)
			}
			a = a.Unmap() // "::ffff:203.0.113.9" → 203.0.113.9/32
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		pfx = pfx.Masked()
		key := pfx.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
		prefixes = append(prefixes, pfx)
	}
	if len(out) == 0 {
		return nil, nil, nil
	}
	return out, prefixes, nil
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

// ruleMatchFilters evaluates one rule's match block. ip/ipOK come from a single
// parse in Simulate (the client IP is the same for every rule).
// verifiedBot is the FCrDNS good-bot name for the request ("" = none).
func ruleMatchFilters(m TrafficRuleMatch, ip netip.Addr, ipOK bool, country, ua, path, method, qs, verifiedBot string) bool {
	if m.VerifiedBot && verifiedBot == "" {
		return false // only a forward-confirmed crawler satisfies verified_bot
	}
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
	if len(m.CountryNotIn) > 0 {
		// Unknown country ("") never matches — see the CountryNotIn field
		// comment: "" is the fail-open sentinel, not "definitely elsewhere".
		if country == "" {
			return false
		}
		for _, cc := range m.CountryNotIn {
			if country == cc {
				return false
			}
		}
	}
	if len(m.ipAnyCompiled) > 0 {
		if !ipOK {
			return false // no/invalid client IP → an IP condition cannot match
		}
		ok := false
		for _, pfx := range m.ipAnyCompiled {
			if pfx.Contains(ip) { // false across families (v4 addr vs v6 prefix)
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
			// A lone "-" is the access-log spelling of "no User-Agent header"
			// and is what operators type to mean exactly that. Match it ONLY
			// against an absent/empty UA (the edge sends "" — cfm.lua's
			// `http_user_agent or ""` — never "-"): as a plain substring it
			// would instead match every UA containing a hyphen
			// ("python-requests", "meta-externalagent", …) and never the
			// empty one.
			if p == "-" {
				if ua == "" || ua == "-" {
					ok = true
					break
				}
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
			// A path pattern may embed a query part ("/x.php?a=b"): the segment
			// before the first '?' matches the request path, the segment after
			// matches the request query string per-parameter (see
			// queryPatternMatch). The edge (cfm.lua) delivers path and query
			// split, so operators can paste a full URL — e.g.
			// "/forum/ucp.php?mode=register" — and it matches "/forum/ucp.php"
			// with qs "mode=register&sid=…".
			pPath, pQuery, hasQuery := strings.Cut(p, "?")
			if !pathPatternMatch(strings.TrimSpace(pPath), path) {
				continue
			}
			if hasQuery && !queryPatternMatch(strings.TrimSpace(pQuery), qs) {
				continue
			}
			ok = true
			break
		}
		if !ok {
			return false
		}
	}
	// QS guards — evaluated last, after UA/path have already narrowed the candidate set
	if m.HasQS && qs == "" {
		return false
	}
	if m.qsNotRxCompiled != nil && qs != "" {
		if m.qsNotRxCompiled.MatchString(qs) {
			return false
		}
	}
	return true
}

// pathPatternMatch applies the two path-matching rules used by ruleMatchFilters
// to the path portion of a pattern (the segment before any '?'): a wildcard
// match ('*'/'?' honoured), else a literal prefix match for patterns with no
// wildcard metacharacters. An empty pattern (e.g. a bare "?query" rule) matches
// any path.
func pathPatternMatch(p, path string) bool {
	if p == "" {
		return true
	}
	if wildcardMatch(p, path) {
		return true
	}
	if !strings.ContainsAny(p, "*?") && strings.HasPrefix(path, p) {
		return true
	}
	return false
}

// queryPatternMatch reports whether the request query string satisfies the
// query part of a path pattern ("/x?a=b&c" → "a=b&c"). Matching is per
// parameter, NOT a raw substring:
//   - Both the request query and the pattern are URL-decoded first, so an
//     evasion like "mode=%72egister" (which the origin decodes to
//     "mode=register") still matches a "mode=register" pattern.
//   - Each '&'-separated token in the pattern must be present in the request:
//     "key=value" matches a parameter with that exact (case-insensitive) key
//     AND value — so "id=5" does NOT match "id=50" — while a bare "key" matches
//     any parameter with that key regardless of value.
//   - An empty pattern query (a bare "…?" suffix) matches any query; the
//     has_qs guard is the way to require merely that a query be present.
func queryPatternMatch(patQS, rawQS string) bool {
	patQS = strings.TrimSpace(patQS)
	if patQS == "" {
		return true
	}
	req := parseQueryParams(rawQS)
	for _, tok := range strings.Split(patQS, "&") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		pk, pv, hasVal := strings.Cut(tok, "=")
		pk = strings.ToLower(strings.TrimSpace(decodeQueryComponent(pk)))
		pv = strings.ToLower(strings.TrimSpace(decodeQueryComponent(pv)))
		found := false
		for _, rp := range req {
			if rp.key != pk {
				continue
			}
			if !hasVal || rp.val == pv {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type queryParam struct{ key, val string }

// parseQueryParams splits a raw query string into URL-decoded, lowercased
// key/value pairs. Malformed percent-escapes fall back to the raw component so
// a broken escape can never make the parser skip (and thus silently pass) a
// parameter.
func parseQueryParams(raw string) []queryParam {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "&")
	out := make([]queryParam, 0, len(parts))
	for _, kv := range parts {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		out = append(out, queryParam{
			key: strings.ToLower(decodeQueryComponent(k)),
			val: strings.ToLower(decodeQueryComponent(v)),
		})
	}
	return out
}

// decodeQueryComponent URL-decodes a single query key or value, returning the
// original string unchanged if it is not valid percent-encoding.
func decodeQueryComponent(s string) string {
	if dec, err := url.QueryUnescape(s); err == nil {
		return dec
	}
	return s
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
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range raws {
		e, unknown := decodeStoredRule(raw)
		if e == nil {
			continue
		}
		e.Unsupported = false
		if unknown {
			// A rule carrying match/scope keys THIS binary does not know was
			// written by a newer cfm. Dropping the keys would WIDEN the rule
			// (an allow keyed only on that field becomes allow-everything, a
			// block becomes block-everything). So: keep the original bytes
			// (written back verbatim by saveLocked), list it as disabled +
			// unsupported, never evaluate it, and refuse Update() on it.
			log.Printf("[webdet][rules] rule %s uses match/scope fields this cfm build does not understand; kept on disk verbatim, not enforced, not editable here (upgrade cfm)", e.ID)
			e.Enabled = false
			e.Unsupported = true
		}
		norm, err := normalizeTrafficRule(*e, false)
		if err != nil {
			continue
		}
		if norm.CreatedAt.IsZero() {
			norm.CreatedAt = time.Now().UTC()
		}
		s.rules[norm.ID] = norm
		if unknown {
			s.frozen[norm.ID] = append(json.RawMessage(nil), raw...)
		}
	}
	s.recountLocked()
}

// decodeStoredRule decodes one persisted rule. It reports unknown=true when
// the stored `match` or `scope` block carries a key this build does not
// define — the signal that a newer cfm wrote a selector we cannot honour (see
// load()). Only the two selector blocks are probed: a whole-rule check would
// trip on harmless future metadata (hit counters, tags). Rules that fail to
// decode at all return nil.
func decodeStoredRule(raw json.RawMessage) (*TrafficRule, bool) {
	var e TrafficRule
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false
	}
	var probe struct {
		Match json.RawMessage `json:"match"`
		Scope json.RawMessage `json:"scope"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return &e, false
	}
	if len(probe.Match) > 0 {
		dec := json.NewDecoder(bytes.NewReader(probe.Match))
		dec.DisallowUnknownFields()
		var m TrafficRuleMatch
		if err := dec.Decode(&m); err != nil {
			return &e, true
		}
	}
	if len(probe.Scope) > 0 {
		dec := json.NewDecoder(bytes.NewReader(probe.Scope))
		dec.DisallowUnknownFields()
		var sc TrafficRuleScope
		if err := dec.Decode(&sc); err != nil {
			return &e, true
		}
	}
	return &e, false
}

func (s *trafficRuleStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	type stored struct {
		prio int
		id   string
		raw  json.RawMessage
	}
	arr := make([]stored, 0, len(s.rules))
	for id, e := range s.rules {
		if raw, ok := s.frozen[id]; ok {
			// Written by a newer cfm: persist the ORIGINAL bytes so the
			// selectors this build cannot decode survive until the upgrade.
			arr = append(arr, stored{prio: e.Priority, id: id, raw: raw})
			continue
		}
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		arr = append(arr, stored{prio: e.Priority, id: id, raw: b})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].prio != arr[j].prio {
			return arr[i].prio < arr[j].prio
		}
		return arr[i].id < arr[j].id
	})
	raws := make([]json.RawMessage, 0, len(arr))
	for _, e := range arr {
		raws = append(raws, e.raw)
	}
	b, err := json.MarshalIndent(raws, "", "  ")
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
