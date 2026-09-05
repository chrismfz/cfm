package webdetector

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTrafficRuleStoreAddListPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	s := newTrafficRuleStore(path)

	rule, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 120,
		Scope: TrafficRuleScope{
			Vhosts: []string{"Example.com", "*.Example.com"},
		},
		Match: TrafficRuleMatch{
			CountryIn: []string{"us", "ca"},
			UAAny:     []string{"*meta-externalagent*"},
			PathAny:   []string{"wp-login.php"},
			Methods:   []string{"get", "post"},
		},
		Action: TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"},
		Note:   "test",
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if rule.ID == "" {
		t.Fatalf("expected generated id")
	}
	if got := len(s.List()); got != 1 {
		t.Fatalf("expected 1 rule, got %d", got)
	}

	s2 := newTrafficRuleStore(path)
	rows := s2.List()
	if len(rows) != 1 {
		t.Fatalf("expected 1 persisted rule, got %d", len(rows))
	}
	got := rows[0]
	if got.Action.Type != TrafficActionThrottle || got.Action.Profile != "soft_bot" {
		t.Fatalf("unexpected action: %+v", got.Action)
	}
	if len(got.Match.CountryIn) != 2 || got.Match.CountryIn[0] != "US" {
		t.Fatalf("unexpected countries: %#v", got.Match.CountryIn)
	}
	if len(got.Match.PathAny) != 1 || got.Match.PathAny[0] != "/wp-login.php" {
		t.Fatalf("unexpected paths: %#v", got.Match.PathAny)
	}
}

func TestTrafficRuleValidation(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))

	_, err := s.Add(TrafficRule{
		Enabled: true,
		Scope:   TrafficRuleScope{Vhosts: []string{"example.com"}},
		Action:  TrafficRuleAction{Type: TrafficActionThrottle},
	})
	if err == nil {
		t.Fatalf("expected error when throttle has no profile")
	}

	_, err = s.Add(TrafficRule{
		Enabled: true,
		Scope:   TrafficRuleScope{Vhosts: []string{"example.com"}},
		Action:  TrafficRuleAction{Type: "drop"},
	})
	if err == nil {
		t.Fatalf("expected error for unsupported action")
	}
}

func TestTrafficRuleSimulate_FirstMatchByPriority(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))

	_, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 200,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{UAAny: []string{"*facebookexternalhit*"}},
		Action:   TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"},
	})
	if err != nil {
		t.Fatalf("add throttle rule: %v", err)
	}
	_, err = s.Add(TrafficRule{
		Enabled:  true,
		Priority: 50,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{PathAny: []string{"/wp-login.php"}, Methods: []string{"POST"}},
		Action:   TrafficRuleAction{Type: TrafficActionChallenge},
	})
	if err != nil {
		t.Fatalf("add challenge rule: %v", err)
	}

	got := s.Simulate(TrafficRuleEvalInput{
		Host:   "example.com",
		UA:     "facebookexternalhit/1.1",
		Path:   "/wp-login.php",
		Method: "POST",
	})
	if !got.Matched {
		t.Fatalf("expected rule match")
	}
	if got.Action != TrafficActionChallenge {
		t.Fatalf("expected challenge action due to higher priority, got %s", got.Action)
	}
}

// TestTrafficRuleQueryInPath covers the "/path?query" pattern form: the segment
// before '?' matches the request path, the segment after is a case-insensitive
// substring match against the request query string. This is the mathematica.gr
// "challenge /forum/ucp.php?mode=register" case, which previously never matched
// because the query was compared against the path (and '?' was a wildcard).
func TestTrafficRuleQueryInPath(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if _, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 120,
		Scope:    TrafficRuleScope{Vhosts: []string{"mathematica.gr"}},
		Match: TrafficRuleMatch{
			Methods: []string{"GET", "POST"},
			PathAny: []string{"/forum/ucp.php?mode=register"},
		},
		Action: TrafficRuleAction{Type: TrafficActionChallenge},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	cases := []struct {
		name string
		path string
		qs   string
		want bool
	}{
		{"exact", "/forum/ucp.php", "mode=register", true},
		{"with extra params after", "/forum/ucp.php", "mode=register&sid=abc123", true},
		{"with extra params before", "/forum/ucp.php", "sid=abc123&mode=register", true},
		{"case insensitive", "/forum/ucp.php", "MODE=Register", true},
		{"percent-encoded value evasion", "/forum/ucp.php", "mode=%72egister", true},
		{"percent-encoded key evasion", "/forum/ucp.php", "%6dode=register", true},
		{"wrong mode", "/forum/ucp.php", "mode=login", false},
		{"value superstring is not a match", "/forum/ucp.php", "mode=registered", false},
		{"substring across params is not a match", "/forum/ucp.php", "x=mode=register", false},
		{"no query", "/forum/ucp.php", "", false},
		{"wrong path", "/forum/index.php", "mode=register", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := s.Simulate(TrafficRuleEvalInput{
				Host: "mathematica.gr", Method: "GET", Path: tc.path, QueryString: tc.qs,
			})
			if res.Matched != tc.want {
				t.Fatalf("path=%q qs=%q matched=%v want=%v", tc.path, tc.qs, res.Matched, tc.want)
			}
		})
	}
}

// TestTrafficRulePlainPathIgnoresQuery confirms a path-only pattern (no '?')
// still matches regardless of the request query string — no regression.
func TestTrafficRulePlainPathIgnoresQuery(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if _, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 120,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{PathAny: []string{"/wp-login.php"}},
		Action:   TrafficRuleAction{Type: TrafficActionChallenge},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, qs := range []string{"", "redirect_to=%2Fwp-admin%2F", "action=register"} {
		res := s.Simulate(TrafficRuleEvalInput{Host: "example.com", Method: "GET", Path: "/wp-login.php", QueryString: qs})
		if !res.Matched {
			t.Fatalf("plain path should match regardless of qs=%q", qs)
		}
	}
}

// TestTrafficRuleQueryParamPrecision pins the per-parameter matching semantics:
// an "id=5" pattern matches only an exact id=5 parameter (not id=50 / userid=5),
// and a bare "token" key pattern matches any value for that key.
func TestTrafficRuleQueryParamPrecision(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	add := func(id, pattern string) {
		if _, err := s.Add(TrafficRule{
			ID:       id,
			Enabled:  true,
			Priority: 100,
			Scope:    TrafficRuleScope{Vhosts: []string{id + ".example.com"}},
			Match:    TrafficRuleMatch{PathAny: []string{pattern}},
			Action:   TrafficRuleAction{Type: TrafficActionChallenge},
		}); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}
	add("exact", "/api?id=5")
	add("keyonly", "/dl?token")

	cases := []struct {
		rule string
		qs   string
		want bool
	}{
		{"exact", "id=5", true},
		{"exact", "id=5&x=1", true},
		{"exact", "id=50", false},    // value superstring
		{"exact", "userid=5", false}, // key superstring
		{"exact", "id=6", false},     // wrong value
		{"keyonly", "token=anything", true},
		{"keyonly", "token=", true},
		{"keyonly", "other=1", false},
	}
	for _, tc := range cases {
		t.Run(tc.rule+"_"+tc.qs, func(t *testing.T) {
			res := s.Simulate(TrafficRuleEvalInput{
				Host: tc.rule + ".example.com", Method: "GET",
				Path: map[string]string{"exact": "/api", "keyonly": "/dl"}[tc.rule], QueryString: tc.qs,
			})
			if res.Matched != tc.want {
				t.Fatalf("rule=%s qs=%q matched=%v want=%v", tc.rule, tc.qs, res.Matched, tc.want)
			}
		})
	}
}

// TestTrafficRuleSimulate_DisabledRulesNeverEnforce pins the contract that
// Simulate — which is ALSO the nginx bridge's enforcement path (RuleDecision) —
// never returns a disabled rule as the verdict. Before this test a "block
// CN,RU (disabled)" preset blocked live traffic, because the loop only looked
// at host + filters. The disabled would-be match is surfaced separately via
// DisabledMatch so the simulator can say "would match if enabled".
func TestTrafficRuleSimulate_DisabledRulesNeverEnforce(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))

	blockAll, err := s.Add(TrafficRule{
		Enabled:  false,
		Priority: 10,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Action:   TrafficRuleAction{Type: TrafficActionBlock},
		Note:     "disabled block-all",
	})
	if err != nil {
		t.Fatalf("add disabled rule: %v", err)
	}

	// Only a disabled rule matches → no enforcement, but it is reported.
	got := s.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET"})
	if got.Matched {
		t.Fatalf("disabled rule must never be the verdict: %+v", got)
	}
	if got.DisabledMatch == nil || got.DisabledMatch.ID != blockAll.ID {
		t.Fatalf("expected disabled_match=%s, got %+v", blockAll.ID, got.DisabledMatch)
	}

	// An enabled rule ranked BELOW the disabled one wins the verdict; the
	// disabled one is still reported because it precedes the live match.
	thr, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 100,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Action:   TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"},
	})
	if err != nil {
		t.Fatalf("add throttle rule: %v", err)
	}
	got = s.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET"})
	if !got.Matched || got.Rule.ID != thr.ID || got.Action != TrafficActionThrottle {
		t.Fatalf("expected enabled throttle verdict, got %+v", got)
	}
	if got.DisabledMatch == nil || got.DisabledMatch.ID != blockAll.ID {
		t.Fatalf("expected preceding disabled rule to be reported, got %+v", got.DisabledMatch)
	}

	// A disabled rule ranked AFTER the live match is irrelevant → not reported.
	if _, err := s.Add(TrafficRule{
		Enabled:  false,
		Priority: 500,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Action:   TrafficRuleAction{Type: TrafficActionChallenge},
	}); err != nil {
		t.Fatalf("add trailing disabled rule: %v", err)
	}
	if ok := s.Remove(blockAll.ID); !ok {
		t.Fatalf("remove disabled block-all")
	}
	got = s.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET"})
	if !got.Matched || got.Rule.ID != thr.ID {
		t.Fatalf("expected throttle verdict, got %+v", got)
	}
	if got.DisabledMatch != nil {
		t.Fatalf("disabled rule shadowed by the live match must not be reported: %+v", got.DisabledMatch)
	}

	// Persisted + reloaded: the enabled flag survives and the contract holds.
	s2 := newTrafficRuleStore(s.path)
	got = s2.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET"})
	if !got.Matched || got.Action != TrafficActionThrottle {
		t.Fatalf("reloaded store: expected throttle verdict, got %+v", got)
	}
}

// TestTrafficRuleUA_DashMeansNoUserAgent: a lone "-" UA pattern matches only a
// request WITHOUT a User-Agent (the edge sends "" for a missing header; "-" is
// the access-log spelling operators type). It must not act as a substring
// match for every hyphenated UA.
func TestTrafficRuleUA_DashMeansNoUserAgent(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if _, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 10,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{UAAny: []string{"-"}},
		Action:   TrafficRuleAction{Type: TrafficActionBlock},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	cases := []struct {
		ua   string
		want bool
	}{
		{"", true},
		{"-", true},
		{"python-requests/2.31", false},
		{"meta-externalagent/1.1", false},
		{"Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0", false},
	}
	for _, tc := range cases {
		got := s.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET", UA: tc.ua}).Matched
		if got != tc.want {
			t.Fatalf("ua=%q matched=%v want=%v", tc.ua, got, tc.want)
		}
	}
}

// TestTrafficRuleCountryNotIn: "everyone except GR/CY" as ONE rule. An empty
// country ("") is the edge's fail-open sentinel (geo down / cache miss /
// cfm_panel.lua) and must NOT match, or a geo hiccup would 403 every visitor.
func TestTrafficRuleCountryNotIn(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if _, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 900,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{CountryNotIn: []string{"gr", "CY"}},
		Action:   TrafficRuleAction{Type: TrafficActionBlock},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, tc := range []struct {
		cc   string
		want bool
	}{{"GR", false}, {"cy", false}, {"US", true}, {"", false}} {
		got := s.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET", Country: tc.cc}).Matched
		if got != tc.want {
			t.Fatalf("country=%q matched=%v want=%v", tc.cc, got, tc.want)
		}
	}
	// Persisted upper-cased, and the two country fields are mutually exclusive.
	rows := newTrafficRuleStore(s.path).List()
	if len(rows) != 1 || len(rows[0].Match.CountryNotIn) != 2 || rows[0].Match.CountryNotIn[0] != "GR" {
		t.Fatalf("unexpected persisted not_in: %#v", rows)
	}
	if _, err := s.Add(TrafficRule{
		Scope:  TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:  TrafficRuleMatch{CountryIn: []string{"GR"}, CountryNotIn: []string{"US"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	}); err == nil {
		t.Fatalf("expected country_in + country_not_in to be rejected")
	}
	if _, err := s.Add(TrafficRule{
		Scope:  TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:  TrafficRuleMatch{CountryNotIn: []string{"GRE"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	}); err == nil {
		t.Fatalf("expected 3-letter code in country_not_in to be rejected")
	}
}

// TestTrafficRuleIPAny: IPv4/IPv6 CIDR + bare-address matching, canonical
// storage, and the fail-closed behaviour for a missing/invalid client IP.
func TestTrafficRuleIPAny(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	r, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 15,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{IPAny: []string{"203.0.113.0/24", " 198.51.100.7 ", "2001:db8:abcd::1/48", "203.0.113.128/25", "::ffff:192.0.2.9", "::ffff:192.0.2.0/120"}},
		Action:   TrafficRuleAction{Type: TrafficActionAllow},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// v4-mapped entries are canonicalised to plain v4 so they can actually match.
	want := []string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8:abcd::/48", "203.0.113.128/25", "192.0.2.9/32", "192.0.2.0/24"}
	if len(r.Match.IPAny) != len(want) {
		t.Fatalf("stored ip_any %#v want %#v", r.Match.IPAny, want)
	}
	for i := range want {
		if r.Match.IPAny[i] != want[i] {
			t.Fatalf("stored ip_any[%d]=%q want %q", i, r.Match.IPAny[i], want[i])
		}
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.9", true},
		{"203.0.113.200", true},
		{"198.51.100.7", true},
		{"198.51.100.8", false},
		{"2001:db8:abcd:1::5", true},
		{"2001:db8:abce::1", false},
		{"::ffff:203.0.113.9", true}, // v4-mapped v6 is unmapped before matching
		{"192.0.2.9", true},          // stored from "::ffff:192.0.2.9"
		{"192.0.2.77", true},         // stored from "::ffff:192.0.2.0/120" → /24
		{"[2001:db8:abcd::7]", true}, // bracketed v6 tolerated
		{"", false},
		{"not-an-ip", false},
	}
	for _, sto := range []*trafficRuleStore{s, newTrafficRuleStore(s.path)} {
		for _, tc := range cases {
			got := sto.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET", IP: tc.ip}).Matched
			if got != tc.want {
				t.Fatalf("ip=%q matched=%v want=%v", tc.ip, got, tc.want)
			}
		}
	}
	for _, bad := range []string{"203.0.113.0/33", "1.2.3", "2001:db8::/129", "example.com", "::ffff:192.0.2.0/95", "01.2.3.4", "1.2.3.4/024"} {
		if _, err := s.Add(TrafficRule{
			Scope:  TrafficRuleScope{Vhosts: []string{"example.com"}},
			Match:  TrafficRuleMatch{IPAny: []string{bad}},
			Action: TrafficRuleAction{Type: TrafficActionAllow},
		}); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

// TestTrafficRuleIPAny_ComposesWithGeoFence: office range allow (15) → good bots
// allow (10 already) → block country_not_in (900): the Phase-2 geo-fence recipe.
func TestTrafficRuleIPAny_ComposesWithGeoFence(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	add := func(pr int, m TrafficRuleMatch, act string) {
		if _, err := s.Add(TrafficRule{Enabled: true, Priority: pr, Scope: TrafficRuleScope{Vhosts: []string{"shop.gr"}}, Match: m, Action: TrafficRuleAction{Type: act}}); err != nil {
			t.Fatalf("add %d: %v", pr, err)
		}
	}
	add(15, TrafficRuleMatch{IPAny: []string{"203.0.113.0/24"}}, TrafficActionAllow)
	add(900, TrafficRuleMatch{CountryNotIn: []string{"GR", "CY"}}, TrafficActionBlock)
	for _, tc := range []struct {
		ip, cc, want string
	}{
		{"203.0.113.5", "US", TrafficActionAllow}, // office from abroad
		{"198.51.100.1", "US", TrafficActionBlock},
		{"198.51.100.1", "GR", ""},
		{"198.51.100.1", "", ""}, // unknown geo is fail-open: never fenced out
	} {
		res := s.Simulate(TrafficRuleEvalInput{Host: "shop.gr", Path: "/", Method: "GET", IP: tc.ip, Country: tc.cc})
		if res.Action != tc.want {
			t.Fatalf("ip=%s cc=%q action=%q want %q", tc.ip, tc.cc, res.Action, tc.want)
		}
	}
}

// TestTrafficRuleLoad_UnknownFieldsFrozen: a rules.json written by a NEWER cfm
// may carry match/scope keys this build does not know. Ignoring them would
// widen the rule (an allow keyed only on the unknown field becomes
// allow-everything), so such a rule is listed disabled+unsupported, never
// evaluated, refused by Update, and — crucially — written back to disk
// VERBATIM on the next save so the upgrade finds it intact.
func TestTrafficRuleLoad_UnknownFieldsFrozen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	data := `[
	  {"id":"r_future","enabled":true,"priority":15,"scope":{"vhosts":["example.com"]},
	   "match":{"asn_in":[16509]},"action":{"type":"allow"},"note":"written by a newer cfm"},
	  {"id":"r_scope","enabled":true,"priority":20,"scope":{"vhosts":["*.example.com"],"exclude_vhosts":["admin.example.com"]},
	   "match":{"country_in":["US"]},"action":{"type":"block"}},
	  {"id":"r_known","enabled":true,"priority":900,"scope":{"vhosts":["example.com"]},
	   "match":{"country_not_in":["GR"]},"action":{"type":"block"}}
	]`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := newTrafficRuleStore(path)
	for _, id := range []string{"r_future", "r_scope"} {
		r, ok := s.Get(id)
		if !ok {
			t.Fatalf("%s must still load", id)
		}
		if r.Enabled || !r.Unsupported {
			t.Fatalf("%s must load disabled+unsupported, got enabled=%v unsupported=%v", id, r.Enabled, r.Unsupported)
		}
	}
	known, ok := s.Get("r_known")
	if !ok || !known.Enabled || known.Unsupported {
		t.Fatalf("known-field rule must load enabled: ok=%v %+v", ok, known)
	}

	// Never evaluated: neither verdict nor disabled_match.
	res := s.Simulate(TrafficRuleEvalInput{Host: "example.com", Path: "/", Method: "GET", Country: "US"})
	if !res.Matched || res.Rule.ID != "r_known" {
		t.Fatalf("expected the known block to win, got %+v", res)
	}
	if res.DisabledMatch != nil {
		t.Fatalf("unsupported rule must not surface as disabled_match: %+v", res.DisabledMatch)
	}

	// Cannot be enabled/edited here.
	fut, _ := s.Get("r_future")
	fut.Enabled = true
	if _, err := s.Update("r_future", fut); err == nil {
		t.Fatalf("Update on an unsupported rule must be refused")
	}

	// A save triggered by ANY other write keeps the unknown selectors verbatim.
	if _, err := s.Add(TrafficRule{
		Enabled: true, Priority: 500,
		Scope:  TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:  TrafficRuleMatch{Methods: []string{"POST"}},
		Action: TrafficRuleAction{Type: TrafficActionChallenge},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, needle := range []string{`"asn_in"`, `16509`, `"exclude_vhosts"`, `"admin.example.com"`} {
		if !strings.Contains(string(b), needle) {
			t.Fatalf("rules.json lost %s after save:\n%s", needle, b)
		}
	}
	if strings.Contains(string(b), `"unsupported"`) {
		t.Fatalf("in-memory marker must not be persisted:\n%s", b)
	}
	// The frozen rule keeps its ORIGINAL enabled:true on disk (the newer build
	// will honour it again), while this build still sees it disabled.
	s2 := newTrafficRuleStore(path)
	if r, _ := s2.Get("r_future"); r.Enabled || !r.Unsupported {
		t.Fatalf("reloaded frozen rule: %+v", r)
	}
	var back []map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal saved file: %v", err)
	}
	for _, m := range back {
		if m["id"] == "r_future" && m["enabled"] != true {
			t.Fatalf("frozen rule's on-disk enabled flag must stay as written by the newer cfm: %v", m)
		}
	}
	// Removing a frozen rule removes its bytes too.
	if !s2.Remove("r_scope") {
		t.Fatalf("remove frozen")
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), `"exclude_vhosts"`) {
		t.Fatalf("removed frozen rule still on disk")
	}
	// A client cannot mark a rule unsupported through the API.
	added, err := s2.Add(TrafficRule{
		Unsupported: true, Enabled: true, Priority: 600,
		Scope:  TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:  TrafficRuleMatch{Methods: []string{"PUT"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	})
	if err != nil || added.Unsupported {
		t.Fatalf("Add must clear the in-memory marker: err=%v %+v", err, added)
	}
}

// TestTrafficRuleVerifiedBot: match.verified_bot is satisfied ONLY by a
// non-empty FCrDNS verdict on the input; a User-Agent never counts. The verdict
// is echoed in the result so the simulator can explain the outcome, and the
// store's HasVerifiedBotRules counter follows enabled rules only.
func TestTrafficRuleVerifiedBot(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if s.HasVerifiedBotRules() {
		t.Fatalf("empty store must not need verified-bot lookups")
	}
	allow, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 10,
		Scope:    TrafficRuleScope{Vhosts: []string{"shop.gr"}},
		Match:    TrafficRuleMatch{VerifiedBot: true},
		Action:   TrafficRuleAction{Type: TrafficActionAllow},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := s.Add(TrafficRule{
		Enabled:  true,
		Priority: 900,
		Scope:    TrafficRuleScope{Vhosts: []string{"shop.gr"}},
		Match:    TrafficRuleMatch{CountryNotIn: []string{"GR"}},
		Action:   TrafficRuleAction{Type: TrafficActionBlock},
	}); err != nil {
		t.Fatalf("add block: %v", err)
	}
	if !s.HasVerifiedBotRules() || !s.NeedsVerifiedBotFor("shop.gr") || !s.NeedsVerifiedBotFor("SHOP.GR.") {
		t.Fatalf("store must report a verified_bot rule for shop.gr")
	}
	if s.NeedsVerifiedBotFor("other.gr") {
		t.Fatalf("the per-host gate must not fire for a host no verified_bot rule covers")
	}

	// Googlebot UA from the US without a verdict → the fence blocks it.
	res := s.Simulate(TrafficRuleEvalInput{Host: "shop.gr", Path: "/", Method: "GET", IP: "66.249.66.1", Country: "US", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)"})
	if res.Action != TrafficActionBlock || res.VerifiedBot != "" {
		t.Fatalf("UA alone must not satisfy verified_bot: %+v", res)
	}
	// With a verdict → the allow wins and the verdict is echoed (lower-cased).
	res = s.Simulate(TrafficRuleEvalInput{Host: "shop.gr", Path: "/", Method: "GET", IP: "66.249.66.1", Country: "US", VerifiedBot: " GoogleBot "})
	if res.Action != TrafficActionAllow || res.Rule.ID != allow.ID || res.VerifiedBot != "googlebot" {
		t.Fatalf("verified crawler must hit the allow: %+v", res)
	}
	// The generic "google" verdict (*.google.com: Translate proxy, AMP cache,
	// Feedfetcher) is excluded for rules — otherwise translate.google.com
	// would traverse any geo-fence.
	res = s.Simulate(TrafficRuleEvalInput{Host: "shop.gr", Path: "/", Method: "GET", IP: "74.125.1.1", Country: "US", VerifiedBot: "google"})
	if res.Action != TrafficActionBlock || res.VerifiedBot != "" {
		t.Fatalf("generic google verdict must not satisfy verified_bot: %+v", res)
	}

	// Disabling the rule: the bridge's per-host gate drops (no more lookups on
	// the hot path) but the simulate API can still test the disabled rule.
	allow.Enabled = false
	if _, err := s.Update(allow.ID, allow); err != nil {
		t.Fatalf("update: %v", err)
	}
	if s.NeedsVerifiedBotFor("shop.gr") {
		t.Fatalf("disabled verified_bot rule must not gate the hot path")
	}
	if !s.HasVerifiedBotRules() {
		t.Fatalf("a disabled verified_bot rule must still be testable via the simulate API")
	}
	if !s.Remove(allow.ID) {
		t.Fatalf("remove")
	}
	// Persisted + reloaded counter.
	if _, err := s.Add(TrafficRule{Enabled: true, Priority: 11, Scope: TrafficRuleScope{Vhosts: []string{"shop.gr"}}, Match: TrafficRuleMatch{VerifiedBot: true}, Action: TrafficRuleAction{Type: TrafficActionAllow}}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if re := newTrafficRuleStore(s.path); !re.HasVerifiedBotRules() || !re.NeedsVerifiedBotFor("shop.gr") {
		t.Fatalf("reloaded store must rebuild the verified_bot indexes")
	}
}

// TestVerifiedBotNamesListedInRulesModel keeps the cfm-admin display list of
// verifiable crawlers (rules-model.js VERIFIED_BOT_NAMES) in step with the Go
// registry goodBotPTRSuffixes — the JS copy is for display only, but a name
// missing there misleads the operator about what verified_bot covers.
func TestVerifiedBotNamesListedInRulesModel(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("..", "webui", "static", "assets", "webdet", "rules-model.js"))
	if err != nil {
		t.Skipf("rules-model.js not found: %v", err)
	}
	src := string(js)
	start := strings.Index(src, "VERIFIED_BOT_NAMES")
	if start < 0 {
		t.Fatalf("rules-model.js has no VERIFIED_BOT_NAMES")
	}
	end := strings.Index(src[start:], "]")
	if end < 0 {
		t.Fatalf("VERIFIED_BOT_NAMES not terminated")
	}
	jsNames := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z0-9_-]+)"`).FindAllStringSubmatch(src[start:start+end], -1) {
		jsNames[m[1]] = true
	}
	want := map[string]bool{}
	for _, name := range goodBotPTRSuffixes {
		if !verifiedBotExcludedForRules[name] {
			want[name] = true
		}
	}
	for name := range want {
		if !jsNames[name] {
			t.Errorf("good-bot %q (goodBotPTRSuffixes) is missing from rules-model.js VERIFIED_BOT_NAMES", name)
		}
	}
	for name := range jsNames {
		if !want[name] {
			t.Errorf("rules-model.js VERIFIED_BOT_NAMES lists %q, which the daemon cannot verify for rules (not in goodBotPTRSuffixes, or excluded)", name)
		}
	}
}

// jsStringList extracts the string literals of one exported JS array constant
// from rules-model.js (`NAME = Object.freeze([ "a", "b" ])`), so a Go test can
// exercise the recipe lists against the real matcher without keeping a second
// copy of them (CLAUDE.md §5: one source, never a drifting twin).
func jsStringList(t *testing.T, src, name string) []string {
	t.Helper()
	start := strings.Index(src, "export const "+name+" ")
	if start < 0 {
		t.Fatalf("rules-model.js has no %s", name)
	}
	open := strings.Index(src[start:], "[")
	end := strings.Index(src[start:], "]")
	if open < 0 || end < 0 || end < open {
		t.Fatalf("%s not a bracketed list", name)
	}
	var out []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(src[start+open:start+end], -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatalf("%s is empty", name)
	}
	return out
}

func jsStringConst(t *testing.T, src, name string) string {
	t.Helper()
	m := regexp.MustCompile(`export const ` + name + ` = "((?:[^"\\]|\\.)*)";`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("rules-model.js has no string constant %s", name)
	}
	return m[1]
}

// TestRecipeProbePathsMatchScannerPaths runs the cfm-admin "Block secret /
// dev-file probes" recipe list (rules-model.js PROBE_PATHS) through the SAME
// matcher the edge enforces (ruleMatchFilters → pathPatternMatch): every path
// the 2026-09 Google-Cloud sweeps requested must match, /.well-known/ (ACME /
// DCV) and ordinary catalogue paths must not, and the recipes' query-keyed
// pattern "/?wc-ajax" must mean "any path whose query carries wc-ajax".
func TestRecipeProbePathsMatchScannerPaths(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("..", "webui", "static", "assets", "webdet", "rules-model.js"))
	if err != nil {
		t.Skipf("rules-model.js not found: %v", err)
	}
	src := string(js)
	probe := jsStringList(t, src, "PROBE_PATHS")
	if len(probe) > maxPatternsPerField {
		t.Fatalf("PROBE_PATHS has %d entries, the rule field allows %d", len(probe), maxPatternsPerField)
	}
	if _, err := normalizePatternList(probe, maxPatternsPerField, true); err != nil {
		t.Fatalf("PROBE_PATHS rejected by normalizePatternList: %v", err)
	}
	m := TrafficRuleMatch{PathAny: probe}
	hit := func(path string) bool {
		return ruleMatchFilters(m, netip.MustParseAddr("203.0.113.9"), true, "US", "Mozilla/5.0", path, "GET", "", "")
	}
	for _, p := range []string{
		"/.env", "/.env.local", "/.env.production", "/bin/.env", // prefix on the file, wildcard-free
		"/.git/config", "/.svn/entries", "/.aws/credentials", "/.ssh/id_rsa", "/.htpasswd", "/.DS_Store",
		"/phpinfo.php", "/wp-admin/phpinfo.php", "/mail/phpinfo.php", "/old_phpinfo.php", "/_profiler/phpinfo",
		"/phpinfo.php.bak", "/wp-config.php.bak", "/index.php.old", "/config.php.save", "/phpinfo.php~", "/backup/site.sql",
		"/server-status", "/server-status.php",
	} {
		if !hit(p) {
			t.Errorf("probe path %q must match PROBE_PATHS", p)
		}
	}
	for _, p := range []string{
		"/", "/.well-known/acme-challenge/token", "/.well-known/pki-validation/x.txt", "/product/ring-19003w/",
		"/wp-content/uploads/2025/12/photo.jpg", "/environment/", "/gitlab/", "/servers/", "/info.php", "/assets/app.php",
		"/wp-admin/admin-ajax.php", "/xmlrpc.php", "/server-information/", "/environment.php",
	} {
		if hit(p) {
			t.Errorf("legitimate path %q must NOT match PROBE_PATHS", p)
		}
	}
	if strings.HasPrefix("/bin/.env", "/.env") {
		t.Fatalf("test premise: /bin/.env is not a prefix match")
	}

	// "/?wc-ajax": the path part "/" prefix-matches every path, the query part
	// requires a wc-ajax parameter (any value) — WooCommerce fragments on every
	// locale prefix, nothing else.
	wc := TrafficRuleMatch{PathAny: []string{"/?wc-ajax"}}
	hitWC := func(path, qs string) bool {
		return ruleMatchFilters(wc, netip.MustParseAddr("203.0.113.9"), true, "GR", "Mozilla/5.0", path, "POST", qs, "")
	}
	if !hitWC("/", "wc-ajax=get_refreshed_fragments") || !hitWC("/en/", "wc-ajax=xoo_wsc_refresh_fragments") {
		t.Errorf("/?wc-ajax must match a wc-ajax query on any path")
	}
	if hitWC("/", "") || hitWC("/shop/", "min_price=120&filter_color=red") {
		t.Errorf("/?wc-ajax must not match without the parameter")
	}

	// The bot query-string pass-through must be valid Go RE2 with the "(?i)"
	// prefix normalizeTrafficRule adds, and must let pagination / click ids
	// through while catching a facet grid.
	rx, err := regexp.Compile("(?i)" + jsStringConst(t, src, "BOT_QS_PASSTHROUGH"))
	if err != nil {
		t.Fatalf("BOT_QS_PASSTHROUGH is not RE2: %v", err)
	}
	for _, ok := range []string{"page=2", "fbclid=IwAR0", "utm_source=fb&x=1", "a=1&paged=3", "gclid=abc"} {
		if !rx.MatchString(ok) {
			t.Errorf("pass-through %q should match BOT_QS_PASSTHROUGH", ok)
		}
	}
	for _, facet := range []string{"min_price=120&filter_color=red", "ind=k&ind=n", "orderby=price", "pageless=1", "lg-min=10&lv-max=-380"} {
		if rx.MatchString(facet) {
			t.Errorf("facet %q must not match BOT_QS_PASSTHROUGH", facet)
		}
	}
}
