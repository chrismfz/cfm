package webdetector

import (
	"path/filepath"
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
		{"wrong mode", "/forum/ucp.php", "mode=login", false},
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
