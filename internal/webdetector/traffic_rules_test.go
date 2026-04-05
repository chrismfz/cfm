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
