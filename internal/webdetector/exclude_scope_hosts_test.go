package webdetector

import (
	"path/filepath"
	"testing"
)

func scopeSet(hosts ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		m[h] = struct{}{}
	}
	return m
}

// A host exclude written by an account that later lost the domain can be
// removed by the domain's new owner, and the list shows the new owner none of
// the writer's other domains.
func TestHostExcludeAfterDomainMoves(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	// Account A (d.com, x.com, y.com) excludes d.com.
	if !s.Add("host", "d.com", scopeSet("d.com", "x.com", "y.com")) {
		t.Fatal("add")
	}
	// d.com moves to account B.
	b := scopeSet("d.com", "b.com")

	listed := filterExcludeListForScope(s.List(), b)
	if len(listed) != 1 {
		t.Fatalf("B lists %d entries, want 1", len(listed))
	}
	for _, h := range listed[0].ScopeHosts {
		if h != "d.com" {
			t.Fatalf("B sees A's other domain %q in scope_hosts %v", h, listed[0].ScopeHosts)
		}
	}
	if got := s.List()[0].ScopeHosts; len(got) != 3 {
		t.Fatalf("stored scope_hosts changed: %v", got)
	}

	if !s.Remove("host", "d.com", b) {
		t.Fatal("B could not remove the exclude on its own domain")
	}
	if n := len(s.List()); n != 0 {
		t.Fatalf("%d entries left after remove", n)
	}
}

// Path excludes keep the exact scope match: their scope_hosts is the set of
// sites they apply to, so another scope must not remove them.
func TestPathExcludeRemoveNeedsExactScope(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	if !s.Add("path", "/feed", scopeSet("d.com", "x.com")) {
		t.Fatal("add")
	}
	if s.Remove("path", "/feed", scopeSet("d.com")) {
		t.Fatal("a different scope removed a path exclude")
	}
	if !s.Remove("path", "/feed", scopeSet("d.com", "x.com")) {
		t.Fatal("exact scope could not remove the path exclude")
	}
}

// A rule-scoped host exclude is removed only with its own rule-id set.
func TestHostExcludeAnyScopeRemoveKeepsRuleIDs(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	s.AddWithRuleIDs("host", "d.com", scopeSet("d.com", "x.com"), []int{402})
	s.AddWithRuleIDs("host", "d.com", scopeSet("d.com", "x.com"), nil)
	if !s.RemoveWithRuleIDs("host", "d.com", scopeSet("d.com"), []int{402}) {
		t.Fatal("remove rule-scoped")
	}
	if n := len(s.List()); n != 1 || len(s.List()[0].RuleIDs) != 0 {
		t.Fatalf("left %+v, want only the whole-WAF entry", s.List())
	}
}
