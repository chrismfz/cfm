package webdetector

import (
	"path/filepath"
	"testing"
)

// TestFirstWAFHostMatch pins the vhost controls' WAF column: it answers what
// MatchWAFRules (and the edge, cfm_waf_excl.lua skip_for) applies, scope
// included. A value-only match showed the WAF off on sub-hosts a scoped
// whole-WAF exclude does not take, where the edge runs it.
func TestFirstWAFHostMatch(t *testing.T) {
	type entry struct {
		value string
		scope []string
		rules []int
	}
	tests := []struct {
		name        string
		entries     []entry
		host        string
		wantMatched bool
		wantValue   string
	}{
		{"exact match", []entry{{value: "foo.com"}}, "foo.com", true, "foo.com"},
		{"subdomain match", []entry{{value: "foo.com"}}, "www.foo.com", true, "foo.com"},
		{"false positive prevention", []entry{{value: "foo.com"}}, "badfoo.com", false, ""},
		{"wildcard behavior", []entry{{value: "*.foo.com"}}, "www.foo.com", true, "*.foo.com"},
		{"rule-scoped leaves the WAF on", []entry{{value: "foo.com", rules: []int{402}}}, "foo.com", false, ""},
		{"scope takes the host", []entry{{value: "foo.com", scope: []string{"foo.com", "www.foo.com"}}}, "www.foo.com", true, "foo.com"},
		{"scope does not take a sub-host", []entry{{value: "foo.com", scope: []string{"foo.com", "www.foo.com"}}}, "shop.foo.com", false, ""},
		{"scope glob", []entry{{value: "foo.com", scope: []string{"*.foo.com"}}}, "shop.foo.com", true, "foo.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
			for _, e := range tt.entries {
				if !s.AddWithRuleIDs("host", e.value, scopeSetOf(e.scope), e.rules) {
					t.Fatalf("add %+v", e)
				}
			}
			got, matched := s.FirstWAFHostMatch(tt.host)
			if matched != tt.wantMatched || got.Value != tt.wantValue {
				t.Fatalf("FirstWAFHostMatch(%q) = (%q, %v), want (%q, %v)", tt.host, got.Value, matched, tt.wantValue, tt.wantMatched)
			}
			// The column must agree with the enforcement path.
			if skipAll, _ := s.MatchWAFRules(tt.host, "/"); skipAll != tt.wantMatched {
				t.Fatalf("MatchWAFRules(%q) skipAll = %v, column says %v", tt.host, skipAll, tt.wantMatched)
			}
		})
	}
}
