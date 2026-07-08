package webdetector

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCompiledValueMatcher_BoundarySemantics locks the host/path boundary
// matching that replaced a plain strings.Contains (which silently disabled the
// WAF/challenge on unintended vhosts/paths). It MUST stay in lock-step with the
// Lua matcher (configs/lua/cfm_waf_excl.lua matches_rule; the mirror cases live
// in scripts/tests/cfm_waf_excl_test.lua) — the in-path (Lua) and log-driven
// (Go) engines must agree on which requests an exclude covers.
func TestCompiledValueMatcher_BoundarySemantics(t *testing.T) {
	cases := []struct {
		kind, rule, value string
		want              bool
	}{
		// host: exact or dot-boundary subdomain suffix
		{"host", "shop.gr", "shop.gr", true},
		{"host", "shop.gr", "www.shop.gr", true},
		{"host", "shop.gr", "cpanel.shop.gr", true},
		{"host", "shop.gr", "a.b.shop.gr", true},
		{"host", "shop.gr", "myshop.gr", false},        // the substring bug
		{"host", "shop.gr", "shop.gr.evil.com", false}, // suffix-embedded
		{"host", "shop.gr", "evil-shop.gr", false},     // prefix-glued label
		{"host", "www.shop.gr", "shop.gr", false},      // parent ≠ child rule
		// path: exact or path-segment prefix
		{"path", "/admin", "/admin", true},
		{"path", "/admin", "/admin/users", true},
		{"path", "/admin", "/admin/", true},
		{"path", "/admin", "/administrator", false}, // the substring bug
		{"path", "/admin", "/admin-panel", false},
		{"path", "/api", "/therapy", false}, // mid-string substring
		{"path", "/.well-known/", "/.well-known/acme/x", true},
		{"path", "/.well-known/", "/.well-known", false}, // trailing-slash rule needs the slash
		// glob: anchored wildcard matching, unchanged
		{"host", "*.shop.gr", "www.shop.gr", true},
		{"host", "*.shop.gr", "shop.gr", false},
		{"host", "*shop.gr", "myshop.gr", true}, // explicit operator glob
		{"path", "/wp-admin/*", "/wp-admin/setup", true},
		{"path", "/wp-admin/*", "/wp-adminx", false},
		// glob wildcards are SEGMENT-scoped ([^/]* / [^/], not .* / .) — they
		// do NOT cross a '/'. These MUST stay in lock-step with the in-path Lua
		// matcher (scripts/tests/cfm_waf_excl_test.lua): a regression to '.*'
		// here would silently re-open the one-sided WAF-off widening (audit F10).
		{"path", "/wp-admin/*", "/wp-admin/a/b", false}, // '*' stops at one segment
		{"path", "/assets/*", "/assets/app.js", true},
		{"path", "/?/b", "/a/b", true},
		{"path", "/?/b", "///b", false}, // '?' is [^/], not '.'
		{"path", "/*/b", "/a/b", true},
		{"path", "/*/b", "/a/b/c", false}, // leading /*/ is exactly one segment
	}
	for _, c := range cases {
		got := compileValueMatcher(c.kind, c.rule).Match(c.value)
		if got != c.want {
			t.Errorf("Match(kind=%s rule=%q value=%q) = %v, want %v", c.kind, c.rule, c.value, got, c.want)
		}
	}
}

func TestExcludeStore_ScopedHostMatch(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	scope := map[string]struct{}{"app.example.com": {}}
	if ok := s.Add("host", "app.example.com", scope); !ok {
		t.Fatalf("expected scoped add to succeed")
	}
	if !s.MatchChallenge("app.example.com") {
		t.Fatalf("expected host to match scoped entry")
	}
	if s.MatchChallenge("other.example.com") {
		t.Fatalf("did not expect host outside scope to match")
	}
}

func TestExcludeStore_ScopedPathMatchRequiresHostInScope(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	scope := map[string]struct{}{"www.example.com": {}}
	if ok := s.Add("path", "/wp-admin/*", scope); !ok {
		t.Fatalf("expected scoped path add to succeed")
	}
	if !s.MatchWAF("www.example.com", "/wp-admin/setup") {
		t.Fatalf("expected in-scope host/path to match")
	}
	if s.MatchWAF("other.example.com", "/wp-admin/setup") {
		t.Fatalf("did not expect path match for out-of-scope host")
	}
}

func TestExcludeStore_LoadLegacyEntriesAsGlobal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "excludes.json")
	legacy := `[{"type":"path","value":"/legacy","created_at":"2026-01-01T00:00:00Z"}]`
	if err := os.WriteFile(p, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}
	s := newExcludeStore(p)
	if !s.MatchWAF("any.example.com", "/legacy") {
		t.Fatalf("expected legacy entry without scope to be treated global")
	}
}

func TestExcludeStore_MatchWAFChecksHostAndPathRulesWithScope(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	scope := map[string]struct{}{"tenant-a.example.com": {}}
	if ok := s.Add("path", "/wp-admin/*", scope); !ok {
		t.Fatalf("expected scoped path add to succeed")
	}
	if ok := s.Add("host", "tenant-a.example.com", scope); !ok {
		t.Fatalf("expected scoped host add to succeed")
	}
	if !s.MatchWAF("tenant-a.example.com", "/wp-admin/index.php") {
		t.Fatalf("expected in-scope host+path to match")
	}
	if s.MatchWAF("tenant-b.example.com", "/wp-admin/index.php") {
		t.Fatalf("expected out-of-scope tenant path to not match")
	}
	if s.MatchWAF("tenant-b.example.com", "/") {
		t.Fatalf("expected out-of-scope tenant host to not match")
	}
}

// Rule-scoped exclude should not trigger MatchWAF (which means "skip the
// whole WAF"); it should only show up in MatchWAFRules.skipIDs.
func TestExcludeStore_RuleScopedDoesNotTriggerWholeWAFSkip(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	if ok := s.AddWithRuleIDs("host", "scraper-target.example.com", nil, []int{321}); !ok {
		t.Fatalf("expected rule-scoped host add to succeed")
	}
	if s.MatchWAF("scraper-target.example.com", "/anything") {
		t.Fatalf("rule-scoped exclude must NOT trigger whole-WAF MatchWAF")
	}
	skipAll, skipIDs := s.MatchWAFRules("scraper-target.example.com", "/anything")
	if skipAll {
		t.Fatalf("rule-scoped exclude wrongly returned skipAll=true")
	}
	if _, ok := skipIDs[321]; !ok {
		t.Fatalf("expected skipIDs to contain 321; got %v", skipIDs)
	}
	if len(skipIDs) != 1 {
		t.Fatalf("expected only rule 321 in skipIDs; got %v", skipIDs)
	}
}

// Whole-WAF entry takes precedence; even with a rule-scoped entry alongside,
// MatchWAFRules short-circuits on skipAll=true.
func TestExcludeStore_WholeWAFShortCircuitsOverRuleScoped(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	if ok := s.Add("host", "noisy.example.com", nil); !ok {
		t.Fatalf("expected legacy whole-WAF add to succeed")
	}
	if ok := s.AddWithRuleIDs("host", "noisy.example.com", nil, []int{320}); !ok {
		t.Fatalf("expected rule-scoped add on same host to succeed (different key)")
	}
	skipAll, _ := s.MatchWAFRules("noisy.example.com", "/")
	if !skipAll {
		t.Fatalf("expected whole-WAF entry to win → skipAll=true")
	}
}

// Two rule-scoped entries on the same host union their RuleIDs in skipIDs.
func TestExcludeStore_RuleScopedUnion(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	if ok := s.AddWithRuleIDs("host", "vito.example.com", nil, []int{321}); !ok {
		t.Fatalf("first add failed")
	}
	if ok := s.AddWithRuleIDs("host", "vito.example.com", nil, []int{401, 402}); !ok {
		t.Fatalf("second add failed (different RuleIDs should be a distinct entry)")
	}
	skipAll, skipIDs := s.MatchWAFRules("vito.example.com", "/")
	if skipAll {
		t.Fatalf("no whole-WAF entry exists; skipAll must be false")
	}
	want := []int{321, 401, 402}
	for _, id := range want {
		if _, ok := skipIDs[id]; !ok {
			t.Errorf("expected skipIDs to contain %d; got %v", id, skipIDs)
		}
	}
	if len(skipIDs) != 3 {
		t.Errorf("expected 3 IDs in union; got %v", skipIDs)
	}
}

// Persistence round-trip: rule-scoped entries survive a store reload.
func TestExcludeStore_RuleIDsPersistAcrossLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "excludes.json")
	s1 := newExcludeStore(p)
	if ok := s1.AddWithRuleIDs("host", "persist.example.com", nil, []int{320, 401}); !ok {
		t.Fatalf("add failed")
	}
	s2 := newExcludeStore(p) // reload from disk
	skipAll, skipIDs := s2.MatchWAFRules("persist.example.com", "/")
	if skipAll {
		t.Fatalf("expected rule-scoped, got skipAll=true")
	}
	if _, ok := skipIDs[320]; !ok {
		t.Fatalf("rule 320 lost across reload; skipIDs=%v", skipIDs)
	}
	if _, ok := skipIDs[401]; !ok {
		t.Fatalf("rule 401 lost across reload; skipIDs=%v", skipIDs)
	}
}

// Vhost-controls panel filter: rule-scoped entries must not appear in the
// "WAF disabled for this host" list — they only suppress specific rule IDs,
// the WAF still runs.
func TestFilterWholeWAFEntries_DropsRuleScoped(t *testing.T) {
	entries := []excludeEntry{
		{Type: "host", Value: "noisy.example.com"},                  // whole-WAF — kept
		{Type: "host", Value: "tuned.example.com", RuleIDs: []int{321}}, // rule-scoped — dropped
		{Type: "path", Value: "/admin"},                                // whole-WAF — kept
	}
	got := filterWholeWAFEntries(entries)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (rule-scoped filtered out); got %d (%v)", len(got), got)
	}
	for _, e := range got {
		if len(e.RuleIDs) > 0 {
			t.Errorf("rule-scoped entry leaked into filtered list: %v", e)
		}
	}
}

// Remove targets the exact (type, value, scope, rule-ids) entry; whole-WAF
// remove must not nuke a rule-scoped entry on the same host.
func TestExcludeStore_RemoveDistinguishesRuleScoping(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	_ = s.Add("host", "shared.example.com", nil)                     // whole-WAF
	_ = s.AddWithRuleIDs("host", "shared.example.com", nil, []int{320}) // rule-scoped

	// Removing the whole-WAF entry leaves the rule-scoped one in place.
	if !s.Remove("host", "shared.example.com", nil) {
		t.Fatalf("expected whole-WAF remove to succeed")
	}
	skipAll, skipIDs := s.MatchWAFRules("shared.example.com", "/")
	if skipAll {
		t.Fatalf("after whole-WAF remove, skipAll must be false")
	}
	if _, ok := skipIDs[320]; !ok {
		t.Fatalf("rule-scoped entry was wrongly removed; skipIDs=%v", skipIDs)
	}

	// Now remove the rule-scoped entry by passing the matching rule-ids.
	if !s.RemoveWithRuleIDs("host", "shared.example.com", nil, []int{320}) {
		t.Fatalf("expected rule-scoped remove to succeed")
	}
	skipAll, skipIDs = s.MatchWAFRules("shared.example.com", "/")
	if skipAll || len(skipIDs) != 0 {
		t.Fatalf("expected no excludes left; got skipAll=%v skipIDs=%v", skipAll, skipIDs)
	}
}
