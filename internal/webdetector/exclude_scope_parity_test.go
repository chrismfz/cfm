package webdetector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// waf_exclude_scope.txt rows: the entry's scope_hosts ("-" = none), the
// request host, and whether an exclude with that scope applies there.
type wafExcludeScopeCase struct {
	scope []string
	host  string
	want  bool
}

func readWAFExcludeScopeFixture(t *testing.T) []wafExcludeScopeCase {
	t.Helper()
	f, err := os.Open("../../scripts/tests/fixtures/waf_exclude_scope.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []wafExcludeScopeCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) != 3 || (fs[2] != "0" && fs[2] != "1") {
			t.Fatalf("bad fixture line %q", line)
		}
		var scope []string
		if fs[0] != "-" {
			scope = strings.Split(fs[0], ",")
		}
		out = append(out, wafExcludeScopeCase{scope: scope, host: fs[1], want: fs[2] == "1"})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < 40 {
		t.Fatalf("fixture read %d cases", len(out))
	}
	return out
}

func scopeSetOf(hosts []string) map[string]struct{} {
	if len(hosts) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		m[h] = struct{}{}
	}
	return m
}

// TestWAFExcludeScope_EdgeParity runs the fixture the in-path WAF runs too
// (scripts/tests/cfm_waf_excl_scope_test.lua): an exclude's scope_hosts take
// exactly the hosts the edge applies it on. Before the edge read scope_hosts,
// a path exclude narrowed to one vhost switched the WAF off on that path of
// every vhost in-path while this matcher said "that vhost only".
func TestWAFExcludeScope_EdgeParity(t *testing.T) {
	for _, c := range readWAFExcludeScopeFixture(t) {
		host := strings.ToLower(c.host)
		e := compiledExcludeEntry{Scope: compileScopeMatcher(normalizeScopeHosts(c.scope)), Scoped: len(c.scope) > 0}
		if got := e.scopeTakes(host); got != c.want {
			t.Errorf("scope %q host %q: scopeTakes = %v, want %v", c.scope, c.host, got, c.want)
		}

		// The whole enforcement path, as the edge runs it: a whole-WAF path
		// exclude and a rule-scoped one, both with this scope.
		s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
		if !s.Add("path", "/import/", scopeSetOf(c.scope)) {
			t.Fatalf("add path exclude scope %q", c.scope)
		}
		if skipAll, _ := s.MatchWAFRules(c.host, "/import/x"); skipAll != c.want {
			t.Errorf("scope %q host %q: whole-WAF path exclude skipAll = %v, want %v", c.scope, c.host, skipAll, c.want)
		}
		r := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
		if !r.AddWithRuleIDs("path", "/import/", scopeSetOf(c.scope), []int{402}) {
			t.Fatalf("add rule-scoped path exclude scope %q", c.scope)
		}
		skipAll, ids := r.MatchWAFRules(c.host, "/import/x")
		_, has := ids[402]
		if skipAll || has != c.want {
			t.Errorf("scope %q host %q: rule-scoped path exclude skipAll=%v ids=%v, want 402 skipped=%v", c.scope, c.host, skipAll, ids, c.want)
		}
	}
}

// TestCompiledScopeMatcher_UnusableGlobTakesNoHost pins the fail-closed fix:
// a scope whose every host is a glob compileGlob refuses used to compile to
// an empty matcher, which Match read as "no scope" — every host.
func TestCompiledScopeMatcher_UnusableGlobTakesNoHost(t *testing.T) {
	for _, scope := range [][]string{{"shop[a.gr"}, {`shop*\`}, {"shop[a.gr", `x*\`}} {
		m := compileScopeMatcher(normalizeScopeHosts(scope))
		for _, h := range []string{"shop.gr", "shopa.gr", "other.example"} {
			if m.Match(h) {
				t.Errorf("scope %q (no usable host) took %q", scope, h)
			}
		}
	}
	if !compileScopeMatcher(nil).Match("any.example") {
		t.Fatal("no scope must take every host")
	}
}
