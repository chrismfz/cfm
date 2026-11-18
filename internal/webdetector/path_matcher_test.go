package webdetector

import (
	"bufio"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// linearFirst is the loop pathMatcher replaced (trackChallengePaths and the
// MALPATH counter in ingest): the first rule, in order, whose non-empty
// pattern occurs in pl.
func linearFirst(subs []string, pl string) int {
	for i, sub := range subs {
		if sub != "" && strings.Contains(pl, sub) {
			return i
		}
	}
	return -1
}

// readListFile reads a list the way MALPATH_FILE / CHALLENGE_PATHS_FILE are
// read (webdetector_register.go): trimmed, # comments and blanks skipped,
// lower-cased.
func readListFile(t testing.TB, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

func realMalpathSubs(t testing.TB) (mal, chal []string) {
	list := readListFile(t, "../../configs/webdetector_malpaths.txt")
	if len(list) < 50 {
		t.Fatalf("malpath list has only %d entries", len(list))
	}
	return ruleSubs(compileMalRules(list, 3)), ruleSubs(compileChalRules(list, 2))
}

func fixturePaths(t testing.TB) []string {
	var out []string
	f, err := os.Open("testdata/malpath_match_paths.txt")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// TestPathMatcherRealMalpathList runs the shipped list over the fixture, and
// over every pattern embedded in a path, and asserts the one-pass matcher
// picks the same first-match index as the linear loop, for both rule lists.
func TestPathMatcherRealMalpathList(t *testing.T) {
	mal, chal := realMalpathSubs(t)
	paths := fixturePaths(t)
	for _, s := range mal {
		paths = append(paths, s, "/x"+s, s+"/y", "/a/b"+s+".php", s[:len(s)/2], s[1:])
	}
	matched := 0
	for _, subs := range [][]string{mal, chal} {
		m := newPathMatcher(subs)
		for _, p := range paths {
			pl := strings.ToLower(p)
			want := linearFirst(subs, pl)
			if got := m.first(pl); got != want {
				t.Errorf("path %q: matcher=%d linear=%d", p, got, want)
			}
			if want >= 0 {
				matched++
			}
		}
	}
	if matched == 0 {
		t.Fatal("no fixture path matched: the test is checking nothing")
	}
	// The default config reads one file for both checks; the engine then
	// shares one matcher (and one scan per line).
	if !newPathMatcher(mal).sameSubs(chal) {
		t.Error("MALPATH and CHALLENGE_PATHS compile the shipped list to different patterns")
	}
}

// TestPathMatcherRandomEquivalence: overlapping patterns over a tiny
// alphabet (prefixes, suffixes, duplicates, one pattern inside another) are
// where an Aho-Corasick output/failure-link bug shows.
func TestPathMatcherRandomEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	gen := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "ab/c."[rng.Intn(5)]
		}
		return string(b)
	}
	for iter := 0; iter < 2000; iter++ {
		subs := make([]string, 1+rng.Intn(12))
		for i := range subs {
			subs[i] = gen(rng.Intn(5)) // includes "" (never matches)
		}
		m := newPathMatcher(subs)
		for k := 0; k < 30; k++ {
			s := gen(rng.Intn(20))
			if got, want := m.first(s), linearFirst(subs, s); got != want {
				t.Fatalf("subs=%q s=%q: matcher=%d linear=%d", subs, s, got, want)
			}
		}
	}
}

func TestPathMatcherEdgeCases(t *testing.T) {
	if newPathMatcher(nil) != nil || newPathMatcher([]string{"", ""}) != nil {
		t.Fatal("a list with no non-empty pattern must compile to nil")
	}
	var nilM *pathMatcher
	if nilM.first("/x") != -1 {
		t.Fatal("nil matcher must match nothing")
	}
	// Every byte value in the patterns: the full-alphabet fallback.
	all := make([]string, 0, 256)
	for b := 0; b < 256; b++ {
		all = append(all, string([]byte{byte(b), byte(b)}))
	}
	m := newPathMatcher(all)
	for b := 0; b < 256; b++ {
		s := string([]byte{'x', byte(b), byte(b), 'y'})
		if got, want := m.first(s), linearFirst(all, s); got != want {
			t.Fatalf("byte %d: matcher=%d linear=%d", b, got, want)
		}
	}
	// Non-ASCII bytes in path and pattern.
	subs := []string{"päth", "/ü"}
	m = newPathMatcher(subs)
	for _, s := range []string{"/ünï/päth", "/pa", "/ü"} {
		if got, want := m.first(s), linearFirst(subs, s); got != want {
			t.Fatalf("%q: matcher=%d linear=%d", s, got, want)
		}
	}
}

// TestEngineSharesMalpathMatcher: one list for both checks -> one matcher;
// different lists -> separate matchers, each answering for its own rules.
func TestEngineSharesMalpathMatcher(t *testing.T) {
	list := []string{"/.env", "5:/wp-config.php", "/.git/"}
	e := NewEngine(Config{
		MalPathList: list, MalPathCount: 3,
		ChallengePathsEnabled: true, ChallengePathsList: list, ChallengePathsCount: 2,
	})
	if e.malMatch == nil || e.malMatch != e.chalMatch {
		t.Fatal("same list must share one matcher")
	}
	e = NewEngine(Config{
		MalPathList: list, MalPathCount: 3,
		ChallengePathsEnabled: true, ChallengePathsList: []string{"/.git/", "/.env"}, ChallengePathsCount: 2,
	})
	if e.malMatch == e.chalMatch {
		t.Fatal("different lists must not share a matcher")
	}
	pm := pathMatchOnce{p: "/A/.GIT/config"}
	if got := pm.first(e.malMatch); got != 2 {
		t.Fatalf("mal index = %d, want 2", got)
	}
	if got := pm.first(e.chalMatch); got != 0 {
		t.Fatalf("chal index = %d, want 0", got)
	}
}

var benchPaths = []string{
	"/wp-content/uploads/2026/11/photo-1024x768.jpg",
	"/wp-admin/admin-ajax.php",
	"/product/blue-shirt/",
	"/wp-includes/js/jquery/jquery.min.js",
	"/index.php",
	"/category/news/page/2/",
	"/wp-json/wp/v2/posts",
	"/static/js/main.4f2a.js",
}

var benchSink int

// BenchmarkMalpathMatch: old = the two linear loops per log line (MALPATH +
// CHALLENGE_PATHS, each lower-casing the path); new = one lower-case, one
// scan of the shared matcher. Typical non-matching paths, the common case.
func BenchmarkMalpathMatch(b *testing.B) {
	mal, chal := realMalpathSubs(b)
	b.Run("old_linear_x2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p := benchPaths[i%len(benchPaths)]
			benchSink += linearFirst(chal, strings.ToLower(p))
			benchSink += linearFirst(mal, strings.ToLower(p))
		}
	})
	m := newPathMatcher(mal)
	b.Run("new_shared_matcher", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pm := pathMatchOnce{p: benchPaths[i%len(benchPaths)]}
			benchSink += pm.first(m)
			benchSink += pm.first(m)
		}
	})
}

// TestPathMatcherLinearFallback: a list whose table would pass the cap keeps
// the linear loop, with the same answers.
func TestPathMatcherLinearFallback(t *testing.T) {
	mal, _ := realMalpathSubs(t)
	old := pathMatcherMaxCells
	pathMatcherMaxCells = 100
	m := newPathMatcher(mal)
	pathMatcherMaxCells = old
	if m == nil || !m.linear || m.delta != nil {
		t.Fatal("over the cap: want the linear fallback and no table")
	}
	for _, p := range fixturePaths(t) {
		pl := strings.ToLower(p)
		if got, want := m.first(pl), linearFirst(mal, pl); got != want {
			t.Errorf("path %q: fallback=%d linear=%d", p, got, want)
		}
	}
	if full := newPathMatcher(mal); full.linear {
		t.Fatal("the shipped list must fit the default cap")
	}
}
