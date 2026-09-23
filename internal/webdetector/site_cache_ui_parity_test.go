package webdetector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// siteCacheUIParityCase is one line of scripts/tests/fixtures/site_cache_ui_parity.txt,
// the vectors the cfm-admin Site Cache page model (site-cache-model.js) is
// tested against too: the daemon side of the page's client-side validation.
type siteCacheUIParityCase struct {
	line           int
	kind, in, want string
}

func loadSiteCacheUIParity(t *testing.T) []siteCacheUIParityCase {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "scripts", "tests", "fixtures", "site_cache_ui_parity.txt"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var out []siteCacheUIParityCase
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("fixture line %d: want 3 TAB-separated fields, got %d: %q", n, len(parts), line)
		}
		in := parts[1]
		if in == "<empty>" {
			in = ""
		}
		out = append(out, siteCacheUIParityCase{line: n, kind: parts[0], in: in, want: parts[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return out
}

// TestSiteCacheUIParityFixture runs the ttl / host / cookie vectors through
// the daemon: parseCacheTTL for a TTL, and the real set path (Apply) for a
// host or an auth-cookie name, so the page's model is pinned to what the API
// accepts, not to a copy of it.
func TestSiteCacheUIParityFixture(t *testing.T) {
	cases := loadSiteCacheUIParity(t)
	counts := map[string]int{}
	on := true
	recipe := "static_lean"
	for _, c := range cases {
		counts[c.kind]++
		switch c.kind {
		case "ttl":
			d, err := parseCacheTTL(c.in)
			got := "invalid"
			if err == nil {
				got = strconv.FormatInt(int64(d.Seconds()), 10)
			}
			if got != c.want {
				t.Errorf("line %d: parseCacheTTL(%q) = %s, want %s", c.line, c.in, got, c.want)
			}
		case "host":
			s := newTestSiteCacheStore(t)
			_, err := s.Apply(SiteCachePatch{Host: c.in, Static: &SiteCacheTierPatch{Enabled: &on, Recipe: &recipe}}, false)
			if got := okOrBad(err); got != c.want {
				t.Errorf("line %d: set host %q: %s (err %v), want %s", c.line, c.in, got, err, c.want)
			}
		case "cookie", "cookieq":
			in := c.in
			if c.kind == "cookieq" {
				u, err := strconv.Unquote(`"` + in + `"`)
				if err != nil {
					t.Fatalf("line %d: cookieq %q: %v", c.line, in, err)
				}
				in = u
			}
			s := newTestSiteCacheStore(t)
			names := []string{in}
			_, err := s.Apply(SiteCachePatch{Host: "shop.example.com", Static: &SiteCacheTierPatch{Enabled: &on, Recipe: &recipe}, AuthCookies: &names}, false)
			if got := okOrBad(err); got != c.want {
				t.Errorf("line %d: set auth cookie %q: %s (err %v), want %s", c.line, in, got, err, c.want)
			}
		case "bucket":
			// Edge-side: scripts/tests/cfm_cache_ui_parity_test.lua.
		default:
			t.Errorf("line %d: unknown kind %q", c.line, c.kind)
		}
	}
	for _, k := range []string{"ttl", "host", "cookie", "cookieq", "bucket"} {
		if counts[k] == 0 {
			t.Errorf("fixture has no %q cases", k)
		}
	}
}

func okOrBad(err error) string {
	if err == nil {
		return "ok"
	}
	return "bad"
}

func newTestSiteCacheStore(t *testing.T) *siteCacheStore {
	t.Helper()
	return newSiteCacheStore(filepath.Join(t.TempDir(), "site_cache.json"))
}
