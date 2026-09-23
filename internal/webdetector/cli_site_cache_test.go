// internal/webdetector/cli_site_cache_test.go
package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `set` sends ONLY the flags given (a merge patch), so a retune never resets
// the omitted tier or the cookie settings.
func TestParseSiteCacheSetFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		want  string // the JSON the CLI sends
	}{
		{"micro ttl only", []string{"--micro-ttl", "30s"},
			`{"host":"a.com","micro":{"ttl":"30s"}}`},
		{"enable static", []string{"--static", "static_lean", "--static-ttl=7d"},
			`{"host":"a.com","static":{"enabled":true,"recipe":"static_lean","ttl":"7d"}}`},
		{"static off keeps recipe", []string{"--static", "off"},
			`{"host":"a.com","static":{"enabled":false}}`},
		{"micro=OFF", []string{"--micro=OFF"},
			`{"host":"a.com","micro":{"enabled":false}}`},
		{"no strict", []string{"--no-strict-cookies"},
			`{"host":"a.com","strict_cookies":false}`},
		{"strict", []string{"--strict-cookies"},
			`{"host":"a.com","strict_cookies":true}`},
		{"auth cookies replace", []string{"--auth-cookies", "a, b"},
			`{"host":"a.com","auth_cookies":["a","b"]}`},
		{"auth cookies clear", []string{"--no-auth-cookies"},
			`{"host":"a.com","auth_cookies":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseSiteCacheSetFlags("a.com", tc.flags)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			b, _ := json.Marshal(p)
			if string(b) != tc.want {
				t.Fatalf("sent %s\nwant %s", b, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		flags []string
		err   string
	}{
		{"no flags", nil, "nothing to change"},
		{"missing value", []string{"--micro"}, "missing value"},
		{"value is a flag", []string{"--micro", "--strict-cookies"}, "missing value"},
		{"empty value", []string{"--static-ttl="}, "empty value"},
		{"empty auth list", []string{"--auth-cookies=,"}, "--no-auth-cookies"},
		{"switch with value", []string{"--strict-cookies=1"}, "takes no value"},
		{"unknown", []string{"--bogus"}, "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSiteCacheSetFlags("a.com", tc.flags); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.err)
			}
		})
	}
}

// `off` must leave the vhost uncached even under an admin's armed wildcard: it
// keeps an all-off entry (an opt-out row in the feed). `remove` deletes the
// entry, and the vhost then follows the wildcard. (`off` used to delete, which
// left the host cached — and deleted an opt-out, turning caching back ON.)
func TestSiteCacheCLI_OffKeepsOptOutRemoveDeletes(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(adminCtx()))
	}))
	defer ts.Close()
	on := SiteCacheTier{Enabled: true, Recipe: "static_lean"}
	if _, err := e.siteCache.Set(SiteCacheEntry{Host: "*.example.com", Static: on}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.siteCache.Set(SiteCacheEntry{Host: "a.example.com", Static: on}); err != nil {
		t.Fatal(err)
	}
	feedHas := func(host string) (CachePolicyRow, bool) {
		for _, r := range e.SiteCachePolicyFeed() {
			if r.Host == host {
				return r, true
			}
		}
		return CachePolicyRow{}, false
	}

	for _, verb := range []string{"off", "disable"} {
		if err := runSiteCacheWebTop(ts.URL, []string{verb, "a.example.com"}); err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		row, ok := feedHas("a.example.com")
		if !ok || row.Static != nil || row.Micro != nil {
			t.Fatalf("%s: want an opt-out row for a.example.com, got ok=%v %+v", verb, ok, row)
		}
	}
	// `off` on a host with no entry at all creates the opt-out.
	if err := runSiteCacheWebTop(ts.URL, []string{"off", "b.example.com"}); err != nil {
		t.Fatalf("off new host: %v", err)
	}
	if _, ok := feedHas("b.example.com"); !ok {
		t.Fatal("off on a new host under an armed wildcard did not opt it out")
	}

	if err := runSiteCacheWebTop(ts.URL, []string{"remove", "a.example.com"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := e.SiteCacheGet("a.example.com"); ok {
		t.Fatal("remove kept the entry")
	}
	if key, ok := e.siteCache.StatsKeyFor("a.example.com"); !ok || key != "*.example.com" {
		t.Fatalf("after remove the host must follow the wildcard: %q %v", key, ok)
	}
}
