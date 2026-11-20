package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// malpathCounts sums the per-IP CHALLENGE_PATHS and MALPATH counters over
// every host's buckets.
func malpathCounts(e *Engine, ip string) (chal, mal int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, hs := range e.hosts {
		for _, b := range hs.buckets {
			chal += b.ipsChalPath[ip]
			mal += b.ipsMalPath[ip]
		}
	}
	return chal, mal
}

func newPathExcludeEngine(t *testing.T) *Engine {
	t.Helper()
	list := []string{"/.env", "/.tmb/"}
	return NewEngine(Config{
		Every: time.Second, Window: 2 * time.Minute,
		MalPathList: list, MalPathCount: 20,
		ChallengePathsEnabled: true, ChallengePathsList: list, ChallengePathsCount: 1,
		ChallengeExcludeStorePath: filepath.Join(t.TempDir(), "challenge_excludes.json"),
	})
}

// A host-scoped path exclude stops BOTH malpath counters for that host and
// path only: the same path on another host, and another path on the same
// host, still count.
func TestChallengePathExcludeStopsBothCounters(t *testing.T) {
	e := newPathExcludeEngine(t)
	if !e.ChallengeExcludeAdd("path", "/images/.tmb/", scopeSet("site.gr")) {
		t.Fatal("add")
	}
	ts := float64(time.Now().Unix())
	hit := func(ip, host, uri string) {
		e.ingest(LogRec{TS: ts, IP: ip, Host: host, Method: "GET", URI: uri, Status: 200, UA: "ua"}, "raw")
	}

	hit("192.0.2.1", "site.gr", "/images/.tmb/l1_abc.png?_t=1")
	hit("192.0.2.1", "SITE.GR", "/Images/.TMB/l1_def.png")
	if c, m := malpathCounts(e, "192.0.2.1"); c != 0 || m != 0 {
		t.Fatalf("excluded path counted: chal=%d mal=%d", c, m)
	}

	hit("192.0.2.2", "other.gr", "/images/.tmb/l1_abc.png")
	if c, m := malpathCounts(e, "192.0.2.2"); c != 1 || m != 1 {
		t.Fatalf("same path on another host: chal=%d mal=%d, want 1/1", c, m)
	}
	hit("192.0.2.3", "site.gr", "/.env")
	if c, m := malpathCounts(e, "192.0.2.3"); c != 1 || m != 1 {
		t.Fatalf("other path on the excluded host: chal=%d mal=%d, want 1/1", c, m)
	}
	// A traversal / encoded path under the prefix is another file: it counts.
	for i, uri := range []string{
		"/images/.tmb/../../.env",
		"/images/.tmb/%2e%2e/%2e%2e/.env",
		"/images/.tmb/..%2f..%2f.env",
		"/images/.tmb//../.env",
		"/images/.tmb/.\\..\\.env",
	} {
		ip := "192.0.2." + string(rune('a'+i))
		hit(ip, "site.gr", uri)
		if c, m := malpathCounts(e, ip); c != 1 || m != 1 {
			t.Fatalf("%s skipped: chal=%d mal=%d, want 1/1", uri, c, m)
		}
	}
	// The www. alias of a literal scope host is covered.
	hit("192.0.2.9", "www.site.gr", "/images/.tmb/l1_abc.png")
	if c, m := malpathCounts(e, "192.0.2.9"); c != 0 || m != 0 {
		t.Fatalf("www alias counted: chal=%d mal=%d", c, m)
	}
	// Segment boundary: /images/.tmb/ is a pure prefix; /images2/.tmb/ is not under it.
	hit("192.0.2.4", "site.gr", "/images2/.tmb/x.png")
	if c, m := malpathCounts(e, "192.0.2.4"); c != 1 || m != 1 {
		t.Fatalf("a path outside the exclude: chal=%d mal=%d, want 1/1", c, m)
	}
}

// An unscoped path entry (an older version wrote one) stays inert: it would
// exempt the path on every site. Host entries keep their meaning, and a path
// entry never matches as a host.
func TestChallengePathExcludeUnscopedIsInert(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "x.json"))
	if !s.Add("path", "/.tmb/", nil) {
		t.Fatal("add")
	}
	if _, ok := s.MatchChallengePath("site.gr", "/.tmb/x.png"); ok {
		t.Fatal("an unscoped path entry matched")
	}
	if !s.Add("host", "site.gr", nil) || !s.MatchChallenge("site.gr") || s.MatchChallenge("myshop.gr") {
		t.Fatal("host entry semantics changed")
	}
	if !s.Add("path", "/site.gr", scopeSet("site.gr")) || s.MatchChallenge("other.gr") {
		t.Fatal("a path entry matched as a host")
	}
	if v, ok := s.MatchChallengePath("site.gr", "/site.gr/x"); !ok || v != "/site.gr" {
		t.Fatalf("scoped path entry: %q %v", v, ok)
	}
}

func adminReq(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	return req.WithContext(ctx)
}

func scopedReq(method, target string, hosts ...string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleScoped)
	ctx = context.WithValue(ctx, CtxScopeKey{}, scopeSet(hosts...))
	return req.WithContext(ctx)
}

func TestChallengePathExcludeAPIScope(t *testing.T) {
	e := newPathExcludeEngine(t)
	call := func(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h(rr, r)
		return rr
	}
	add, rm := e.handleChallengeExcludeAdd, e.handleChallengeExcludeRemove

	// Admin: scope_hosts is required, a match-all scope and the site root are refused.
	for _, q := range []string{
		"type=path&value=/.tmb/",
		"type=path&value=/.tmb/&scope_hosts=*",
		"type=path&value=/.tmb/&scope_hosts=*.*",
		"type=path&value=/.tmb/&scope_hosts=[a-z]*.*",
		"type=path&value=/&scope_hosts=a.gr",
		"type=path&value=/*&scope_hosts=a.gr",
		"type=path&value=/*/*&scope_hosts=a.gr",
		"type=path&value=/*.php&scope_hosts=a.gr",
		"type=path&value=/[!/]*&scope_hosts=a.gr",
		"type=path&value=/[a-z]*&scope_hosts=a.gr",
		"type=path&value=/*/.tmb/*&scope_hosts=a.gr",
		"type=path&value=/.tmb/&scope_hosts=*-*",
		"type=path&value=/.tmb/&scope_hosts=*a*",
		"type=path&value=/.tmb/&scope_hosts=*.gr",
	} {
		if rr := call(add, adminReq("POST", "/api/v1/challenge/exclude/add?"+q)); rr.Code != http.StatusBadRequest {
			t.Fatalf("admin %s: %d %s", q, rr.Code, rr.Body.String())
		}
	}
	if rr := call(add, adminReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/.tmb/&scope_hosts=a.gr")); rr.Code != http.StatusOK {
		t.Fatalf("admin scoped add: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(add, adminReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/images/*/.tmb/*&scope_hosts=a.gr")); rr.Code != http.StatusOK {
		t.Fatalf("admin glob add: %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("a.gr", "/images/x/.tmb/l1.png"); !ok {
		t.Fatal("glob entry did not match")
	}

	// Scoped: defaults to its vhost set; may narrow; may not reach another tenant.
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/dup-installer/", "t1.gr", "t2.gr")); rr.Code != http.StatusOK {
		t.Fatalf("scoped add: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/x/&scope_hosts=t2.gr", "t1.gr", "t2.gr")); rr.Code != http.StatusOK {
		t.Fatalf("scoped narrowed add: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/x/&scope_hosts=a.gr", "t1.gr")); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped add on another tenant: %d", rr.Code)
	}
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/x/")); rr.Code != http.StatusForbidden {
		t.Fatalf("vhost-less scoped add: %d", rr.Code)
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("t1.gr", "/dup-installer/main.php"); !ok {
		t.Fatal("scoped entry does not apply on its own vhost")
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("a.gr", "/dup-installer/main.php"); ok {
		t.Fatal("scoped entry applies outside its vhosts")
	}

	// List: t1.gr sees its own entry with scope cut to t1.gr, and neither a.gr's
	// nor the t2.gr-only one.
	rr := call(e.handleChallengeExcludeList, scopedReq("GET", "/api/v1/challenge/exclude/list", "t1.gr"))
	var rows []excludeEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != "/dup-installer/" || len(rows[0].ScopeHosts) != 1 || rows[0].ScopeHosts[0] != "t1.gr" {
		t.Fatalf("scoped list: %+v", rows)
	}

	// Remove: another tenant cannot; the owner can, echoing the cut scope (as
	// the UI does) or without one.
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/.tmb/", "b.gr")); rr.Code == http.StatusOK {
		t.Fatal("another tenant removed an entry")
	}
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/.tmb/&scope_hosts=a.gr", "b.gr")); rr.Code != http.StatusForbidden {
		t.Fatalf("another tenant naming a.gr: %d", rr.Code)
	}
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/dup-installer/&scope_hosts=t1.gr", "t1.gr", "t2.gr")); rr.Code != http.StatusOK {
		t.Fatalf("owner remove with cut scope: %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/x/", "t2.gr")); rr.Code != http.StatusOK {
		t.Fatalf("owner remove without scope: %d %s", rr.Code, rr.Body.String())
	}
	// A tenant holding only part of an entry's hosts cannot remove it.
	if !e.ChallengeExcludeAdd("path", "/shared/", scopeSet("t1.gr", "a.gr")) {
		t.Fatal("add")
	}
	// A partial owner takes only its own host out of a shared entry.
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/shared/", "t1.gr")); rr.Code != http.StatusOK {
		t.Fatalf("a partial owner removing its host: %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("t1.gr", "/shared/x"); ok {
		t.Fatal("the partial owner's host is still covered")
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("a.gr", "/shared/x"); !ok {
		t.Fatal("another tenant's host lost its exclude")
	}
	// A domain move: A wrote [m1.gr, m2.gr]; m2.gr moves to B, who removes it
	// for m2.gr only, and A keeps m1.gr.
	if !e.ChallengeExcludeAdd("path", "/moved/", scopeSet("m1.gr", "m2.gr")) {
		t.Fatal("add")
	}
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/moved/", "m2.gr", "bb.gr")); rr.Code != http.StatusOK {
		t.Fatalf("new owner remove: %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("m2.gr", "/moved/x"); ok {
		t.Fatal("moved domain still covered")
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("m1.gr", "/moved/x"); !ok {
		t.Fatal("the writer's remaining host lost its exclude")
	}
	// A narrowed remove takes only the named host out.
	if !e.ChallengeExcludeAdd("path", "/two/", scopeSet("t1.gr", "t2.gr")) {
		t.Fatal("add")
	}
	if rr := call(rm, scopedReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/two/&scope_hosts=t1.gr", "t1.gr", "t2.gr")); rr.Code != http.StatusOK {
		t.Fatalf("narrowed remove: %d", rr.Code)
	}
	if _, ok := e.challengeExcludes.MatchChallengePath("t2.gr", "/two/x"); !ok {
		t.Fatal("narrowed remove dropped the other host")
	}
	// A tenant holding a wildcard vhost never gets it as a scope.
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/x/", "*.t5.gr")); rr.Code != http.StatusForbidden {
		t.Fatalf("wildcard-only token: %d", rr.Code)
	}
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/x/&scope_hosts=*.t5.gr", "*.t5.gr")); rr.Code != http.StatusForbidden {
		t.Fatalf("wildcard scope_hosts from a tenant: %d", rr.Code)
	}
	// A token whose own set holds a match-all glob cannot use it as the scope.
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/x/", "*")); rr.Code != http.StatusForbidden {
		t.Fatalf("match-all token scope: %d", rr.Code)
	}
	// A wildcard with a literal label is a real scope.
	if rr := call(add, adminReq("POST", "/api/v1/challenge/exclude/add?type=path&value=/w/&scope_hosts=*.t9.gr")); rr.Code != http.StatusOK {
		t.Fatalf("admin *.t9.gr add: %d %s", rr.Code, rr.Body.String())
	}

	// Admin removes a legacy unscoped entry without scope_hosts.
	if !e.ChallengeExcludeAdd("path", "/legacy/", nil) {
		t.Fatal("add legacy")
	}
	if rr := call(rm, adminReq("POST", "/api/v1/challenge/exclude/remove?type=path&value=/legacy/")); rr.Code != http.StatusOK {
		t.Fatalf("admin remove legacy: %d %s", rr.Code, rr.Body.String())
	}
	// Host excludes for scoped callers are unchanged.
	if rr := call(add, scopedReq("POST", "/api/v1/challenge/exclude/add?type=host&value=a.gr", "t1.gr")); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped host exclude outside scope: %d", rr.Code)
	}
}
