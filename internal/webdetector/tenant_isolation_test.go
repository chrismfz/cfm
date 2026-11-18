package webdetector

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two tenants on one node, every kind of state the scoped-allowed endpoints
// read seeded for both, and tenant A's token sent to each of them. Nothing of
// tenant B may come back: not its host, not an IP only B saw, not what a
// shared IP did on B, not an operator note written on a rule that names B.
// The black-box run that preceded this test used an empty engine and could
// not see a cross-tenant leak; this one can.
const (
	isoHostA   = "a-tenant.example"
	isoHostB   = "b-tenant.example"
	isoIPB     = "198.51.100.66" // seen only on B
	isoIPBoth  = "203.0.113.7"   // seen on both
	isoPathB   = "/b-only-secret-path"
	isoNoteB   = "b-operator-note-sentinel"
	isoReasonB = "b-history-reason-sentinel"
)

var isoSentinels = []string{isoHostB, isoIPB, isoPathB, isoNoteB, isoReasonB}

func isoDo(t *testing.T, mux *http.ServeMux, ctx context.Context, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rd).WithContext(ctx)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func isoSeed(t *testing.T, mux *http.ServeMux, method, target string, body any) {
	t.Helper()
	if rr := isoDo(t, mux, adminCtx(), method, target, body); rr.Code/100 != 2 {
		t.Fatalf("seed %s %s: %d %s", method, target, rr.Code, rr.Body.String())
	}
}

func newTenantIsolationEngine(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	t.Cleanup(SetDefaultDirsForTest(t.TempDir()))
	dir := t.TempDir()
	e := NewEngine(Config{TrafficRulesStorePath: filepath.Join(dir, "rules.json")})
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hs.Close)
	e.history = hs
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

	// Live traffic: an IP per tenant, and one IP on both (its B path must
	// not show on A).
	now := float64(time.Now().Unix())
	for i := 0; i < 40; i++ {
		ts := now + float64(i)*0.01
		e.ingest(LogRec{TS: ts, IP: "192.0.2.10", Host: isoHostA, Method: "GET", URI: "/a-page", Status: 200, UA: "Mozilla/5.0 a"}, "")
		e.ingest(LogRec{TS: ts, IP: isoIPB, Host: isoHostB, Method: "GET", URI: isoPathB, Status: 404, UA: "Mozilla/5.0 b"}, "")
		e.ingest(LogRec{TS: ts, IP: isoIPBoth, Host: isoHostA, Method: "GET", URI: "/a-page", Status: 200, UA: "shared"}, "")
		e.ingest(LogRec{TS: ts, IP: isoIPBoth, Host: isoHostB, Method: "POST", URI: isoPathB, Status: 403, UA: "shared", Ref: "https://" + isoHostB + "/"}, "")
	}

	// Durable history for both, including the shared IP on B and payload
	// fields scoped callers never get.
	ts := time.Now().Unix()
	for _, ev := range []HistoryEvent{
		{TsUnix: ts, Type: "waf_trigger", Host: isoHostA, IP: isoIPBoth, Reason: "WAF_SQLI", Payload: map[string]interface{}{"rule_id": 301}},
		{TsUnix: ts, Type: "waf_trigger", Host: isoHostB, IP: isoIPBoth, Reason: isoReasonB, Payload: map[string]interface{}{"rule_id": 301, "path": isoPathB}},
		{TsUnix: ts, Type: "challenge_solved", Host: isoHostA, IP: isoIPBoth, Payload: map[string]interface{}{"src": "vhost:" + isoHostB, "sig": "ptr:1", "v2_via": isoHostB}},
		{TsUnix: ts, Type: "challenge_issued", Host: isoHostB, IP: isoIPB, Reason: isoReasonB},
	} {
		if !hs.AppendChecked(ev) {
			t.Fatalf("history append %+v", ev)
		}
	}

	// Operator and tenant state for both.
	for _, h := range []string{isoHostA, isoHostB} {
		isoSeed(t, mux, http.MethodPost, "/api/v1/waf/exclude/add?type=host&value="+h, nil)
		isoSeed(t, mux, http.MethodPost, "/api/v1/challenge/exclude/add?type=host&value="+h, nil)
		isoSeed(t, mux, http.MethodPost, "/api/v1/challenge/vhost/add?host="+h+"&ttl=1h&reason=manual", nil)
		isoSeed(t, mux, http.MethodPost, "/api/v1/clam/override/add?type=host&value="+h, nil)
		isoSeed(t, mux, http.MethodPost, "/api/v1/clam/sigignore/add?host="+h+"&pattern=Doc.Foo-*", nil)
		isoSeed(t, mux, http.MethodPost, "/api/v1/http3/enable?host="+h, nil)
		isoSeed(t, mux, http.MethodPost, "/api/v1/site-cache/set", SiteCacheEntry{Host: h, Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe", TTL: "1s"}})
	}
	// A path exclude scoped to B, and a node-wide one.
	isoSeed(t, mux, http.MethodPost, "/api/v1/waf/exclude/add?type=path&value="+isoPathB+"&scope_hosts="+isoHostB+"&rule_ids=402", nil)
	// Traffic rules: one per tenant, one shared across both carrying an
	// operator note and B's own address, one node-wide.
	for _, r := range []TrafficRule{
		{Enabled: true, Priority: 10, Scope: TrafficRuleScope{Vhosts: []string{isoHostA}}, Match: TrafficRuleMatch{UAAny: []string{"*a-bot*"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: true, Priority: 20, Scope: TrafficRuleScope{Vhosts: []string{isoHostB}}, Note: isoNoteB, Match: TrafficRuleMatch{PathAny: []string{isoPathB}}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: true, Priority: 30, Scope: TrafficRuleScope{Vhosts: []string{isoHostA, isoHostB}}, Note: isoNoteB, Match: TrafficRuleMatch{UAAny: []string{"*shared-bot*"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: true, Priority: 40, Scope: TrafficRuleScope{Vhosts: []string{"*"}}, Note: isoNoteB, Match: TrafficRuleMatch{IPAny: []string{isoIPB + "/32"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
	} {
		isoSeed(t, mux, http.MethodPost, "/api/v1/webdet/rules/add", r)
	}
	// Challenge Access-Control: B's own entry and a shared one.
	for _, ent := range []ChallengeAccessEntry{
		{Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{isoHostB}}, Note: isoNoteB, Match: challengeAccessMatch{TrafficRuleMatch: TrafficRuleMatch{IPAny: []string{isoIPB + "/32"}}}},
		{Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{isoHostA, isoHostB}}, Note: isoNoteB, Match: challengeAccessMatch{TrafficRuleMatch: TrafficRuleMatch{UAAny: []string{"*monitor*"}}}},
	} {
		isoSeed(t, mux, http.MethodPost, "/api/v1/challenge/access/add", ent)
	}
	return e, mux
}

func TestScopedTenantSeesNothingOfAnotherTenant(t *testing.T) {
	_, mux := newTenantIsolationEngine(t)

	// The seed must be visible to the operator, or a clean scoped answer
	// proves nothing.
	for _, target := range []string{
		"/api/v1/webdet/top-short",
		"/api/v1/webdet/drilldown?host=" + isoHostB,
		"/api/v1/webdet/history/events?host=" + isoHostB,
		"/api/v1/webdet/rules",
		"/api/v1/waf/exclude/list",
		"/api/v1/challenge/access",
	} {
		rr := isoDo(t, mux, adminCtx(), http.MethodGet, target, nil)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), isoHostB) && !strings.Contains(rr.Body.String(), isoIPB) {
			t.Fatalf("seed not visible to admin at %s: %d %.300s", target, rr.Code, rr.Body.String())
		}
	}

	a := scopedCtx(isoHostA)
	hostA := "host=" + isoHostA
	targets := []string{
		"/api/v1/webdet/top",
		"/api/v1/webdet/top-short",
		"/api/v1/webdet/top-short?vhosts=" + isoHostA,
		"/api/v1/webdet/suspicious",
		"/api/v1/webdet/long-top",
		"/api/v1/webdet/drilldown?" + hostA,
		"/api/v1/webdet/vhosts",
		"/api/v1/webdet/vhosts?vhost=" + isoHostA,
		"/api/v1/webdet/rules",
		"/api/v1/webdet/rules/export",
		"/api/v1/webdet/rules/export?vhost=" + isoHostA,
		"/api/v1/webdet/history/events?" + hostA,
		"/api/v1/webdet/history/events?" + hostA + "&ip=" + isoIPBoth,
		"/api/v1/webdet/history/events?" + hostA + "&enrich=1",
		"/api/v1/webdet/history/summary?" + hostA,
		"/api/v1/webdet/history/summary?" + hostA + "&ip=" + isoIPBoth,
		"/api/v1/webdet/history/challenge-outcomes?" + hostA,
		"/api/v1/webdet/history/waf-by-rule?" + hostA,
		"/api/v1/webdet/history/vhost-overview?" + hostA,
		"/api/v1/challenge/access",
		"/api/v1/challenge/events?" + hostA,
		"/api/v1/challenge/exclude/list",
		"/api/v1/challenge/vhost/status?" + hostA,
		"/api/v1/waf/exclude/list",
		"/api/v1/waf/engine/summary",
		"/api/v1/waf/rules",
		"/api/v1/clam/override/list",
		"/api/v1/clam/mode/list",
		"/api/v1/clam/sigignore/list",
		"/api/v1/http3/list",
		"/api/v1/site-cache/list",
		"/api/v1/site-cache/stats",
		"/api/v1/site-cache/stats?" + hostA,
	}
	for _, target := range targets {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			rr := isoDo(t, mux, a, method, target, nil)
			body := rr.Body.String()
			for _, s := range isoSentinels {
				if strings.Contains(body, s) {
					t.Errorf("%s %s (%d) leaks %q: %.400s", method, target, rr.Code, s, body)
				}
			}
			if method == http.MethodGet && rr.Code != http.StatusOK {
				t.Errorf("%s %s: status %d, want 200 (%.200s)", method, target, rr.Code, body)
			}
		}
	}

	// A's own state does come back, so the clean answers above are not empty
	// ones.
	for _, target := range []string{
		"/api/v1/webdet/top-short", "/api/v1/webdet/drilldown?" + hostA, "/api/v1/webdet/history/events?" + hostA,
		"/api/v1/webdet/rules", "/api/v1/webdet/vhosts", "/api/v1/challenge/access", "/api/v1/waf/exclude/list",
		"/api/v1/challenge/exclude/list", "/api/v1/clam/override/list", "/api/v1/clam/sigignore/list",
		"/api/v1/http3/list", "/api/v1/site-cache/list", "/api/v1/challenge/vhost/status?" + hostA,
	} {
		if rr := isoDo(t, mux, a, http.MethodGet, target, nil); !strings.Contains(rr.Body.String(), isoHostA) {
			t.Errorf("GET %s: tenant A's own state missing (%d %.200s)", target, rr.Code, rr.Body.String())
		}
	}

	// Naming B, in any spelling, is refused and the refusal names nothing.
	for _, target := range []string{
		"/api/v1/webdet/drilldown?host=" + isoHostB,
		"/api/v1/webdet/drilldown?host=" + isoHostA + "&host=" + isoHostB,
		"/api/v1/webdet/drilldown?host=" + strings.ToUpper(isoHostB),
		"/api/v1/webdet/drilldown?host=" + isoHostB + ".",
		"/api/v1/webdet/top-short?vhosts=" + isoHostA + "," + isoHostB,
		"/api/v1/webdet/vhosts?vhost=" + isoHostB,
		"/api/v1/webdet/history/events?host=" + isoHostB,
		"/api/v1/webdet/history/events",
		"/api/v1/webdet/history/summary?host=" + isoHostB,
		"/api/v1/webdet/history/challenge-outcomes?host=" + isoHostB,
		"/api/v1/webdet/history/waf-by-rule?host=" + isoHostB,
		"/api/v1/webdet/history/vhost-overview?host=" + isoHostB,
		"/api/v1/challenge/events?host=" + isoHostB,
		"/api/v1/challenge/vhost/status?host=" + isoHostB,
		"/api/v1/site-cache/stats?host=" + isoHostB,
	} {
		rr := isoDo(t, mux, a, http.MethodGet, target, nil)
		if rr.Code/100 == 2 {
			t.Errorf("GET %s: status %d, want a refusal (%.200s)", target, rr.Code, rr.Body.String())
		}
		for _, s := range isoSentinels {
			if strings.Contains(rr.Body.String(), s) {
				t.Errorf("GET %s refusal names %q: %.200s", target, s, rr.Body.String())
			}
		}
	}
}

func TestClampHistoryQueryLimit(t *testing.T) {
	for in, want := range map[int]int{-1: 100, 0: 100, 1: 1, 500: 500, maxHistoryQueryLimit: maxHistoryQueryLimit, 100000000: maxHistoryQueryLimit} {
		if got := clampHistoryQueryLimit(in); got != want {
			t.Errorf("clampHistoryQueryLimit(%d) = %d, want %d", in, got, want)
		}
	}
}
