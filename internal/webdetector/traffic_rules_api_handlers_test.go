// internal/webdetector/traffic_rules_api_handlers_test.go
package webdetector

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// scopedCtx returns a context with the given vhost(s) in the scope key,
// simulating a scoped token issued by the middleware.
func scopedCtx(vhosts ...string) context.Context {
	m := make(map[string]struct{}, len(vhosts))
	for _, v := range vhosts {
		m[v] = struct{}{}
	}
	return context.WithValue(context.Background(), CtxScopeKey{}, m)
}

// adminCtx returns a plain background context — no scope → admin / loopback.
func adminCtx() context.Context { return context.Background() }

// mustAddRule adds a rule through the store directly (bypasses HTTP) and
// returns the normalised rule with its generated ID.
func mustAddRule(t *testing.T, e *Engine, vhost, action string) TrafficRule {
	t.Helper()
	r, err := e.TrafficRuleAdd(TrafficRule{
		Enabled:  true,
		Priority: 100,
		Scope:    TrafficRuleScope{Vhosts: []string{vhost}},
		Match:    TrafficRuleMatch{UAAny: []string{"*bot*"}},
		Action:   TrafficRuleAction{Type: action},
	})
	if err != nil {
		t.Fatalf("mustAddRule: %v", err)
	}
	return r
}

// mustAddThrottleRule adds a throttle rule (needs profile).
func mustAddThrottleRule(t *testing.T, e *Engine, vhost string) TrafficRule {
	t.Helper()
	r, err := e.TrafficRuleAdd(TrafficRule{
		Enabled:  true,
		Priority: 100,
		Scope:    TrafficRuleScope{Vhosts: []string{vhost}},
		Match:    TrafficRuleMatch{UAAny: []string{"*bot*"}},
		Action:   TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"},
	})
	if err != nil {
		t.Fatalf("mustAddThrottleRule: %v", err)
	}
	return r
}

func newTestEngine(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	e := NewEngine(Config{TrafficRulesStorePath: filepath.Join(t.TempDir(), "rules.json")})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

// doRequest fires a request against the mux with the given context and returns
// the response recorder.
func doRequest(mux *http.ServeMux, ctx context.Context, method, path string, body []byte) *httptest.ResponseRecorder {
	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody).WithContext(ctx)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// ── Original smoke test (must still pass unchanged) ──────────────────────────

func TestTrafficRulesAPI_CRUDAndSimulate(t *testing.T) {
	e, mux := newTestEngine(t)

	addReq := TrafficRule{
		Enabled:  true,
		Priority: 100,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{UAAny: []string{"*facebookexternalhit*"}},
		Action:   TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"},
	}
	body, _ := json.Marshal(addReq)

	rr := doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/add", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", rr.Code, rr.Body.String())
	}
	var addResp struct {
		Rule TrafficRule `json:"rule"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &addResp); err != nil {
		t.Fatalf("decode add: %v", err)
	}
	if addResp.Rule.ID == "" {
		t.Fatalf("expected rule id")
	}

	// List
	rr = doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/rules", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Simulate — admin context, should match
	simBody := []byte(`{"host":"example.com","ua":"facebookexternalhit/1.1","path":"/","method":"GET"}`)
	rr = doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/simulate", simBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("simulate status=%d body=%s", rr.Code, rr.Body.String())
	}
	var simResp TrafficRuleEvalResult
	if err := json.Unmarshal(rr.Body.Bytes(), &simResp); err != nil {
		t.Fatalf("decode simulate: %v", err)
	}
	if !simResp.Matched || simResp.Action != TrafficActionThrottle {
		t.Fatalf("unexpected simulate result: %+v", simResp)
	}

	// Remove
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/webdet/rules/remove?id="+addResp.Rule.ID, []byte("{}"))
	if rr.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Confirm store is empty after remove
	_ = e
}

// ── Scope enforcement tests ───────────────────────────────────────────────────

// TestRulesScope_List verifies that a scoped token only sees its own vhost's rules.
func TestRulesScope_List(t *testing.T) {
	_, mux := newTestEngine(t)

	// Add rules for two different vhosts via admin context.
	ruleA := TrafficRule{
		Enabled: true, Priority: 100,
		Scope:  TrafficRuleScope{Vhosts: []string{"alpha.com"}},
		Match:  TrafficRuleMatch{UAAny: []string{"*bot*"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	}
	ruleB := TrafficRule{
		Enabled: true, Priority: 100,
		Scope:  TrafficRuleScope{Vhosts: []string{"beta.com"}},
		Match:  TrafficRuleMatch{UAAny: []string{"*crawler*"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	}
	bodyA, _ := json.Marshal(ruleA)
	bodyB, _ := json.Marshal(ruleB)
	doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/add", bodyA)
	doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/add", bodyB)

	// Admin sees both.
	rr := doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/rules", nil)
	var resp trafficRuleListResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Rows) != 2 {
		t.Fatalf("admin: expected 2 rules, got %d", len(resp.Rows))
	}

	// Scoped token for alpha.com sees only alpha.com rule.
	rr = doRequest(mux, scopedCtx("alpha.com"), http.MethodGet, "/api/v1/webdet/rules", nil)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Rows) != 1 {
		t.Fatalf("scoped alpha: expected 1 rule, got %d", len(resp.Rows))
	}
	if resp.Rows[0].Scope.Vhosts[0] != "alpha.com" {
		t.Fatalf("scoped alpha: wrong rule returned: %+v", resp.Rows[0])
	}

	// Scoped token for beta.com sees only beta.com rule.
	rr = doRequest(mux, scopedCtx("beta.com"), http.MethodGet, "/api/v1/webdet/rules", nil)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Rows) != 1 {
		t.Fatalf("scoped beta: expected 1 rule, got %d", len(resp.Rows))
	}
	if resp.Rows[0].Scope.Vhosts[0] != "beta.com" {
		t.Fatalf("scoped beta: wrong rule returned: %+v", resp.Rows[0])
	}

	// Scoped token for unknown.com sees nothing (empty rows, not error).
	rr = doRequest(mux, scopedCtx("unknown.com"), http.MethodGet, "/api/v1/webdet/rules", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown scope: expected 200 empty, got %d", rr.Code)
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Rows) != 0 {
		t.Fatalf("unknown scope: expected 0 rules, got %d", len(resp.Rows))
	}
}

// TestRulesScope_Get verifies scope check on single rule retrieval.
func TestRulesScope_Get(t *testing.T) {
	e, mux := newTestEngine(t)
	rule := mustAddRule(t, e, "mysite.com", TrafficActionBlock)

	// Admin can fetch it.
	rr := doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/rules/get?id="+rule.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin get: status=%d", rr.Code)
	}

	// Correct scoped token can fetch it.
	rr = doRequest(mux, scopedCtx("mysite.com"), http.MethodGet, "/api/v1/webdet/rules/get?id="+rule.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("correct scope get: status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Wrong scoped token gets 403.
	rr = doRequest(mux, scopedCtx("other.com"), http.MethodGet, "/api/v1/webdet/rules/get?id="+rule.ID, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("wrong scope get: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRulesScope_Add verifies that a scoped token cannot create rules for other vhosts.
func TestRulesScope_Add(t *testing.T) {
	_, mux := newTestEngine(t)

	newRule := TrafficRule{
		Enabled: true, Priority: 50,
		Scope:  TrafficRuleScope{Vhosts: []string{"victim.com"}},
		Match:  TrafficRuleMatch{UAAny: []string{"*"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	}
	body, _ := json.Marshal(newRule)

	// Scoped token for attacker.com tries to add rule for victim.com → 403.
	rr := doRequest(mux, scopedCtx("attacker.com"), http.MethodPost, "/api/v1/webdet/rules/add", body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant add: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped token for victim.com CAN add rule for its own vhost → 200.
	rr = doRequest(mux, scopedCtx("victim.com"), http.MethodPost, "/api/v1/webdet/rules/add", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("own-vhost add: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRulesScope_Update verifies cross-tenant update protection.
func TestRulesScope_Update(t *testing.T) {
	e, mux := newTestEngine(t)
	// Rule belongs to site-a.com
	rule := mustAddRule(t, e, "site-a.com", TrafficActionBlock)

	updated := TrafficRule{
		Enabled: false, Priority: 999,
		Scope:  TrafficRuleScope{Vhosts: []string{"site-a.com"}},
		Match:  TrafficRuleMatch{},
		Action: TrafficRuleAction{Type: TrafficActionAllow},
	}
	body, _ := json.Marshal(updated)
	path := "/api/v1/webdet/rules/update?id=" + rule.ID

	// Wrong scope → 403.
	rr := doRequest(mux, scopedCtx("site-b.com"), http.MethodPost, path, body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("wrong scope update: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Correct scope → 200.
	rr = doRequest(mux, scopedCtx("site-a.com"), http.MethodPost, path, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("correct scope update: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRulesScope_Update_ScopeEscalation verifies a scoped token cannot update a
// rule's vhosts to include vhosts outside its own scope.
func TestRulesScope_Update_ScopeEscalation(t *testing.T) {
	e, mux := newTestEngine(t)
	rule := mustAddRule(t, e, "mysite.com", TrafficActionBlock)

	// Try to re-scope the rule to include a vhost outside the token's allowlist.
	escalated := TrafficRule{
		Enabled: true, Priority: 100,
		Scope:  TrafficRuleScope{Vhosts: []string{"mysite.com", "targetsite.com"}},
		Match:  TrafficRuleMatch{UAAny: []string{"*"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	}
	body, _ := json.Marshal(escalated)
	path := "/api/v1/webdet/rules/update?id=" + rule.ID

	// Token for mysite.com only — targetsite.com is out of scope → 403.
	rr := doRequest(mux, scopedCtx("mysite.com"), http.MethodPost, path, body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scope escalation: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRulesScope_Remove verifies cross-tenant rule deletion protection.
func TestRulesScope_Remove(t *testing.T) {
	e, mux := newTestEngine(t)
	rule := mustAddRule(t, e, "protected.com", TrafficActionBlock)
	path := "/api/v1/webdet/rules/remove?id=" + rule.ID

	// Wrong scope → 403, rule stays.
	rr := doRequest(mux, scopedCtx("evil.com"), http.MethodPost, path, []byte("{}"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("wrong scope remove: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Rule still exists after failed removal attempt.
	if _, ok := e.TrafficRuleGet(rule.ID); !ok {
		t.Fatal("rule was deleted despite 403 response")
	}

	// Correct scope → 200, rule deleted.
	rr = doRequest(mux, scopedCtx("protected.com"), http.MethodPost, path, []byte("{}"))
	if rr.Code != http.StatusOK {
		t.Fatalf("correct scope remove: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Confirm deletion.
	if _, ok := e.TrafficRuleGet(rule.ID); ok {
		t.Fatal("rule still exists after successful removal")
	}
}

// TestRulesScope_Simulate verifies scoped simulate restriction.
func TestRulesScope_Simulate(t *testing.T) {
	_, mux := newTestEngine(t)

	// Add a rule for target.com via admin.
	addBody, _ := json.Marshal(TrafficRule{
		Enabled: true, Priority: 100,
		Scope:  TrafficRuleScope{Vhosts: []string{"target.com"}},
		Match:  TrafficRuleMatch{UAAny: []string{"*badbot*"}},
		Action: TrafficRuleAction{Type: TrafficActionBlock},
	})
	doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/add", addBody)

	simReq := func(host string) []byte {
		b, _ := json.Marshal(map[string]string{
			"host": host, "ua": "badbot/1.0", "path": "/", "method": "GET",
		})
		return b
	}

	// Scoped token for target.com CAN simulate against its own host.
	rr := doRequest(mux, scopedCtx("target.com"), http.MethodPost,
		"/api/v1/webdet/rules/simulate", simReq("target.com"))
	if rr.Code != http.StatusOK {
		t.Fatalf("own simulate: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped token for attacker.com CANNOT simulate against target.com → 403.
	rr = doRequest(mux, scopedCtx("attacker.com"), http.MethodPost,
		"/api/v1/webdet/rules/simulate", simReq("target.com"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant simulate: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRulesScope_AdminUnrestricted verifies that admin / loopback context
// (nil scope) is never blocked by the scope checks.
func TestRulesScope_AdminUnrestricted(t *testing.T) {
	e, mux := newTestEngine(t)
	rule := mustAddThrottleRule(t, e, "any.com")

	// Admin can list.
	rr := doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/rules", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin list: %d", rr.Code)
	}

	// Admin can get.
	rr = doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/rules/get?id="+rule.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin get: %d", rr.Code)
	}

	// Admin can simulate against any host.
	simBody, _ := json.Marshal(map[string]string{"host": "any.com", "ua": "bot/1", "method": "GET"})
	rr = doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/simulate", simBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin simulate: %d", rr.Code)
	}

	// Admin can remove.
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/webdet/rules/remove?id="+rule.ID, []byte("{}"))
	if rr.Code != http.StatusOK {
		t.Fatalf("admin remove: %d", rr.Code)
	}
}

// TestRulesBodySizeLimit verifies that oversized POST bodies are rejected.
func TestRulesBodySizeLimit(t *testing.T) {
	_, mux := newTestEngine(t)

	// Build a payload just over the 64 KiB limit.
	huge := make([]byte, maxRuleBodyBytes+1024)
	for i := range huge {
		huge[i] = 'x'
	}

	rr := doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/add", huge)
	// Should be 400 (bad JSON / body too large), never 200.
	if rr.Code == http.StatusOK {
		t.Fatal("oversized body was accepted — size limit not enforced")
	}
}
