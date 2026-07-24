package webdetector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNginxBridgeOKTouchScopedByHostAndScope(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	ip := "203.0.113.10"

	rr := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"ip":"203.0.113.10","host":"a.example.com","scope":"web","ttl_sec":120}`)
	req := httptest.NewRequest(http.MethodPost, "/nginx/ok/touch", body)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleOKTouch(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ok touch status=%d body=%s", rr.Code, rr.Body.String())
	}

	check := func(host, scope, wantVH string) {
		drr := httptest.NewRecorder()
		dreq := httptest.NewRequest(http.MethodGet, "/nginx/decision?ip="+ip+"&host="+host+"&scope="+scope, nil)
		dreq.Header.Set("X-CFM-Token", "tok")
		b.mu.Lock()
		b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
		b.mu.Unlock()
		b.handleDecision(drr, dreq)
		var payload map[string]any
		_ = json.Unmarshal(drr.Body.Bytes(), &payload)
		if payload["vhost_action"] != wantVH {
			t.Fatalf("host=%s scope=%s expected %s got payload=%+v", host, scope, wantVH, payload)
		}
	}

	check("a.example.com", "web", "allow")
	check("b.example.com", "web", "challenge")
	check("a.example.com", "panel:2083", "challenge")
}

func TestNginxBridgeOKTouchRequiresHostAndScope(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	for _, raw := range []string{
		`{"ip":"203.0.113.10","host":"","scope":"web","ttl_sec":120}`,
		`{"ip":"203.0.113.10","host":"a.example.com","scope":"","ttl_sec":120}`,
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/nginx/ok/touch", bytes.NewBufferString(raw))
		req.Header.Set("X-CFM-Token", "tok")
		b.handleOKTouch(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("raw=%s expected 400 got %d", raw, rr.Code)
		}
	}
}

func TestNginxBridgeWAFExcludesIncludesScopeHosts(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.ListWAFExcludes = func() []excludeEntry {
		return []excludeEntry{
			{Type: "host", Value: "tenant-a.example.com", ScopeHosts: []string{"tenant-a.example.com"}},
			{Type: "path", Value: "/wp-admin/*"},
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/waf/excludes", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleWAFExcludes(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var payload struct {
		Entries []excludeEntry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(payload.Entries))
	}
	if got := payload.Entries[0].ScopeHosts; len(got) != 1 || got[0] != "tenant-a.example.com" {
		t.Fatalf("expected scoped entry to preserve scope_hosts, got=%v", got)
	}
}

func TestNginxBridgeDecisionIncludesRuleAction(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
		if in.Host == "example.com" {
			return TrafficRuleEvalResult{
				Matched: true,
				Rule:    TrafficRule{ID: "r_test"},
				Action:  TrafficActionThrottle,
				Profile: "soft_bot",
			}
		}
		return TrafficRuleEvalResult{}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=1.2.3.4&host=example.com&uri=%2F&method=GET&ua=testua", nil)
	req.Header.Set("X-CFM-Token", "tok")

	b.handleDecision(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["rule_action"] != TrafficActionThrottle {
		t.Fatalf("missing/invalid rule_action: %+v", payload)
	}
	if payload["throttle_profile"] != "soft_bot" {
		t.Fatalf("missing throttle profile: %+v", payload)
	}
	if payload["rule_id"] != "r_test" {
		t.Fatalf("missing rule id: %+v", payload)
	}
}

func TestNginxBridgeDecisionRuleActionMatchesSimulate(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		profile string
	}{
		{name: "allow", action: TrafficActionAllow},
		{name: "challenge", action: TrafficActionChallenge},
		{name: "block", action: TrafficActionBlock},
		{name: "throttle", action: TrafficActionThrottle, profile: "soft_bot"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
			_, err := store.Add(TrafficRule{
				ID:       "r_" + tc.name,
				Enabled:  true,
				Priority: 100,
				Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
				Match:    TrafficRuleMatch{Methods: []string{"GET"}, PathAny: []string{"/"}},
				Action:   TrafficRuleAction{Type: tc.action, Profile: tc.profile},
			})
			if err != nil {
				t.Fatalf("add rule: %v", err)
			}

			sim := store.Simulate(TrafficRuleEvalInput{
				Host:   "example.com",
				IP:     "1.2.3.4",
				Path:   "/",
				Method: "GET",
			})
			if !sim.Matched {
				t.Fatalf("expected simulate to match")
			}

			b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
			b.RuleDecision = store.Simulate

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet,
				"/nginx/decision?ip=1.2.3.4&host=example.com&uri=%2F&method=GET&ua=testua", nil)
			req.Header.Set("X-CFM-Token", "tok")
			b.handleDecision(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}

			var payload map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["rule_action"] != sim.Action {
				t.Fatalf("rule_action mismatch payload=%+v simulate=%+v", payload, sim)
			}
			if payload["rule_id"] != sim.Rule.ID {
				t.Fatalf("rule_id mismatch payload=%+v simulate=%+v", payload, sim)
			}

			if tc.profile != "" {
				if payload["throttle_profile"] != tc.profile {
					t.Fatalf("throttle_profile mismatch payload=%+v", payload)
				}
			} else if _, ok := payload["throttle_profile"]; ok {
				t.Fatalf("unexpected throttle_profile for non-throttle action payload=%+v", payload)
			}
		})
	}
}

// TestNginxBridgeDecisionMatchesQueryInPath exercises the full edge→bridge
// path: cfm.lua now sends the request target with its query string, the bridge
// splits it into path + qs, and a "/forum/ucp.php?mode=register" rule matches.
// The uri param carries the encoded '?'/'=' exactly as ngx.escape_uri produces.
func TestNginxBridgeDecisionMatchesQueryInPath(t *testing.T) {
	store := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if _, err := store.Add(TrafficRule{
		ID:       "r_ucp",
		Enabled:  true,
		Priority: 120,
		Scope:    TrafficRuleScope{Vhosts: []string{"mathematica.gr"}},
		Match: TrafficRuleMatch{
			Methods: []string{"GET", "POST"},
			PathAny: []string{"/forum/ucp.php?mode=register"},
		},
		Action: TrafficRuleAction{Type: TrafficActionChallenge},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = store.Simulate

	decide := func(encodedURI string) map[string]any {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/nginx/decision?ip=1.2.3.4&host=mathematica.gr&method=GET&ua=testua&uri="+encodedURI, nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return payload
	}

	// /forum/ucp.php?mode=register&sid=deadbeef  (escape_uri-encoded)
	got := decide("%2Fforum%2Fucp.php%3Fmode%3Dregister%26sid%3Ddeadbeef")
	if got["rule_action"] != TrafficActionChallenge {
		t.Fatalf("expected challenge for register page, got=%+v", got)
	}
	if got["rule_id"] != "r_ucp" {
		t.Fatalf("expected rule id r_ucp, got=%+v", got)
	}

	// Same path, different mode — must NOT match.
	got = decide("%2Fforum%2Fucp.php%3Fmode%3Dlogin")
	if _, ok := got["rule_action"]; ok {
		t.Fatalf("expected no rule_action for mode=login, got=%+v", got)
	}
}

// TestNginxBridgeDecisionSeparateQSParam exercises the structured transport:
// the edge sends the decoded path in "uri" and the raw query in a separate "qs"
// param. The bridge must trust "qs" and NOT split "uri" — so a decoded path
// that itself contains a literal '?' (from %3F) stays intact.
func TestNginxBridgeDecisionSeparateQSParam(t *testing.T) {
	var gotPath, gotQS string
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
		gotPath, gotQS = in.Path, in.QueryString
		return TrafficRuleEvalResult{}
	}

	// uri carries a literal '?' in the path; qs is the real (separate) query.
	req := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=1.2.3.4&host=example.com&method=GET&ua=x"+
			"&uri=%2Fweird%3Fpath.php&qs=mode%3Dregister", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(httptest.NewRecorder(), req)

	if gotPath != "/weird?path.php" {
		t.Fatalf("path mis-split: got %q want %q", gotPath, "/weird?path.php")
	}
	if gotQS != "mode=register" {
		t.Fatalf("qs wrong: got %q want %q", gotQS, "mode=register")
	}

	// Empty qs param present → still no split, query is empty.
	req = httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=1.2.3.4&host=example.com&method=GET&ua=x&uri=%2Ffoo&qs=", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(httptest.NewRecorder(), req)
	if gotPath != "/foo" || gotQS != "" {
		t.Fatalf("empty qs: got path=%q qs=%q want /foo and empty", gotPath, gotQS)
	}
}

func TestValidateUploadSourcePath(t *testing.T) {
	pending := filepath.Join(t.TempDir(), "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatalf("mkdir pending: %v", err)
	}
	src := filepath.Join(pending, "upload.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if _, ok := validateUploadSourcePath("../etc/passwd", true, pending); ok {
		t.Fatalf("expected relative traversal path to be rejected")
	}
	if _, ok := validateUploadSourcePath(src, true, pending); !ok {
		t.Fatalf("expected alreadyCopied source inside pending dir to be accepted")
	}
}

func TestNginxBridgeDecisionReevaluatesUADependentRules(t *testing.T) {
	store := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	_, err := store.Add(TrafficRule{
		ID:       "ua_challenge",
		Enabled:  true,
		Priority: 200,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match: TrafficRuleMatch{
			Methods: []string{"GET"},
			PathAny: []string{"/"},
			UAAny:   []string{"*BadBot*"},
		},
		Action: TrafficRuleAction{Type: TrafficActionChallenge},
	})
	if err != nil {
		t.Fatalf("add ua challenge rule: %v", err)
	}

	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = store.Simulate

	base := "/nginx/decision?ip=1.2.3.4&host=example.com&uri=%2F&method=GET&ua="

	allowReq := httptest.NewRequest(http.MethodGet, base+"GoodBrowser", nil)
	allowReq.Header.Set("X-CFM-Token", "tok")
	allowRR := httptest.NewRecorder()
	b.handleDecision(allowRR, allowReq)
	if allowRR.Code != http.StatusOK {
		t.Fatalf("good ua status=%d body=%s", allowRR.Code, allowRR.Body.String())
	}

	var allowPayload map[string]any
	if err := json.Unmarshal(allowRR.Body.Bytes(), &allowPayload); err != nil {
		t.Fatalf("decode good ua payload: %v", err)
	}
	if got, ok := allowPayload["rule_action"]; ok {
		t.Fatalf("expected no rule_action for good ua (no rule match), got=%v payload=%+v", got, allowPayload)
	}

	challengeReq := httptest.NewRequest(http.MethodGet, base+"VeryBadBot/1.0", nil)
	challengeReq.Header.Set("X-CFM-Token", "tok")
	challengeRR := httptest.NewRecorder()
	b.handleDecision(challengeRR, challengeReq)
	if challengeRR.Code != http.StatusOK {
		t.Fatalf("bad ua status=%d body=%s", challengeRR.Code, challengeRR.Body.String())
	}

	var challengePayload map[string]any
	if err := json.Unmarshal(challengeRR.Body.Bytes(), &challengePayload); err != nil {
		t.Fatalf("decode bad ua payload: %v", err)
	}
	if got := challengePayload["rule_action"]; got != TrafficActionChallenge {
		t.Fatalf("expected challenge for bad ua, got=%v payload=%+v", got, challengePayload)
	}
	if got := challengePayload["rule_id"]; got != "ua_challenge" {
		t.Fatalf("expected ua_challenge rule id, got=%v payload=%+v", got, challengePayload)
	}
}

func TestNginxBridgeOKTouchDisabledWhenOkIPTTLZero(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, 0)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/nginx/ok/touch", bytes.NewBufferString(`{"ip":"203.0.113.10","host":"a.example.com","scope":"web","ttl_sec":120}`))
	req.Header.Set("X-CFM-Token", "tok")
	b.handleOKTouch(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ok touch status=%d body=%s", rr.Code, rr.Body.String())
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.okState) != 0 {
		t.Fatalf("okState should remain empty when OkIPTTL=0, got len=%d", len(b.okState))
	}
}

func TestNginxBridgeDecisionDoesNotUseOkStateWhenOkIPTTLZero(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, 0)
	ip := "203.0.113.10"
	host := "a.example.com"
	scope := "web"

	b.mu.Lock()
	b.okState[okStateKey{IP: ip, Host: host, Scope: scope}] = time.Now().Add(time.Minute)
	b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
	b.mu.Unlock()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/decision?ip="+ip+"&host="+host+"&scope="+scope, nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["vhost_action"] != "challenge" {
		t.Fatalf("expected challenge with OkIPTTL=0; payload=%+v", payload)
	}
}
