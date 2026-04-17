package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
