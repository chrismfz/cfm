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
