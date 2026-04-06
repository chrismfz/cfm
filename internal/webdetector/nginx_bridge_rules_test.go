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

func luaDecisionCacheable(payload map[string]any) bool {
	ipAction, _ := payload["ip_action"].(string)
	vhostAction, _ := payload["vhost_action"].(string)
	ruleAction, hasRuleAction := payload["rule_action"].(string)
	return ipAction == "allow" && vhostAction == "allow" && (!hasRuleAction || ruleAction == "allow")
}

func TestNginxBridgeDecisionRuleActionCacheability(t *testing.T) {
	tests := []struct {
		name          string
		ruleAction    string
		expectCacheOK bool
	}{
		{name: "rule block is not cacheable", ruleAction: TrafficActionBlock, expectCacheOK: false},
		{name: "rule challenge is not cacheable", ruleAction: TrafficActionChallenge, expectCacheOK: false},
		{name: "rule throttle is not cacheable", ruleAction: TrafficActionThrottle, expectCacheOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
			b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
				return TrafficRuleEvalResult{
					Matched: true,
					Rule:    TrafficRule{ID: "r_cache"},
					Action:  tc.ruleAction,
					Profile: "soft_bot",
				}
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

			if got := luaDecisionCacheable(payload); got != tc.expectCacheOK {
				t.Fatalf("cacheability mismatch for rule_action=%q: got=%v want=%v payload=%+v", tc.ruleAction, got, tc.expectCacheOK, payload)
			}
		})
	}
}

func TestNginxBridgeDecisionNoRuleActionIsCacheable(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)

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
	if got := luaDecisionCacheable(payload); !got {
		t.Fatalf("expected allow/allow decision without rule_action to be cacheable: payload=%+v", payload)
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
