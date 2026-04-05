package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
