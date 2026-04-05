package webdetector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestTrafficRulesAPI_CRUDAndSimulate(t *testing.T) {
	e := NewEngine(Config{TrafficRulesStorePath: filepath.Join(t.TempDir(), "rules.json")})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

	addReq := TrafficRule{
		Enabled:  true,
		Priority: 100,
		Scope:    TrafficRuleScope{Vhosts: []string{"example.com"}},
		Match:    TrafficRuleMatch{UAAny: []string{"*facebookexternalhit*"}},
		Action:   TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"},
	}
	body, _ := json.Marshal(addReq)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webdet/rules/add", bytes.NewReader(body))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", rr.Code, rr.Body.String())
	}

	var addResp struct {
		Rule TrafficRule `json:"rule"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &addResp); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	if addResp.Rule.ID == "" {
		t.Fatalf("expected rule id in add response")
	}
	if !addResp.Rule.Enabled || len(addResp.Rule.Match.UAAny) == 0 {
		t.Fatalf("unexpected add response rule: %+v", addResp.Rule)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/webdet/rules", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	direct := e.trafficRules.Simulate(TrafficRuleEvalInput{
		Host: "example.com",
		UA:   "facebookexternalhit/1.1",
		Path: "/",
	})
	if !direct.Matched {
		t.Fatalf("expected direct simulate match, got: %+v", direct)
	}

	simBody := []byte(`{"host":"example.com","ua":"facebookexternalhit/1.1","path":"/","method":"GET"}`)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webdet/rules/simulate", bytes.NewReader(simBody))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("simulate status=%d body=%s", rr.Code, rr.Body.String())
	}
	var simResp TrafficRuleEvalResult
	if err := json.Unmarshal(rr.Body.Bytes(), &simResp); err != nil {
		t.Fatalf("decode simulate response: %v", err)
	}
	if !simResp.Matched || simResp.Action != TrafficActionThrottle {
		t.Fatalf("unexpected simulate response: %+v", simResp)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webdet/rules/remove?id="+addResp.Rule.ID, bytes.NewReader([]byte("{}")))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", rr.Code, rr.Body.String())
	}
}
