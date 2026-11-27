package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cfm/internal/proxyipfilter"
)

// A CHALLENGE feed of cfm.blocklists (Tor exits) in handleDecision: log mode
// leaves the answer an allow the edge does not cache; enforce raises an
// uncleared listed client to a challenge, for a direct client as for a
// proxied one; the M2M carve-out, a solve and an allow lift it; panel scope
// is never touched.
func listChallengeDecision(t *testing.T, b *NginxBridge, query string) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/decision?"+query, nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var p map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

func TestListChallengeFloor(t *testing.T) {
	resetFPPolicies(t)
	proxyipfilter.ResetForTest()
	t.Cleanup(proxyipfilter.ResetForTest)
	proxyipfilter.PrepareChallengeFeed("TOR", []string{"185.220.101.1", "185.220.101.2"}, nil).Publish()
	proxyipfilter.SetFeed("MYALLOW", true, []string{"185.220.101.2"}, nil)
	b := NewNginxBridge("/tmp/cfm-test-listchal.sock", "tok", time.Minute, time.Minute)

	const tor = "ip=185.220.101.1&host=example.com&method=GET&ua=Mozilla"
	// Log mode: allow, not cacheable.
	proxyipfilter.SetChallengeMode("log")
	if p := listChallengeDecision(t, b, tor+"&uri=%2Fshop"); p["ip_action"] != "allow" || p["rule_action"] != ruleActionObserve {
		t.Fatalf("log mode: %v", p)
	}
	// Not listed: a plain, cacheable allow.
	if p := listChallengeDecision(t, b, "ip=198.51.100.1&host=example.com&uri=%2Fshop"); p["ip_action"] != "allow" || p["rule_action"] != nil {
		t.Fatalf("unlisted: %v", p)
	}

	proxyipfilter.SetChallengeMode("enforce")
	for _, q := range []string{tor + "&uri=%2Fshop", tor + "&uri=%2Fshop&px=1"} {
		if p := listChallengeDecision(t, b, q); p["ip_action"] != "challenge" {
			t.Errorf("enforce %q: %v", q, p)
		}
	}
	// M2M endpoint: the floor is lifted, as the geo floor's.
	if p := listChallengeDecision(t, b, tor+"&uri=%2Fwc-api%2Fv3%2Forders"); p["ip_action"] != "allow" {
		t.Errorf("M2M endpoint: %v", p)
	}
	// An allow cancels it.
	if p := listChallengeDecision(t, b, "ip=185.220.101.2&host=example.com&uri=%2Fshop"); p["ip_action"] != "allow" || p["rule_action"] != nil {
		t.Errorf("allowed: %v", p)
	}
	// Panel scope: never.
	if p := listChallengeDecision(t, b, tor+"&uri=%2F&scope=panel:2083"); p["ip_action"] != "allow" || p["rule_action"] != nil {
		t.Errorf("panel scope: %v", p)
	}
	// A real per-IP block wins over the floor.
	b.mu.Lock()
	b.ipState["185.220.101.1"] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(time.Minute)}
	b.mu.Unlock()
	if p := listChallengeDecision(t, b, tor+"&uri=%2Fshop"); p["ip_action"] != "block" {
		t.Errorf("per-IP block: %v", p)
	}
	b.mu.Lock()
	delete(b.ipState, "185.220.101.1")
	// Solved: the okState clears it.
	b.okState[okStateKey{IP: "185.220.101.1", Host: "example.com", Scope: "web"}] = time.Now().Add(time.Minute)
	b.mu.Unlock()
	if p := listChallengeDecision(t, b, tor+"&uri=%2Fshop"); p["ip_action"] != "allow" {
		t.Errorf("solved: %v", p)
	}
}
