package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The geo-policy challenge floor in handleDecision (policy-kinds slice):
// a fleet-armed country raises ip_action to challenge for uncleared traffic,
// a machine-to-machine endpoint clears a FLOOR-ONLY challenge (payment
// webhooks from an armed country must keep working — review finding), and a
// real per-IP entry is never softened by that carve-out.

func geoFloorDecision(t *testing.T, b *NginxBridge, uri string) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=203.0.113.77&host=example.com&uri="+uri+"&method=GET&ua=curl&country=GR", nil)
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

func TestGeoFloorChallengesArmedCountry(t *testing.T) {
	resetFPPolicies(t)
	b := NewNginxBridge("/tmp/cfm-test-geofloor.sock", "tok", time.Minute, time.Minute)

	// Nothing armed: allow.
	if p := geoFloorDecision(t, b, "%2Fshop"); p["ip_action"] != "allow" {
		t.Fatalf("unarmed: ip_action=%v", p["ip_action"])
	}

	SetFingerprintPolicies([]FingerprintPolicy{{ID: "GR", Kind: "country", Action: "challenge_v2"}})

	// Armed country: the floor challenges a normal page.
	if p := geoFloorDecision(t, b, "%2Fshop"); p["ip_action"] != "challenge" {
		t.Fatalf("armed country: ip_action=%v", p["ip_action"])
	}

	// ...but a machine-to-machine endpoint (WooCommerce API / payment
	// webhooks) clears the FLOOR-ONLY challenge: non-browser callbacks
	// cannot solve a JS challenge.
	if p := geoFloorDecision(t, b, "%2Fwc-api%2Fv3%2Forders"); p["ip_action"] != "allow" {
		t.Fatalf("M2M endpoint under geo floor: ip_action=%v", p["ip_action"])
	}
}

func TestGeoFloorM2MCarveoutNeverSoftensARealPerIPEntry(t *testing.T) {
	resetFPPolicies(t)
	b := NewNginxBridge("/tmp/cfm-test-geofloor2.sock", "tok", time.Minute, time.Minute)
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "GR", Kind: "country", Action: "challenge"}})

	// A REAL per-IP challenge (behavioural detection) owns the action: the
	// M2M carve-out only clears the geo floor, never per-IP suspicion.
	b.mu.Lock()
	b.ipState["203.0.113.77"] = bridgeIPEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
	b.mu.Unlock()

	if p := geoFloorDecision(t, b, "%2Fwc-api%2Fv3%2Forders"); p["ip_action"] != "challenge" {
		t.Fatalf("real per-IP challenge must survive the M2M carve-out: ip_action=%v", p["ip_action"])
	}
}
