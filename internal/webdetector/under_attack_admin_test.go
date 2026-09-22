package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The scoped status endpoint must carry `state` so a cPanel tenant's cfm-admin
// badge (which reaches the vhost list only through this endpoint) shows
// under_attack, not just admins.
func TestHandleChallengeVhostStatus_CarriesState(t *testing.T) {
	e := newAttackHandlerEngine(true) // helper from under_attack_surfaces_test.go
	e.chalAPI = NewChallengeAPIStore(1000)
	e.SetVhostAttackOverride("shop.example", true, time.Now(), 0)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host=shop.example", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["state"] != "under_attack" {
		t.Fatalf("state = %#v, want under_attack", m["state"])
	}
}
