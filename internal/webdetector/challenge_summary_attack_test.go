package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// handleChallengeSummary reports Under-Attack Mode status: enabled, and the
// count of vhosts currently in UNDER_ATTACK (on-state only, not a forced-off
// override), so `cfm webtop attack` can show it.
func TestHandleChallengeSummary_UnderAttackStatus(t *testing.T) {
	e := newAttackHandlerEngine(true) // cfg.UnderAttack + attack tracker (I1b helper)
	e.chalAPI = NewChallengeAPIStore(100)
	e.attack.hosts["a.example"] = &attackVhost{on: true}     // under attack
	e.attack.hosts["b.example"] = &attackVhost{override: -1} // forced off, not on
	e.attack.hosts["c.example"] = &attackVhost{override: +1} // forced on → counts

	ctx := context.WithValue(context.Background(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/summary", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleChallengeSummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["under_attack_enabled"] != true {
		t.Fatalf("under_attack_enabled = %#v, want true", m["under_attack_enabled"])
	}
	if m["under_attack_vhosts"] != float64(2) { // a (on) + c (forced on); b (forced off) excluded
		t.Fatalf("under_attack_vhosts = %#v, want 2", m["under_attack_vhosts"])
	}
}

// Under-Attack status must be stamped even when the challenge store is not
// wired yet (chalAPI==nil, e.g. early startup): the summary still reports
// under_attack_enabled truthfully instead of the zero-value false. Regression
// for the early-return path that returned a bare ChallengeSummary{}.
func TestHandleChallengeSummary_EnabledWithoutStore(t *testing.T) {
	e := newAttackHandlerEngine(true) // cfg.UnderAttack on
	e.chalAPI = nil                   // store not wired
	e.attack.hosts["a.example"] = &attackVhost{on: true}

	ctx := context.WithValue(context.Background(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/summary", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleChallengeSummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["under_attack_enabled"] != true {
		t.Fatalf("under_attack_enabled = %#v, want true (store nil must not mask config)", m["under_attack_enabled"])
	}
	if m["under_attack_vhosts"] != float64(1) {
		t.Fatalf("under_attack_vhosts = %#v, want 1", m["under_attack_vhosts"])
	}
}

// When the feature is off, the summary reports disabled and zero.
func TestHandleChallengeSummary_UnderAttackDisabled(t *testing.T) {
	e := newAttackHandlerEngine(false) // UNDER_ATTACK off (no attack tracker)
	e.chalAPI = NewChallengeAPIStore(100)
	ctx := context.WithValue(context.Background(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/summary", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleChallengeSummary(rr, req)
	var m map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["under_attack_enabled"] != false {
		t.Fatalf("under_attack_enabled = %#v, want false", m["under_attack_enabled"])
	}
}
