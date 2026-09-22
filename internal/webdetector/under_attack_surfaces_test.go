package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAttackHandlerEngine(underAttack bool) *Engine {
	e := &Engine{}
	e.manualChal.init("")
	e.cfg.UnderAttack = underAttack
	if underAttack {
		e.attack = newUnderAttackTracker()
	}
	return e
}

// deriveVhostState places a vhost on the ladder: under_attack > challenged >
// suspicious > normal, single-sourced across surfaces.
func TestDeriveVhostState_Ladder(t *testing.T) {
	e := &Engine{}
	now := time.Unix(1_700_000_000, 0)

	if s := e.deriveVhostState(&ChallengeVhostState{Host: "n"}, now); s != "normal" {
		t.Fatalf("normal: got %q", s)
	}
	sus := &ChallengeVhostState{Host: "s", Status: "inactive", Score: 0.8, OnThresh: 0.7}
	if s := e.deriveVhostState(sus, now); s != "suspicious" {
		t.Fatalf("suspicious: got %q", s)
	}
	ch := &ChallengeVhostState{Host: "c", Status: "active", Mode: "auto", Score: 0.9, OnThresh: 0.7}
	if s := e.deriveVhostState(ch, now); s != "challenged" {
		t.Fatalf("challenged: got %q", s)
	}
	// under_attack wins over challenged.
	e.attack = newUnderAttackTracker()
	e.attack.hosts["c"] = &attackVhost{on: true}
	if s := e.deriveVhostState(ch, now); s != "under_attack" {
		t.Fatalf("under_attack: got %q", s)
	}
	// nil engine / nil row are safe.
	var ne *Engine
	if s := ne.deriveVhostState(&ChallengeVhostState{Host: "x"}, now); s != "normal" {
		t.Fatalf("nil engine: got %q", s)
	}
}

func TestChalStatCol(t *testing.T) {
	if got := chalStatCol(chalVhost{Status: "active", State: "challenged"}); got != "active" {
		t.Fatalf("challenged STAT = %q, want active", got)
	}
	if got := chalStatCol(chalVhost{Status: "active", State: "under_attack"}); got != "attack" {
		t.Fatalf("under_attack STAT = %q, want attack", got)
	}
	if got := chalStatCol(chalVhost{Status: "inactive"}); got != "inactive" {
		t.Fatalf("plain STAT = %q, want inactive", got)
	}
}

func TestParseAttackOn(t *testing.T) {
	cases := map[string]bool{"1": true, "true": true, "on": true, "yes": true, "0": false, "off": false, "no": false}
	for in, want := range cases {
		if got, err := parseAttackOn(in, nil); err != nil || got != want {
			t.Fatalf("parseAttackOn(%q) = (%v,%v), want %v", in, got, err, want)
		}
	}
	if _, err := parseAttackOn("", nil); err == nil {
		t.Fatal("empty value must error, not silently no-op")
	}
	if _, err := parseAttackOn("wat", nil); err == nil {
		t.Fatal("garbage value must error")
	}
	tb := true
	if got, err := parseAttackOn("", &tb); err != nil || !got {
		t.Fatalf("body bool must win: (%v,%v)", got, err)
	}
}

func TestHandleChallengeVhostAttack_Success(t *testing.T) {
	e := newAttackHandlerEngine(true)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?host=shop.example&on=1", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["attack"] != true {
		t.Fatalf("attack = %#v, want true", m["attack"])
	}
	e.attack.mu.Lock()
	st := e.attack.hosts["shop.example"]
	e.attack.mu.Unlock()
	if st == nil || st.override != +1 {
		t.Fatalf("override not recorded: %+v", st)
	}
}

func TestHandleChallengeVhostAttack_MissingOn(t *testing.T) {
	e := newAttackHandlerEngine(true)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?host=shop.example", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing on, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleChallengeVhostAttack_DisabledConflict(t *testing.T) {
	e := newAttackHandlerEngine(false) // UNDER_ATTACK off
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?host=shop.example&on=1", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409 when disabled, got %d: %s", rr.Code, rr.Body.String())
	}
}

// An operator override is reflected by VhostAttackState immediately (before the
// next tick actuates st.on), so the surfaces don't lag the operator's action.
func TestVhostAttackState_ReflectsOverrideImmediately(t *testing.T) {
	e := newAttackHandlerEngine(true)
	now := time.Unix(1_700_000_000, 0)
	e.SetVhostAttackOverride("shop.example", true, now, 0)
	if on, _, _ := e.VhostAttackState("shop.example"); !on {
		t.Fatal("force-on override should read as on before actuation")
	}
	e.SetVhostAttackOverride("shop.example", false, now, 0)
	if on, _, _ := e.VhostAttackState("shop.example"); on {
		t.Fatal("force-off override should read as off immediately")
	}
}

// A vhost forced UNDER_ATTACK with no challenge store row is reported by the
// single-vhost endpoint (200 state=under_attack), not 404 — so it agrees with
// the drilldown rather than reading as "no active challenge".
func TestHandleChallengeVhost_ForcedOverrideNoStoreRow(t *testing.T) {
	e := newAttackHandlerEngine(true)
	e.chalAPI = NewChallengeAPIStore(1000) // empty store: no challenge row for the host
	e.SetVhostAttackOverride("shop.example", true, time.Now(), 0)

	ctx := context.WithValue(context.Background(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost?host=shop.example", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleChallengeVhost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for forced override with no row, got %d: %s", rr.Code, rr.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["state"] != "under_attack" {
		t.Fatalf("state = %#v, want under_attack", m["state"])
	}
}

func TestHandleChallengeVhostAttack_OutOfScopeForbidden(t *testing.T) {
	e := newAttackHandlerEngine(true)
	scope := map[string]struct{}{"other.example": {}} // token limited to a different vhost
	ctx := context.WithValue(context.Background(), CtxScopeKey{}, scope)
	ctx = context.WithValue(ctx, CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleScoped)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?host=shop.example&on=1", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403 out of scope, got %d: %s", rr.Code, rr.Body.String())
	}
	// The override must NOT have been recorded for the out-of-scope host.
	e.attack.mu.Lock()
	_, present := e.attack.hosts["shop.example"]
	e.attack.mu.Unlock()
	if present {
		t.Fatal("out-of-scope request recorded an override (scope bypass)")
	}
}
