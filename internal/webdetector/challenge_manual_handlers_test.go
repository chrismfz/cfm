package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestEngineForChallengeHandlers() *Engine {
	e := &Engine{}
	e.manualChal.init("")
	return e
}

func TestHandleChallengeVhostAdd_AllowsEmptyJSONBodyWithQueryParams(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?host=web-infox.eu&ttl=1h&reason=manual", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	e.handleChallengeVhostAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
	if got["host"] != "web-infox.eu" {
		t.Fatalf("expected host web-infox.eu, got %#v", got["host"])
	}
	if got["status"] != "active" {
		t.Fatalf("expected status active, got %#v", got["status"])
	}
}

func TestHandleChallengeVhostStatus_WWWCoveredByApexManual(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	// Operator challenges the apex; the bridge enforces it on apex AND www.
	e.ManualChallengeVhost("e-vafeiadis.gr", time.Hour, "manual", "")

	get := func(host string) map[string]interface{} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host="+host, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostStatus(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", host, rr.Code, rr.Body.String())
		}
		var m map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: bad json: %v", host, err)
		}
		return m
	}

	if m := get("e-vafeiadis.gr"); m["manual_active"] != true {
		t.Fatalf("apex: expected manual_active=true, got %#v", m["manual_active"])
	}
	// The regression: before the fix this reported false for the www variant.
	if m := get("www.e-vafeiadis.gr"); m["manual_active"] != true {
		t.Fatalf("www: expected manual_active=true (covered by apex manual), got %#v", m["manual_active"])
	}
}

func TestHandleChallengeVhostAdd_RejectsInvalidJSON(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?host=web-infox.eu", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	e.handleChallengeVhostAdd(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid JSON") {
		t.Fatalf("expected invalid JSON error, got: %s", rr.Body.String())
	}
}

// ── Slice D: scoped TTL ceiling on the manual vhost challenge ────────────────
// A scoped (cPanel customer) token's panic-button arm is a temporary shield:
// requests beyond scopedMaxChallengeTTL are CLAMPED (never rejected — the
// panic button must not fail on a big number) and the response says so via
// ttl_capped + the effective ttl/expiry. Admin callers stay uncapped.

func scopedAddReq(target string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, nil)
	ctx := context.WithValue(req.Context(), CtxRoleKey{}, CtxRoleScoped)
	ctx = context.WithValue(ctx, CtxScopeKey{}, map[string]struct{}{"tenant-a.example.com": {}})
	return req.WithContext(ctx)
}

func TestHandleChallengeVhostAdd_ScopedTTLCapClamps(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	rr := httptest.NewRecorder()
	e.handleChallengeVhostAdd(rr, scopedAddReq("/api/v1/challenge/vhost/add?host=tenant-a.example.com&ttl=72h"))
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped over-cap arm must clamp, not fail: %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		TTL       string    `json:"ttl"`
		TTLCapped bool      `json:"ttl_capped"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if got.TTL != scopedMaxChallengeTTL.String() {
		t.Fatalf("ttl = %q, want clamped %q", got.TTL, scopedMaxChallengeTTL.String())
	}
	if !got.TTLCapped {
		t.Fatalf("ttl_capped must be true on a clamped arm (silent caps hide policy)")
	}
	if d := time.Until(got.ExpiresAt); d > scopedMaxChallengeTTL+time.Minute {
		t.Fatalf("expires_at %v exceeds the scoped ceiling", got.ExpiresAt)
	}
}

func TestHandleChallengeVhostAdd_ScopedTTLUnderCapUntouched(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	rr := httptest.NewRecorder()
	e.handleChallengeVhostAdd(rr, scopedAddReq("/api/v1/challenge/vhost/add?host=tenant-a.example.com&ttl=1h"))
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped in-cap arm failed: %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		TTL       string `json:"ttl"`
		TTLCapped bool   `json:"ttl_capped"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.TTL != "1h0m0s" || got.TTLCapped {
		t.Fatalf("in-cap arm must pass through untouched, got ttl=%q capped=%v", got.TTL, got.TTLCapped)
	}
}

func TestHandleChallengeVhostAdd_AdminTTLUncapped(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?host=any.example.com&ttl=720h", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAdd(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin arm failed: %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		TTL       string `json:"ttl"`
		TTLCapped bool   `json:"ttl_capped"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.TTL != "720h0m0s" || got.TTLCapped {
		t.Fatalf("admin must stay uncapped, got ttl=%q capped=%v", got.TTL, got.TTLCapped)
	}
}

func TestHandleChallengeVhostAdd_ScopedRoleWithoutScopeFailsClosed(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?host=tenant-a.example.com&ttl=1h", nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxRoleKey{}, CtxRoleScoped))
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAdd(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped role with no scope map must fail closed, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ── Slice D: manual arm/disarm history carries rung + actor ──────────────────
// "Who armed v2 on this vhost" used to need a timestamp join of cfm.api.log
// against the history DB; the history event now records both. Rung is always
// present on manual_on (explicit "v1", so a missing key means a pre-slice-D
// event, never "plain"); actor comes from the request scope.

func TestManualChallengeHistoryCarriesRungAndActor(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}
	e.manualChal.init("")

	// Scoped arm of a v2 challenge via the handler (actor derived from scope).
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAdd(rr, scopedAddReq("/api/v1/challenge/vhost/add?host=tenant-a.example.com&ttl=1h&rung=v2"))
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped v2 arm failed: %d: %s", rr.Code, rr.Body.String())
	}

	evs, err := hs.QueryEvents("tenant-a.example.com", "", "challenge_vhost_manual_on", 5)
	if err != nil || len(evs) != 1 {
		t.Fatalf("manual_on events: %v (err=%v)", evs, err)
	}
	if got := evs[0].Payload["rung"]; got != "v2" {
		t.Fatalf("manual_on payload rung = %#v, want v2", got)
	}
	if got := evs[0].Payload["actor"]; got != "scoped" {
		t.Fatalf("manual_on payload actor = %#v, want scoped", got)
	}

	// Admin disarm (nil scope) records actor=admin.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/remove?host=tenant-a.example.com", nil)
	rr = httptest.NewRecorder()
	e.handleChallengeVhostRemove(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin remove failed: %d: %s", rr.Code, rr.Body.String())
	}
	evs, err = hs.QueryEvents("tenant-a.example.com", "", "challenge_vhost_manual_off", 5)
	if err != nil || len(evs) != 1 {
		t.Fatalf("manual_off events: %v (err=%v)", evs, err)
	}
	if got := evs[0].Payload["actor"]; got != "admin" {
		t.Fatalf("manual_off payload actor = %#v, want admin", got)
	}

	// The legacy wrapper (internal callers) records rung but no actor key.
	e.ManualChallengeVhost("internal.example.com", time.Hour, "manual", "")
	evs, _ = hs.QueryEvents("internal.example.com", "", "challenge_vhost_manual_on", 5)
	if len(evs) != 1 {
		t.Fatalf("wrapper manual_on events: %v", evs)
	}
	if got := evs[0].Payload["rung"]; got != "v1" {
		t.Fatalf("wrapper payload rung = %#v, want explicit v1", got)
	}
	if _, ok := evs[0].Payload["actor"]; ok {
		t.Fatalf("wrapper must not fabricate an actor, got %#v", evs[0].Payload["actor"])
	}
}

// ── Slice D security review folds: reason sanitization + attack audit ────────

func TestSanitizeAuditReason(t *testing.T) {
	if got := sanitizeAuditReason("panic-button"); got != "panic-button" {
		t.Fatalf("plain reason mangled: %q", got)
	}
	// CR/LF and control chars must never survive into the flat audit logs —
	// `reason="x\n...actor=admin"` was the review's forgery payload (I1).
	if got := sanitizeAuditReason("x\n2026 [challenge][vhost] actor=admin\r\x00y"); got != "x2026 [challenge][vhost] actor=adminy" {
		t.Fatalf("control chars survived: %q", got)
	}
	if got := sanitizeAuditReason(strings.Repeat("a", 500)); len(got) > 200 {
		t.Fatalf("cap not applied: len=%d", len(got))
	}
}

func TestManualChallengeReasonSanitizedAtInputBoundary(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}
	e.manualChal.init("")

	rr := httptest.NewRecorder()
	e.handleChallengeVhostAdd(rr, scopedAddReq("/api/v1/challenge/vhost/add?host=tenant-a.example.com&ttl=1h&reason="+
		"evil%0Aaction%3Dmanual_off%20actor%3Dadmin"))
	if rr.Code != http.StatusOK {
		t.Fatalf("arm failed: %d: %s", rr.Code, rr.Body.String())
	}
	evs, err := hs.QueryEvents("tenant-a.example.com", "", "challenge_vhost_manual_on", 5)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events: %v (err=%v)", evs, err)
	}
	if strings.ContainsAny(evs[0].Reason, "\r\n") {
		t.Fatalf("newline survived into the audit reason: %q", evs[0].Reason)
	}
}

func TestAttackOverrideIsAudited(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs, cfg: Config{UnderAttack: true}}
	e.manualChal.init("")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?host=tenant-a.example.com&on=1", nil)
	ctx := context.WithValue(req.Context(), CtxRoleKey{}, CtxRoleScoped)
	ctx = context.WithValue(ctx, CtxScopeKey{}, map[string]struct{}{"tenant-a.example.com": {}})
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req.WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("attack override failed: %d: %s", rr.Code, rr.Body.String())
	}
	evs, err := hs.QueryEvents("tenant-a.example.com", "", "challenge_vhost_attack_override", 5)
	if err != nil || len(evs) != 1 {
		t.Fatalf("attack override left no audit event (review I3): %v (err=%v)", evs, err)
	}
	if evs[0].Payload["actor"] != "scoped" || evs[0].Payload["on"] != true {
		t.Fatalf("audit payload wrong: %#v", evs[0].Payload)
	}
	if evs[0].Reason != "attack_forced" {
		t.Fatalf("audit reason = %q, want attack_forced", evs[0].Reason)
	}
}
