package webdetector

import (
	"context"
	"encoding/json"
	"fmt"
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

// ── Every attack override is TTL-bound ────────────────────────────────────────
// Operator decisions: 2026-09-22, a scoped forced-ON override expires like the
// panic-button arm (24h ceiling); 2026-11-17, every override holds for a TTL
// (the call's ttl, else UNDER_ATTACK_OVERRIDE_TTL, 6h) and arms the vhost's
// challenge for the same window. Expiry is honoured by the tick AND the read
// path, and the response/audit carry the bound.

func attackRequest(t *testing.T, e *Engine, query string, scopedHost string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?"+query, nil)
	if scopedHost != "" {
		ctx := context.WithValue(req.Context(), CtxRoleKey{}, CtxRoleScoped)
		ctx = context.WithValue(ctx, CtxScopeKey{}, map[string]struct{}{scopedHost: {}})
		req = req.WithContext(ctx)
	}
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("attack %s: %d: %s", query, rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	return resp
}

func overrideExpiry(e *Engine, host string) time.Time {
	e.attack.mu.Lock()
	defer e.attack.mu.Unlock()
	return e.attack.hosts[host].overrideExpires
}

func TestAttackOverrideScopedTTLBound(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs, cfg: Config{UnderAttack: true}, attack: newUnderAttackTracker(), attackOverrides: newAttackOverrideStore("")}
	e.manualChal.init("")

	// Asked for more than the ceiling: capped at 24h, and said so.
	resp := attackRequest(t, e, "host=tenant-a.example.com&on=1&ttl=48h", "tenant-a.example.com")
	if resp["ttl"] != scopedMaxChallengeTTL.String() || resp["ttl_capped"] != true {
		t.Fatalf("scoped override: ttl=%#v capped=%#v, want %q capped", resp["ttl"], resp["ttl_capped"], scopedMaxChallengeTTL.String())
	}
	if _, ok := resp["expires_at"]; !ok {
		t.Fatalf("scoped override response missing expires_at")
	}
	evs, _ := hs.QueryEvents("tenant-a.example.com", "", "challenge_vhost_attack_override", 5)
	if len(evs) != 1 || evs[0].Payload["ttl_sec"] == nil {
		t.Fatalf("audit must carry ttl_sec for a bounded override: %#v", evs)
	}
	if exp := overrideExpiry(e, "tenant-a.example.com"); exp.IsZero() || time.Until(exp) > scopedMaxChallengeTTL+time.Minute {
		t.Fatalf("override expiry not bounded: %v", exp)
	}

	// The arm it made is capped with it.
	if _, armExp, _ := e.manualChal.active("tenant-a.example.com"); time.Until(armExp) > scopedMaxChallengeTTL+time.Minute {
		t.Fatalf("scoped arm not capped: expires in %v", time.Until(armExp))
	}

	// No ttl: the default (6h), under the ceiling, not capped.
	resp = attackRequest(t, e, "host=tenant-a.example.com&on=1", "tenant-a.example.com")
	if resp["ttl"] != defaultAttackOverrideTTL.String() || resp["ttl_capped"] != nil {
		t.Fatalf("scoped default: ttl=%#v capped=%#v", resp["ttl"], resp["ttl_capped"])
	}
}

func TestAttackOverrideAdminDefaultTTL(t *testing.T) {
	e := &Engine{cfg: Config{UnderAttack: true}, attack: newUnderAttackTracker(), attackOverrides: newAttackOverrideStore("")}
	e.manualChal.init("")

	resp := attackRequest(t, e, "host=any.example.com&on=1", "")
	if resp["ttl"] != defaultAttackOverrideTTL.String() {
		t.Fatalf("admin override with no ttl: %#v, want the %s default", resp["ttl"], defaultAttackOverrideTTL)
	}
	exp := overrideExpiry(e, "any.example.com")
	if d := time.Until(exp); d <= 0 || d > defaultAttackOverrideTTL+time.Minute {
		t.Fatalf("admin override expiry = %v (in %v)", exp, d)
	}
	// An explicit ttl is honoured, uncapped for an admin.
	resp = attackRequest(t, e, "host=any.example.com&on=1&ttl=48h", "")
	if resp["ttl"] != (48*time.Hour).String() || resp["ttl_capped"] != nil {
		t.Fatalf("admin ttl=48h: %#v", resp)
	}
	// A bad ttl is refused.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?host=any.example.com&on=1&ttl=-1h", nil)
	rr := httptest.NewRecorder()
	e.handleChallengeVhostAttack(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("ttl=-1h: status %d, want 400", rr.Code)
	}
}

func TestAttackOverrideExpiryReadsAsAuto(t *testing.T) {
	e := &Engine{cfg: Config{UnderAttack: true}, attack: newUnderAttackTracker()}

	// A bounded override whose window has already passed must read as the
	// AUTO state (off here) without waiting for a tick.
	e.SetVhostAttackOverride("shop.example", true, time.Now().Add(-2*time.Hour), time.Hour)
	on, _, _ := e.VhostAttackState("shop.example")
	if on {
		t.Fatalf("expired bounded override must read as auto (off), got forced-on")
	}

	// A live bounded override still reads forced-on.
	e.SetVhostAttackOverride("live.example", true, time.Now(), time.Hour)
	on, _, _ = e.VhostAttackState("live.example")
	if !on {
		t.Fatalf("live bounded override must read forced-on")
	}
}

// Refused: a wildcard host (400) and an `on` for a cfm.allow-bypassed vhost
// (409, the next tick would undo it).
func TestAttackOverrideRefusesWildcardAndBypassed(t *testing.T) {
	e := &Engine{cfg: Config{UnderAttack: true, ChallengeHostBypass: []string{"allowed.example.com"}},
		attack: newUnderAttackTracker(), attackOverrides: newAttackOverrideStore("")}
	e.manualChal.init("")
	for _, tc := range []struct {
		q    string
		code int
	}{
		{"host=*.example.com&on=1", http.StatusBadRequest},
		{"host=allowed.example.com&on=1", http.StatusConflict},
		{"host=allowed.example.com.&on=1", http.StatusConflict},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/attack?"+tc.q, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostAttack(rr, req)
		if rr.Code != tc.code {
			t.Errorf("%s: status %d, want %d", tc.q, rr.Code, tc.code)
		}
	}
	if active, _, _ := e.manualChal.active("allowed.example.com"); active {
		t.Error("a bypassed vhost was armed")
	}
}

// An operator's challenge that ends sooner cuts the override (it never
// outlives the challenge it rides on), and the response says so.
func TestAttackOverrideClippedToAShorterOperatorChallenge(t *testing.T) {
	e := &Engine{cfg: Config{UnderAttack: true}, attack: newUnderAttackTracker(), attackOverrides: newAttackOverrideStore("")}
	e.manualChal.init("")
	e.ManualChallengeVhostAs("shop.example.com", 30*time.Minute, "manual", "", "admin")
	resp := attackRequest(t, e, "host=shop.example.com&on=1&ttl=6h", "")
	if resp["challenge_armed"] != false || resp["ttl_clipped"] != true || resp["challenge_expires_at"] == nil || resp["tier"] == nil {
		t.Fatalf("response: %#v", resp)
	}
	if d, err := time.ParseDuration(fmt.Sprint(resp["ttl"])); err != nil || d > 30*time.Minute {
		t.Fatalf("response ttl %v after the clip, want <= 30m", resp["ttl"])
	}
	_, chExp, _ := e.manualChal.active("shop.example.com")
	if d := overrideExpiry(e, "shop.example.com").Sub(chExp); d > time.Second || d < -time.Second {
		t.Fatalf("override ends %v after the challenge", d)
	}
}
