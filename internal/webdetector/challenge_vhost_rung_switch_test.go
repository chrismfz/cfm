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

// POST /api/v1/challenge/vhost/rung — switch an ARMED manual challenge between
// v1 and v2 without re-arming it: expiry, granted TTL and reason are kept, the
// verify gate's lookup flips immediately, and nothing is created or extended.

func rungReq(t *testing.T, e *Engine, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	e.handleChallengeVhostRung(rr, r)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

func TestHandleChallengeVhostRung_SwitchKeepsExpiryAndReason(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	e.manualChal.set("shop.gr", 2*time.Hour, "panic-button", "")
	_, expBefore, _ := e.manualChal.active("shop.gr")

	rr, body := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=shop.gr&rung=v2", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("switch to v2: %d %s", rr.Code, rr.Body.String())
	}
	if body["rung"] != "v2" || body["from"] != "v1" || body["host"] != "shop.gr" {
		t.Fatalf("response: %v", body)
	}
	if got := e.manualChallengeRung("shop.gr"); got != "v2" {
		t.Fatalf("verify-side rung = %q, want v2", got)
	}
	ok, expAfter, reason := e.manualChal.active("shop.gr")
	if !ok || !expAfter.Equal(expBefore) || reason != "panic-button" {
		t.Fatalf("re-tier must keep expiry+reason: ok=%v exp %v→%v reason=%q", ok, expBefore, expAfter, reason)
	}

	// And back down — an explicit v1 is the operator saying so.
	rr, body = rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=shop.gr&rung=v1", nil))
	if rr.Code != http.StatusOK || body["rung"] != "v1" || body["from"] != "v2" {
		t.Fatalf("switch to v1: %d %v", rr.Code, body)
	}
	if got := e.manualChallengeRung("shop.gr"); got != "" {
		t.Fatalf("verify-side rung after v1 = %q, want plain", got)
	}
}

func TestHandleChallengeVhostRung_WWWRetiersTheCoveringApex(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	e.manualChal.set("shop.gr", time.Hour, "manual", "")
	rr, body := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=www.shop.gr&rung=v2", nil))
	if rr.Code != http.StatusOK || body["host"] != "shop.gr" {
		t.Fatalf("www must re-tier the apex arm that covers it: %d %v", rr.Code, body)
	}
	if e.manualChallengeRung("www.shop.gr") != "v2" {
		t.Fatalf("www not covered by the re-tiered apex")
	}
}

func TestHandleChallengeVhostRung_Refusals(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	// No manual arm (e.g. auto-only): 409, and nothing is created.
	rr, _ := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=auto.gr&rung=v2", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("no manual arm: %d, want 409", rr.Code)
	}
	if ok, _, _ := e.manualChal.active("auto.gr"); ok {
		t.Fatalf("re-tier must never create an arm")
	}

	// An expired arm is not re-tiered (never resurrected).
	e.manualChal.set("old.gr", time.Hour, "manual", "")
	e.manualChal.mu.Lock()
	ent := e.manualChal.vhosts["old.gr"]
	ent.ExpiresAt = time.Now().Add(-time.Second)
	e.manualChal.vhosts["old.gr"] = ent
	e.manualChal.mu.Unlock()
	if rr, _ := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=old.gr&rung=v2", nil)); rr.Code != http.StatusConflict {
		t.Fatalf("expired arm: %d, want 409", rr.Code)
	}

	e.manualChal.set("shop.gr", time.Hour, "manual", "")
	for name, qs := range map[string]string{
		"missing host": "rung=v2",
		"missing rung": "host=shop.gr",
		"bad rung":     "host=shop.gr&rung=v3",
		"wildcard v2":  "host=*.shop.gr&rung=v2",
	} {
		if rr, _ := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?"+qs, nil)); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rr.Code)
		}
	}
	if e.manualChallengeRung("shop.gr") != "" {
		t.Fatalf("a refused request changed the tier")
	}

	// Scope: a tenant re-tiers its own vhost, never another one.
	e.manualChal.set("tenant-a.example.com", time.Hour, "manual", "")
	e.manualChal.set("tenant-b.example.com", time.Hour, "manual", "")
	if rr, _ := rungReq(t, e, scopedAddReq("/api/v1/challenge/vhost/rung?host=tenant-b.example.com&rung=v2")); rr.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope re-tier: %d, want 403", rr.Code)
	}
	if rr, _ := rungReq(t, e, scopedAddReq("/api/v1/challenge/vhost/rung?host=tenant-a.example.com&rung=v2")); rr.Code != http.StatusOK {
		t.Fatalf("in-scope re-tier: %d", rr.Code)
	}
}

func TestHandleChallengeVhostRung_JSONBodyAndAudit(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}
	e.manualChal.init("")
	e.manualChal.set("tenant-a.example.com", time.Hour, "manual", "")

	req := scopedAddReq("/api/v1/challenge/vhost/rung")
	jreq := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung",
		strings.NewReader(`{"host":"tenant-a.example.com","rung":"challenge_v2"}`)).WithContext(req.Context())
	jreq.Header.Set("Content-Type", "application/json")
	if rr, body := rungReq(t, e, jreq); rr.Code != http.StatusOK || body["rung"] != "v2" {
		t.Fatalf("json re-tier: %d %v", rr.Code, body)
	}
	evs, err := hs.QueryEvents("tenant-a.example.com", "", "challenge_vhost_manual_rung", 5)
	if err != nil || len(evs) != 1 {
		t.Fatalf("rung events: %v (err=%v)", evs, err)
	}
	p := evs[0].Payload
	if p["from"] != "v1" || p["rung"] != "v2" || p["actor"] != "scoped" {
		t.Fatalf("audit payload: %v", p)
	}
}

// ── Review folds ─────────────────────────────────────────────────────────────

// The most specific arm wins for the verify-side tier, including a PLAIN one:
// a www host with its own v1 arm is v1 even under a v2 apex, so re-tiering
// the www arm reports exactly what the gate will enforce.
func TestManualChallengeRung_MostSpecificArmWins(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	e.manualChal.set("example.com", time.Hour, "manual", "v2")
	e.manualChal.set("www.example.com", time.Hour, "manual", "")
	if got := e.manualChallengeRung("www.example.com"); got != "" {
		t.Fatalf("www's own v1 arm must win over the v2 apex, got %q", got)
	}
	if got := e.manualChallengeRung("example.com"); got != "v2" {
		t.Fatalf("apex: %q", got)
	}
	// Re-tiering www changes www — and the gate follows.
	rr, body := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=www.example.com&rung=v2", nil))
	if rr.Code != http.StatusOK || body["host"] != "www.example.com" || body["changed"] != true {
		t.Fatalf("www re-tier: %d %v", rr.Code, body)
	}
	if e.manualChallengeRung("www.example.com") != "v2" {
		t.Fatalf("gate did not follow the www re-tier")
	}
	rr, body = rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=www.example.com&rung=v1", nil))
	if rr.Code != http.StatusOK || e.manualChallengeRung("www.example.com") != "" {
		t.Fatalf("www back to v1 must be what the gate enforces: %d %v gate=%q", rr.Code, body, e.manualChallengeRung("www.example.com"))
	}
}

// A scoped token holding only www.example.com must not re-tier the APEX arm
// that covers it (fail-closed 403, nothing changed).
func TestHandleChallengeVhostRung_ScopeChecksTheResolvedTarget(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	e.manualChal.set("tenant-a.example.com", time.Hour, "manual", "v2") // apex of www.tenant-a.example.com
	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=www.tenant-a.example.com&rung=v1", nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxScopeKey{}, map[string]struct{}{"www.tenant-a.example.com": {}}))
	if rr, _ := rungReq(t, e, req); rr.Code != http.StatusForbidden {
		t.Fatalf("re-tier of an out-of-scope apex: %d, want 403", rr.Code)
	}
	if e.manualChallengeRung("tenant-a.example.com") != "v2" {
		t.Fatalf("a refused re-tier changed the apex arm")
	}
}

// Switching to the tier already set is a no-op: 200, changed=false, and no
// audit row — the trail records only real changes.
func TestHandleChallengeVhostRung_NoOpWritesNoAudit(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}
	e.manualChal.init("")
	e.manualChal.set("shop.gr", time.Hour, "manual", "v2")
	rr, body := rungReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/rung?host=shop.gr&rung=v2", nil))
	if rr.Code != http.StatusOK || body["changed"] != false || body["from"] != "v2" {
		t.Fatalf("no-op: %d %v", rr.Code, body)
	}
	if evs, _ := hs.QueryEvents("shop.gr", "", "challenge_vhost_manual_rung", 5); len(evs) != 0 {
		t.Fatalf("a no-op wrote %d audit rows", len(evs))
	}
}

// A manual arm reaches the bridge with the fixed reason "manual", never the
// caller's free text: that is what src=vhost:<reason> reads, and a tenant
// typing "suspicious_vhost" must not pass for an auto challenge.
func TestManualChallengeBridgeReasonIsFixed(t *testing.T) {
	b := NewNginxBridge(t.TempDir()+"/no-edge.sock", "tok", time.Minute, time.Minute)
	e := &Engine{nginxBridge: b}
	e.manualChal.init("")
	e.ManualChallengeVhost("shop.gr", time.Hour, "suspicious_vhost", "v2")
	b.mu.RLock()
	got := b.vhState["shop.gr"].Reason
	b.mu.RUnlock()
	if got != "manual" {
		t.Fatalf("bridge reason = %q, want manual", got)
	}
	if ok, _, reason := e.manualChal.active("shop.gr"); !ok || reason != "suspicious_vhost" {
		t.Fatalf("the operator's text must stay in the manual store: %v %q", ok, reason)
	}
}
