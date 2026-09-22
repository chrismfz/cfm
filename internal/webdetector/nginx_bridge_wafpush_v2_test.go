package webdetector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Slice C (WAF rule tier challenge_v2): a cfm_waf.lua push with
// action="challenge_v2" must
//   - store a plain "challenge" IP decision (the edge wire vocabulary cfm.lua
//     Step 3 enforces — an unknown action there falls through to allow);
//   - record the per-(ip,host) rung mark the verify D5 gate ORs in;
//   - hand the VERBATIM "challenge_v2" to OnTrigger, so cfm.waf.log, the
//     waf_trigger history row and the WAFHitEvent carry the real tier (and
//     wafsec's action=="block" filter keeps autoblock un-keyed on it).

func postIPPush(t *testing.T, b *NginxBridge, body string) int {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/nginx/ip", strings.NewReader(body))
	req.Header.Set("X-CFM-Token", "tok")
	b.handleIPPush(rr, req)
	return rr.Code
}

func TestWAFPushChallengeV2_StoresChallengeAndMarks(t *testing.T) {
	resetChallengeV2Marks(t)
	b := NewNginxBridge("/tmp/cfm-test-wafv2.sock", "tok", time.Minute, time.Minute)

	var gotAction, gotReason string
	b.SetTriggerHook(func(_, action, reason string, _ time.Duration, _, _, _ string, _ int, _, _, _, _ string) {
		gotAction, gotReason = action, reason
	})

	code := postIPPush(t, b, `{"ip":"203.0.113.61","action":"challenge_v2","host":"shop.example","uri":"/page?q=1","method":"get","reason":"WAF_XSS","waf_rule_id":302,"ttl_sec":600}`)
	if code != http.StatusOK {
		t.Fatalf("challenge_v2 push rejected: code=%d", code)
	}

	b.mu.Lock()
	entry, ok := b.ipState["203.0.113.61"]
	b.mu.Unlock()
	if !ok {
		t.Fatalf("challenge_v2 push stored no IP decision")
	}
	if entry.Action != "challenge" {
		t.Fatalf("ipState action = %q, want the wire-normalized %q", entry.Action, "challenge")
	}
	if !challengeV2Marked("203.0.113.61", "shop.example") {
		t.Fatalf("challenge_v2 push did not record the (ip,host) rung mark")
	}
	if challengeV2Marked("203.0.113.61", "other.example") {
		t.Fatalf("rung mark leaked to a host the push did not name")
	}
	if gotAction != "challenge_v2" || gotReason != "WAF_XSS" {
		t.Fatalf("OnTrigger got (action=%q, reason=%q), want the verbatim (challenge_v2, WAF_XSS)", gotAction, gotReason)
	}
}

func TestWAFPushChallengeV2_EmptyHostDegradesToPlainChallenge(t *testing.T) {
	resetChallengeV2Marks(t)
	b := NewNginxBridge("/tmp/cfm-test-wafv2b.sock", "tok", time.Minute, time.Minute)

	code := postIPPush(t, b, `{"ip":"203.0.113.62","action":"challenge_v2","reason":"WAF_XSS","ttl_sec":600}`)
	if code != http.StatusOK {
		t.Fatalf("hostless challenge_v2 push rejected: code=%d", code)
	}
	b.mu.Lock()
	entry, ok := b.ipState["203.0.113.62"]
	b.mu.Unlock()
	challengeV2Marks.mu.Lock()
	markCount := len(challengeV2Marks.m)
	challengeV2Marks.mu.Unlock()
	if !ok || entry.Action != "challenge" {
		t.Fatalf("hostless v2 push must still challenge the IP (ok=%v action=%q)", ok, entry.Action)
	}
	if markCount != 0 {
		t.Fatalf("hostless v2 push must not write a rung mark (fail-open to v1), got %d marks", markCount)
	}
}

func TestWAFPushBatchChallengeV2_SameMapping(t *testing.T) {
	resetChallengeV2Marks(t)
	b := NewNginxBridge("/tmp/cfm-test-wafv2c.sock", "tok", time.Minute, time.Minute)

	var gotAction string
	b.SetTriggerHook(func(_, action, _ string, _ time.Duration, _, _, _ string, _ int, _, _, _, _ string) {
		gotAction = action
	})

	rr := httptest.NewRecorder()
	body := `{"events":[{"p":"/nginx/ip","b":"{\"ip\":\"203.0.113.63\",\"action\":\"challenge_v2\",\"host\":\"blog.example\",\"reason\":\"WAF_XSS\",\"ttl_sec\":600}"}]}`
	req := httptest.NewRequest(http.MethodPost, "/nginx/events", strings.NewReader(body))
	req.Header.Set("X-CFM-Token", "tok")
	b.handleEventsBatch(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("batch challenge_v2 push rejected: code=%d body=%s", rr.Code, rr.Body.String())
	}

	b.mu.Lock()
	entry, ok := b.ipState["203.0.113.63"]
	b.mu.Unlock()
	if !ok || entry.Action != "challenge" {
		t.Fatalf("batch v2 push: ipState (ok=%v action=%q), want challenge", ok, entry.Action)
	}
	if !challengeV2Marked("203.0.113.63", "blog.example") {
		t.Fatalf("batch v2 push did not record the rung mark")
	}
	if gotAction != "challenge_v2" {
		t.Fatalf("batch OnTrigger action = %q, want verbatim challenge_v2", gotAction)
	}
}

// RecordWAFTrigger publishes the verbatim tier: subscribers see
// action=="challenge_v2", and a wafsec-style `!= "block"` filter drops it —
// the doctrine gate that keeps challenge-tier hits out of autoblock.
func TestRecordWAFTriggerChallengeV2_EventCarriesTierAndWafsecFilterDrops(t *testing.T) {
	e := &Engine{}

	// SubscribeWAFHitEvents has no unsubscribe (production subscribers live
	// for the process), so guard the capture with an active flag: publishes
	// from later tests in this package must not touch our slice.
	var (
		mu     sync.Mutex
		active = true
		got    []WAFHitEvent
	)
	t.Cleanup(func() { mu.Lock(); active = false; mu.Unlock() })
	SubscribeWAFHitEvents(func(ev WAFHitEvent) {
		mu.Lock()
		defer mu.Unlock()
		if active {
			got = append(got, ev)
		}
	})

	e.RecordWAFTrigger("203.0.113.64", "shop.example", "/p", "get", "challenge_v2",
		"WAF_XSS", 10*time.Minute, 0, "", "", "", 302, "ua", "", "", "")

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("expected 1 WAFHitEvent, got %d", len(got))
	}
	// Carrying the verbatim tier is also what keeps the hit out of autoblock:
	// the Phase-1 wafsec subscribe filter (waf_security_register.go) drops
	// every event whose Action != "block".
	if got[0].Action != "challenge_v2" {
		t.Fatalf("WAFHitEvent action = %q, want challenge_v2", got[0].Action)
	}
}
