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
//   - record the rung mark the verify D5 gate ORs in — PER IP, like the
//     ipState decision it rides with (cfm.lua serves that challenge on every
//     web host the IP visits), and read for web-scope verifies only;
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
	// The decision is per IP, so the rung covers every web host of the IP —
	// including a sibling vhost the push did not name, where the client can
	// solve the same WAF-imposed challenge (2026-09-29: until then the mark
	// was per (ip,host) and that solve passed at v1).
	if !challengeV2MarkCovers("203.0.113.61", "shop.example", "web") {
		t.Fatalf("challenge_v2 push did not arm the rung on the host it named")
	}
	if !challengeV2MarkCovers("203.0.113.61", "other.example", "web") {
		t.Fatalf("challenge_v2 push did not arm the rung on a sibling web host of the IP")
	}
	if challengeV2MarkCovers("203.0.113.61", "other.example", "panel:2083") {
		t.Fatalf("a WAF mark must not reach a panel-scope verify")
	}
	if challengeV2MarkCovers("203.0.113.99", "shop.example", "web") {
		t.Fatalf("rung mark leaked to an IP the push did not name")
	}
	if challengeV2Marked("203.0.113.61", "shop.example") {
		t.Fatalf("the WAF writer must not write the traffic-rule (ip,host) store")
	}
	if gotAction != "challenge_v2" || gotReason != "WAF_XSS" {
		t.Fatalf("OnTrigger got (action=%q, reason=%q), want the verbatim (challenge_v2, WAF_XSS)", gotAction, gotReason)
	}
}

// The mark store canonicalizes its key (challengeV2MarkKey →
// normalizeClearanceHost): writers feed it normalizeHost output (lowercase +
// port strip) while the verify reader's host comes via normalizeClearanceHost
// (also trims a trailing dot, unbrackets IPv6) — without one shared
// normalizer a `Host: example.com.` write would silently miss the verify
// lookup and disarm v2 for that client (second-review finding).
func TestChallengeV2Mark_HostNormalizationConverges(t *testing.T) {
	resetChallengeV2Marks(t)

	MarkChallengeV2("203.0.113.70", "Example.COM.")
	if !challengeV2Marked("203.0.113.70", "example.com") {
		t.Fatalf("trailing-dot/case write must match the canonical verify lookup")
	}
	MarkChallengeV2("203.0.113.71", "shop.example:443")
	if !challengeV2Marked("203.0.113.71", "shop.example") {
		t.Fatalf("port-carrying write must match the portless verify lookup")
	}
	if challengeV2Marked("203.0.113.70", "other.example") {
		t.Fatalf("normalization must not widen the match")
	}
}

// The mark is keyed by IP alone, so a push without a host still arms the rung
// (it used to degrade to plain v1: an (ip,host) mark had nothing to key on).
func TestWAFPushChallengeV2_HostlessPushStillMarksTheIP(t *testing.T) {
	resetChallengeV2Marks(t)
	b := NewNginxBridge("/tmp/cfm-test-wafv2b.sock", "tok", time.Minute, time.Minute)

	code := postIPPush(t, b, `{"ip":"203.0.113.62","action":"challenge_v2","reason":"WAF_XSS","ttl_sec":600}`)
	if code != http.StatusOK {
		t.Fatalf("hostless challenge_v2 push rejected: code=%d", code)
	}
	b.mu.Lock()
	entry, ok := b.ipState["203.0.113.62"]
	b.mu.Unlock()
	if !ok || entry.Action != "challenge" {
		t.Fatalf("hostless v2 push must still challenge the IP (ok=%v action=%q)", ok, entry.Action)
	}
	if !challengeV2MarkCovers("203.0.113.62", "any.example", "web") {
		t.Fatalf("hostless v2 push must arm the rung for the IP")
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
	if !challengeV2MarkCovers("203.0.113.63", "blog.example", "web") ||
		!challengeV2MarkCovers("203.0.113.63", "other.example", "web") {
		t.Fatalf("batch v2 push did not arm the rung for the IP")
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

// The grain resolver and the waiver bar see a WAF (per-IP) mark on a web-scope
// verify only; a traffic-rule (ip,host) mark keeps its exact-pair scope.
func TestChallengeV2IPMark_GrainAndWaiverAreWebScopeOnly(t *testing.T) {
	resetChallengeV2Marks(t)
	MarkChallengeV2IP(" 203.0.113.80 ")

	if g, _ := challengeV2ArmGrainVia("", "203.0.113.80", "tenant-b.example", "web"); g != v2GrainMark {
		t.Fatalf("web verify on a sibling host: grain=%q, want %q", g, v2GrainMark)
	}
	if g, _ := challengeV2ArmGrainVia("", "203.0.113.80", "tenant-b.example", "panel:2083"); g != "" {
		t.Fatalf("panel verify: grain=%q, want unarmed", g)
	}
	if g, _ := challengeV2ArmGrainVia("", "203.0.113.81", "tenant-b.example", "web"); g != "" {
		t.Fatalf("unmarked IP: grain=%q, want unarmed", g)
	}
	// A geo/vhost arm is not good-bot-waivable while a WAF mark covers the
	// client: that challenge came from the WAF, which never softens for bots.
	if got := challengeV2WaiverBar(v2GrainVhost, "203.0.113.80", "tenant-b.example", "web"); got != v2WaiverMark {
		t.Fatalf("waiver bar under a WAF mark = %q, want %q", got, v2WaiverMark)
	}
	if got := challengeV2WaiverBar(v2GrainVhost, "203.0.113.80", "tenant-b.example", "panel:2083"); got != "" {
		t.Fatalf("waiver bar on a panel verify = %q, want waivable", got)
	}

	// A traffic-rule mark stays exact (ip,host), and web-scope too.
	MarkChallengeV2("203.0.113.82", "shop.example")
	if !challengeV2MarkCovers("203.0.113.82", "shop.example", "web") ||
		challengeV2MarkCovers("203.0.113.82", "other.example", "web") {
		t.Fatalf("traffic-rule mark scope changed")
	}
	if challengeV2MarkCovers("203.0.113.82", "shop.example", "panel:2083") {
		t.Fatalf("a web traffic-rule mark armed a panel-scope verify on the same host")
	}
	if challengeV2MarkCovers("203.0.113.80", "tenant-b.example", "") {
		t.Fatalf("an unknown scope must read as unarmed")
	}
}

// End to end: a v2-tier WAF push (host A = a bare server IP, like rule 602),
// then solves on a sibling vhost B and on a panel port. Before 2026-09-29 the
// failing B solve passed at v1, got a clearance, and released the IP's WAF
// decision on every host; a panel-scope solve released it too.
func TestVerify_WAFV2PushArmsSiblingVhostButNotPanel(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-wafv2e2e.sock", "tok", time.Minute, time.Minute)
	base, capt := startVerifyServerWithBridge(t, b)
	const (
		ip = "203.0.113.90"
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	)
	push := func() {
		t.Helper()
		if code := postIPPush(t, b, `{"ip":"`+ip+`","action":"challenge_v2","host":"84.54.49.44","uri":"/","reason":"WAF_IP_HOST","waf_rule_id":602,"ttl_sec":600}`); code != http.StatusOK {
			t.Fatalf("push rejected: %d", code)
		}
	}
	decided := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		_, ok := b.ipState[ip]
		return ok
	}
	failing := `{"v":1,"wd":true,"glr":"Google SwiftShader","ptr":0,"tch":0,"key":0}`
	panel := map[string]string{"X-CFM-Panel-Port": "2083", "X-Forwarded-Port": "2083"}
	push()

	// 1. Panel port: the WAF mark does not arm it (the failing solve passes,
	// unarmed, as before) — and it must not release the web decision.
	resp := postVerifyHdr(t, base, ip, "tenant.example.gr", ua, failing, panel)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("panel-scope verify was armed by a WAF mark: X-CFM-V2=%q", resp.Header.Get("X-CFM-V2"))
	}
	if solved, rejects := capt.counts(); solved != 1 || rejects != 0 {
		t.Fatalf("panel solve: solved=%d rejects=%d, want 1/0", solved, rejects)
	}
	if s := capt.solved[0]; s.V2Grain != "" || s.HumanityScore < defaultV2FailScore {
		t.Fatalf("panel solve: grain=%q hs=%d, want unarmed with a failing score", s.V2Grain, s.HumanityScore)
	}
	if !decided() {
		t.Fatalf("a panel-scope solve released the IP's web WAF decision")
	}

	// 2. Sibling web vhost, failing solve: rejected under the mark grain, and
	// nothing released.
	resp = postVerify(t, base, ip, "tenant.example.gr", ua, failing)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("failing solve on a sibling vhost: status=%d X-CFM-V2=%q, want 403 + reject",
			resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	if solved, rejects := capt.counts(); solved != 1 || rejects != 1 || capt.rejects[0].V2Grain != v2GrainMark {
		t.Fatalf("sibling reject: solved=%d rejects=%d %+v", solved, rejects, capt.rejects)
	}
	if !decided() {
		t.Fatalf("a rejected solve released the IP's WAF decision")
	}

	// 3. Sibling web vhost, clean solve: passes under the arm and releases.
	resp = postVerify(t, base, ip, "tenant.example.gr", ua, `{"v":1,"wd":false,"ptr":9,"tch":0,"key":1}`)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("clean solve on the sibling vhost was refused: X-CFM-V2=%q", resp.Header.Get("X-CFM-V2"))
	}
	if solved, _ := capt.counts(); solved != 2 || capt.solved[1].V2Grain != v2GrainMark || capt.solved[1].HumanityScore != 0 {
		t.Fatalf("clean sibling solve: solved=%d %+v, want the 2nd solve armed (mark) and clean", solved, capt.solved)
	}
	if decided() {
		t.Fatalf("a web-scope solve did not release the IP's decision")
	}
}
