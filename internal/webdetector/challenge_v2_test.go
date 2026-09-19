package webdetector

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func boolp(b bool) *bool { return &b }
func intp(i int) *int    { return &i }

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
const androidUA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36"

// The D5(b) invariants: absence never convicts; only positive evidence opens a
// score; the no-input amplifier can never open one on its own.
func TestScoreHumanity_AbsenceNeverConvicts(t *testing.T) {
	if hs, tells := scoreHumanity(nil, chromeUA); hs != 0 || len(tells) != 0 {
		t.Fatalf("no payload must score 0, got hs=%d tells=%v", hs, tells)
	}
	// A privacy browser reporting nothing at all (every pointer field nil).
	if hs, _ := scoreHumanity(&humanitySignals{V: 1}, chromeUA); hs != 0 {
		t.Fatalf("all-absent report must score 0, got %d", hs)
	}
	// Keyboard-only user: zero pointer/touch, real keys, nothing else odd —
	// and even with zero keys too, no_input alone must NOT open a score.
	sig := &humanitySignals{V: 1, PTR: intp(0), TCH: intp(0), KEY: intp(0), MTP: intp(0), OW: intp(1200), OH: intp(800)}
	if hs, tells := scoreHumanity(sig, chromeUA); hs != 0 {
		t.Fatalf("no_input must never open a score (D5b), got hs=%d tells=%v", hs, tells)
	}
	// Desktop UA with maxTouchPoints 0 is normal, not a touch lie.
	if hs, _ := scoreHumanity(&humanitySignals{V: 1, MTP: intp(0)}, chromeUA); hs != 0 {
		t.Fatalf("mtp=0 on a desktop UA must not score, got %d", hs)
	}
}

func TestScoreHumanity_PositiveOpeners(t *testing.T) {
	fail := defaultV2FailScore

	// Certain evidence fails alone.
	if hs, tells := scoreHumanity(&humanitySignals{V: 1, WD: boolp(true)}, chromeUA); hs < fail || tells[0] != "webdriver" {
		t.Fatalf("webdriver must fail alone: hs=%d tells=%v", hs, tells)
	}
	if hs, tells := scoreHumanity(nil, strings.Replace(chromeUA, "Chrome/", "HeadlessChrome/", 1)); hs < fail || tells[0] != "headless_ua" {
		t.Fatalf("HeadlessChrome UA must fail alone (no payload needed): hs=%d tells=%v", hs, tells)
	}

	// A single medium opener PASSES — the RDP/VDI user (sw renderer alone).
	rdp := &humanitySignals{V: 1, GLR: "Google SwiftShader"}
	if hs, tells := scoreHumanity(rdp, chromeUA); hs >= fail || len(tells) != 1 || tells[0] != "sw_renderer" {
		t.Fatalf("sw_renderer alone must pass (real RDP users): hs=%d tells=%v", hs, tells)
	}
	// touch lie alone passes; outer_zero alone passes.
	if hs, _ := scoreHumanity(&humanitySignals{V: 1, MTP: intp(0)}, androidUA); hs >= fail {
		t.Fatalf("touch_lie alone must pass, got %d", hs)
	}
	if hs, _ := scoreHumanity(&humanitySignals{V: 1, OW: intp(0), OH: intp(0)}, chromeUA); hs >= fail {
		t.Fatalf("outer_zero alone must pass, got %d", hs)
	}

	// Corroborated combinations fail: the classic headless shape.
	headless := &humanitySignals{
		V: 1, GLR: "llvmpipe (LLVM 15.0.7, 256 bits)",
		OW: intp(0), OH: intp(0),
		PTR: intp(0), TCH: intp(0), KEY: intp(0),
	}
	hs, tells := scoreHumanity(headless, chromeUA)
	if hs < fail {
		t.Fatalf("sw_renderer+outer_zero+no_input must fail: hs=%d tells=%v", hs, tells)
	}
	joined := strings.Join(tells, ",")
	for _, want := range []string{"sw_renderer", "outer_zero", "no_input"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing tell %q in %v", want, tells)
		}
	}
	// But sw_renderer + no_input alone (an RDP user who didn't move the mouse)
	// stays under the line: 60+30=90.
	rdpIdle := &humanitySignals{V: 1, GLR: "SwiftShader", PTR: intp(0), TCH: intp(0), KEY: intp(0)}
	if hs, _ := scoreHumanity(rdpIdle, chromeUA); hs >= fail {
		t.Fatalf("idle RDP user must pass: hs=%d", hs)
	}
}

func TestParseHumanityBody(t *testing.T) {
	if parseHumanityBody(nil) != nil || parseHumanityBody([]byte("")) != nil {
		t.Fatalf("empty body must parse to nil")
	}
	if parseHumanityBody([]byte("not json")) != nil {
		t.Fatalf("garbage must parse to nil")
	}
	sig := parseHumanityBody([]byte(`{"v":1,"wd":false,"mtp":5,"future_field":true}`))
	if sig == nil || sig.WD == nil || *sig.WD || sig.MTP == nil || *sig.MTP != 5 {
		t.Fatalf("tolerant parse failed: %+v", sig)
	}
}

// Pins the slice-3 review finding: the verify preamble must KEEP the body
// bytes for scoring (drain-to-Discard-then-parse silently killed every
// body-borne tell), while still fully consuming/closing the body and
// degrading an over-cap read to "no payload".
func TestReadVerifyBodyKeepsPayload(t *testing.T) {
	payload := `{"v":1,"wd":true}`
	r := httptest.NewRequest("POST", "/__cfm_verify", strings.NewReader(payload))
	w := httptest.NewRecorder()

	b := readVerifyBody(w, r)
	if string(b) != payload {
		t.Fatalf("body not kept: %q", b)
	}
	if sig := parseHumanityBody(b); sig == nil || sig.WD == nil || !*sig.WD {
		t.Fatalf("kept body must parse: %+v", sig)
	}
	// Fully consumed: a second read yields nothing.
	if rest, _ := io.ReadAll(r.Body); len(rest) != 0 {
		t.Fatalf("body not drained, %d bytes left", len(rest))
	}

	// Over-cap → nil ("no payload"), never partial evidence.
	big := httptest.NewRequest("POST", "/__cfm_verify", strings.NewReader(strings.Repeat("x", maxVerifyBodyBytes+10)))
	if b := readVerifyBody(httptest.NewRecorder(), big); b != nil {
		t.Fatalf("over-cap body must read as no payload, got %d bytes", len(b))
	}
}

// The D5(a) scope gate: the same failing score is teeth for an armed
// challenge_v2 fingerprint and shadow for everyone else — exercised at the
// policy-store level the verify handler consults.
func TestChallengeV2GateScope(t *testing.T) {
	resetFPPolicies(t)
	id := fpTestID(t)

	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("unarmed fp must have no action, got %q", got)
	}
	SetFingerprintPolicies([]FingerprintPolicy{{ID: id, Action: "challenge_v2"}})
	if got := FingerprintPolicyForID(id); got != "challenge_v2" {
		t.Fatalf("armed fp: got %q", got)
	}
}

func TestHumanitySuffix(t *testing.T) {
	if s := (ChallengeSolve{HumanityScore: -1}).HumanitySuffix(); s != "" {
		t.Fatalf("disabled rung must render nothing, got %q", s)
	}
	if s := (ChallengeSolve{HumanityScore: 0}).HumanitySuffix(); s != " hs=0" {
		t.Fatalf("clean solve: got %q", s)
	}
	if s := (ChallengeSolve{HumanityScore: 0, HumanityNoPayload: true}).HumanitySuffix(); s != " hs=-" {
		t.Fatalf("no-payload solve must be distinguishable from scored-clean, got %q", s)
	}
	// A UA-borne tell can fire WITH no payload: the real score wins over the dash.
	if s := (ChallengeSolve{HumanityScore: 100, HumanityTells: "headless_ua", HumanityNoPayload: true}).HumanitySuffix(); s != " hs=100 tells=headless_ua" {
		t.Fatalf("no-payload with a fired tell must show the score, got %q", s)
	}
	if s := (ChallengeSolve{HumanityScore: 130, HumanityTells: "sw_renderer,outer_zero,no_input"}).HumanitySuffix(); s != " hs=130 tells=sw_renderer,outer_zero,no_input" {
		t.Fatalf("failing solve: got %q", s)
	}
}
