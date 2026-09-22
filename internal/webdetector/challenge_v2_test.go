package webdetector

import (
	"io"
	"math"
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
	if s := (ChallengeSolve{}).HumanitySuffix(); s != "" {
		t.Fatalf("an UNSCORED solve (zero value) must render nothing, got %q", s)
	}
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 0}).HumanitySuffix(); s != " hs=0" {
		t.Fatalf("clean solve: got %q", s)
	}
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 0, HumanityNoPayload: true}).HumanitySuffix(); s != " hs=-" {
		t.Fatalf("no-payload solve must be distinguishable from scored-clean, got %q", s)
	}
	// A UA-borne tell can fire WITH no payload: the real score wins over the dash.
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 100, HumanityTells: "headless_ua", HumanityNoPayload: true}).HumanitySuffix(); s != " hs=100 tells=headless_ua" {
		t.Fatalf("no-payload with a fired tell must show the score, got %q", s)
	}
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 130, HumanityTells: "sw_renderer,outer_zero,no_input"}).HumanitySuffix(); s != " hs=130 tells=sw_renderer,outer_zero,no_input" {
		t.Fatalf("failing solve: got %q", s)
	}
	// D5d: an ARMED solve that passes must be distinguishable from a plain v1
	// one — otherwise a live tier reads as a forgotten one in the log.
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 0, V2Grain: v2GrainMark}).HumanitySuffix(); s != " hs=0 v2=mark" {
		t.Fatalf("armed clean solve must name its grain, got %q", s)
	}
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 0, HumanityNoPayload: true, V2Grain: v2GrainFP}).HumanitySuffix(); s != " hs=- v2=fp" {
		t.Fatalf("armed no-payload solve must name its grain, got %q", s)
	}
	if s := (ChallengeSolve{HumanityScored: true, HumanityScore: 100, HumanityTells: "webdriver", V2Grain: v2GrainVhost}).HumanitySuffix(); s != " hs=100 tells=webdriver v2=vhost" {
		t.Fatalf("armed failing solve: got %q", s)
	}
	// "Never scored" wins over everything: a literal that did not go through
	// verify cannot claim a score, even with a stale grain along for the ride.
	if s := (ChallengeSolve{V2Grain: v2GrainGeo}).HumanitySuffix(); s != "" {
		t.Fatalf("unscored solve must render nothing even with a grain, got %q", s)
	}
}

// TestChallengeV2ArmGrain pins the D5a predicate the verify gate and the solve
// line now SHARE: which grains arm, in which precedence, and that an unarmed
// solve names none (teeth only where an operator armed — the whole point).
func TestChallengeV2ArmGrain(t *testing.T) {
	resetFPPolicies(t)
	resetChallengeV2Marks(t)
	id := fpTestID(t)

	// Nothing armed anywhere.
	if got := challengeV2ArmGrain(id, "203.0.113.5", "shop.gr"); got != "" {
		t.Fatalf("unarmed solve must report no grain, got %q", got)
	}

	// mark (lowest precedence) alone.
	MarkChallengeV2("203.0.113.5", "shop.gr")
	if got := challengeV2ArmGrain(id, "203.0.113.5", "shop.gr"); got != v2GrainMark {
		t.Fatalf("mark grain: got %q", got)
	}
	// A mark is keyed on the exact (ip, host) pair — another host is unarmed.
	if got := challengeV2ArmGrain(id, "203.0.113.5", "other.gr"); got != "" {
		t.Fatalf("mark must not leak across hosts, got %q", got)
	}

	// vhost arm outranks the mark.
	SetChallengeV2HostArmed(func(host string) bool { return host == "shop.gr" })
	t.Cleanup(func() { SetChallengeV2HostArmed(nil) })
	if got := challengeV2ArmGrain(id, "203.0.113.5", "shop.gr"); got != v2GrainVhost {
		t.Fatalf("vhost grain: got %q", got)
	}

	// geo policy outranks the vhost arm.
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "CN", Kind: "country", Action: "challenge_v2"}})
	SetFingerprintPolicyGeoResolver(func(ip string) (string, uint64) { return "CN", 4134 })
	t.Cleanup(func() { SetFingerprintPolicyGeoResolver(nil) })
	if got := challengeV2ArmGrain(id, "203.0.113.5", "shop.gr"); got != v2GrainGeo {
		t.Fatalf("geo grain: got %q", got)
	}

	// The fingerprint policy outranks everything.
	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: "CN", Kind: "country", Action: "challenge_v2"},
		{ID: id, Action: "challenge_v2"},
	})
	if got := challengeV2ArmGrain(id, "203.0.113.5", "shop.gr"); got != v2GrainFP {
		t.Fatalf("fp grain: got %q", got)
	}

	// A non-v2 fingerprint policy is NOT a v2 arm: only the tier arms the rung
	// (a plain "challenge" fp must fall through to the next grain, not arm).
	SetFingerprintPolicies([]FingerprintPolicy{{ID: id, Action: "challenge"}})
	if got := challengeV2ArmGrain(id, "203.0.113.5", "shop.gr"); got != v2GrainVhost {
		t.Fatalf("plain-challenge fp must not arm v2, got %q", got)
	}
}

// ── Retained (unscored) signals ────────────────────────────────────────────

func fptr(v float64) *float64 { return &v }
func iptr(v int) *int         { return &v }

// The retained report must reach the solve line verbatim-but-rounded, in a
// fixed order, with absent signals simply missing. Regression anchor for the
// bug this replaced: mv/hc/dm/dpr/raf were parsed and silently discarded, so
// "did this client move the mouse at all?" was unanswerable from the logs.
func TestSignalSuffix(t *testing.T) {
	// Nothing retained (no payload) adds no field at all.
	if got := (ChallengeSolve{}).SignalSuffix(); got != "" {
		t.Fatalf("no payload must add no sig field, got %q", got)
	}

	// The operator's real case: a genuine browser that was opened and left
	// alone. Every counter is a REPORTED zero, which must be visible as such.
	quiet := ChallengeSolve{humanity: &humanitySignals{
		PTR: iptr(0), TCH: iptr(0), KEY: iptr(0), MV: fptr(0),
		HC: iptr(8), DPR: fptr(1.5), RAF: fptr(16.666666666666668),
	}}
	const want = " sig=ptr:0,tch:0,key:0,mv:0,hc:8,dpr:1.5,raf:16.7"
	if got := quiet.SignalSuffix(); got != want {
		t.Fatalf("quiet-browser solve:\n got %q\nwant %q", got, want)
	}
	// dm is Chrome-only: on this Firefox-shaped report the key must be ABSENT,
	// not rendered as a reported 0 (the absence/zero confusion D5b forbids).
	if strings.Contains(quiet.SignalSuffix(), "dm:") {
		t.Fatalf("an unreported deviceMemory must not appear at all, got %q", quiet.SignalSuffix())
	}

	// Fractional deviceMemory (low-end Android) survives rounding, and movement
	// keeps one decimal — fractional movementX on HiDPI is a real reading.
	busy := ChallengeSolve{humanity: &humanitySignals{
		PTR: iptr(137), MV: fptr(4821.73), DM: fptr(0.25),
	}}
	if got, want := busy.SignalSuffix(), " sig=ptr:137,mv:4821.7,dm:0.25"; got != want {
		t.Fatalf("busy solve:\n got %q\nwant %q", got, want)
	}

	// Never scientific notation: a %g-style verb here would break a grep/cut
	// corpus pass (and has misrendered a value in this repo before).
	big := ChallengeSolve{humanity: &humanitySignals{MV: fptr(123456789)}}
	if got := big.SignalSuffix(); strings.ContainsAny(got, "eE") {
		t.Fatalf("no exponent form allowed on the log line, got %q", got)
	}
}

// A REPORTED non-zero must never render as "0": `ptr:1,mv:0` is a shape no
// real client produces, and putting it in the corpus would read as "events
// fired, pointer never moved". Sub-pixel movementX is real on HiDPI and
// fractional display scaling, so this is not a theoretical case.
func TestSignalSuffixNeverFakesAZero(t *testing.T) {
	for _, mv := range []float64{0.5, 0.04, 0.0001, sigMinPositive} {
		got := (ChallengeSolve{humanity: &humanitySignals{PTR: iptr(1), MV: fptr(mv)}}).SignalSuffix()
		if strings.Contains(got, "mv:0,") || strings.HasSuffix(got, "mv:0") {
			t.Errorf("mv=%v rendered as a flat zero: %q", mv, got)
		}
		if strings.ContainsAny(got, "eE") {
			t.Errorf("mv=%v rendered in exponent form: %q", mv, got)
		}
	}
	// A genuine zero still renders as a plain zero — that reading is real and
	// is exactly what "opened the page and touched nothing" looks like.
	if got := (ChallengeSolve{humanity: &humanitySignals{MV: fptr(0)}}).SignalSuffix(); got != " sig=mv:0" {
		t.Errorf("a reported zero must stay 0, got %q", got)
	}
	// The guarantee rests on sanitize: a positive too small for any device to
	// report is dropped to absent rather than rendered, so the fallback
	// precision can always express what survives.
	tiny := parseHumanityBody([]byte(`{"v":1,"mv":1e-12,"raf":1e-12}`))
	if tiny == nil || tiny.MV != nil || tiny.RAF != nil {
		t.Errorf("sub-resolution positives must be dropped, got mv=%v raf=%v", tiny.MV, tiny.RAF)
	}
}

// The suffix the two solve-line writers share must carry the retained report
// between the score and the arm, and still render nothing when the rung is off.
func TestHumanitySuffixIncludesSignals(t *testing.T) {
	s := ChallengeSolve{
		HumanityScored: true,
		V2Grain:        v2GrainMark,
		humanity:       &humanitySignals{PTR: iptr(0), MV: fptr(0)},
	}
	if got, want := s.HumanitySuffix(), " hs=0 sig=ptr:0,mv:0 v2=mark"; got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	off := ChallengeSolve{humanity: &humanitySignals{PTR: iptr(5)}}
	if got := off.HumanitySuffix(); got != "" {
		t.Fatalf("unscored solve must render nothing at all, got %q", got)
	}
}

// Bounds are DIGIT SANITY, not a plausibility judgement. What is not a
// reading at all (negative, absurd magnitude) degrades to ABSENT — never to a
// fabricated zero — while everything a browser could actually have reported
// survives untouched, including the anomalous readings the corpus exists to
// find.
func TestSanitizeDropsOnlyNonReadings(t *testing.T) {
	sig := parseHumanityBody([]byte(`{"v":1,"ptr":-3,"tch":9000000,"key":4,` +
		`"mv":1e300,"hc":0,"dm":99999,"dpr":0,"raf":-1}`))
	if sig == nil {
		t.Fatal("a well-formed body must parse")
	}
	// Not readings: a negative count/magnitude and an absurd magnitude.
	if sig.PTR != nil || sig.TCH != nil || sig.MV != nil || sig.RAF != nil {
		t.Errorf("non-readings survived: ptr=%v tch=%v mv=%v raf=%v", sig.PTR, sig.TCH, sig.MV, sig.RAF)
	}
	// Readings — including hc:0 and dpr:0, which are exactly the
	// headless/embedded-WebView evidence this corpus is being built to
	// discover. Erasing them would both destroy the tell and make it
	// indistinguishable from "not reported".
	if got := (ChallengeSolve{humanity: sig}).SignalSuffix(); got != " sig=key:4,hc:0,dm:99999,dpr:0" {
		t.Errorf("readings must survive verbatim, got %q", got)
	}
}

// Regression anchor for the review finding this replaced: an earlier version
// required hc >= 1 and dpr >= 0.001, so a client reporting hc:0/dpr:0 — the
// strongest environment tell in the payload — was silently converted into
// "the browser did not report it".
func TestSanitizeKeepsReportedZeros(t *testing.T) {
	sig := parseHumanityBody([]byte(`{"v":1,"ptr":0,"tch":0,"key":0,"mv":0,"hc":0,"dm":0,"dpr":0,"raf":0}`))
	if sig == nil {
		t.Fatal("a well-formed body must parse")
	}
	const want = " sig=ptr:0,tch:0,key:0,mv:0,hc:0,dm:0,dpr:0,raf:0"
	if got := (ChallengeSolve{humanity: sig}).SignalSuffix(); got != want {
		t.Fatalf("every reported zero must survive:\n got %q\nwant %q", got, want)
	}
}

// Negative zero is a valid float that no reading means: it must never reach a
// surface as "-0".
func TestSigRoundNormalisesNegativeZero(t *testing.T) {
	sig := parseHumanityBody([]byte(`{"v":1,"mv":-0.0,"raf":-0.0}`))
	if sig == nil || sig.MV == nil {
		t.Fatalf("negative zero is a reported zero and must survive sanitize, got %v", sig)
	}
	if got := (ChallengeSolve{humanity: sig}).SignalSuffix(); strings.Contains(got, "-0") {
		t.Errorf("negative zero reached the log line: %q", got)
	}
	if m := (ChallengeSolve{humanity: sig}).signalMap(); math.Signbit(m["mv"].(float64)) {
		t.Errorf("negative zero reached the history row: %v", m["mv"])
	}
}

// Bounding must not be able to move a verdict: no_input needs all three
// counters REPORTED and all three exactly zero, and a count that fails the
// bounds is non-zero anyway. Pins the invariant the sanitize doc-comment
// claims, in both directions.
func TestSanitizeCannotChangeScoring(t *testing.T) {
	// Out-of-bounds counters: the amplifier did not fire before the drop
	// (they are non-zero) and must not fire after it either.
	sig := parseHumanityBody([]byte(`{"v":1,"wd":true,"ptr":-1,"tch":-1,"key":-1}`))
	hs, tells := scoreHumanity(sig, "")
	if hs != tellWebdriver || strings.Contains(strings.Join(tells, ","), "no_input") {
		t.Fatalf("dropped counters must not amplify: hs=%d tells=%v", hs, tells)
	}
	// In-bounds zeros are untouched, so the amplifier still fires on top of a
	// real opener exactly as it did before.
	sig = parseHumanityBody([]byte(`{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`))
	hs, tells = scoreHumanity(sig, "")
	if hs != tellWebdriver+ampNoInput || !strings.Contains(strings.Join(tells, ","), "no_input") {
		t.Fatalf("reported zeros must still amplify: hs=%d tells=%v", hs, tells)
	}
	// And the amplifier still cannot OPEN a score on its own (D5b) — the
	// operator's quiet-browser case: zero input, nothing else, must pass.
	sig = parseHumanityBody([]byte(`{"v":1,"wd":false,"ptr":0,"tch":0,"key":0,"mv":0,"hc":8,"dpr":1.5}`))
	if hs, tells = scoreHumanity(sig, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0"); hs != 0 || len(tells) != 0 {
		t.Fatalf("an untouched real browser must score clean: hs=%d tells=%v", hs, tells)
	}
}
