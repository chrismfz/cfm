package webdetector

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"cfm/internal/abuseshadow"
)

// The rescue's rule, at its boundaries: both readings REPORTED and at or over
// the bar, and no certain tell. It is a pure predicate over the parsed report;
// the gate decides when it is consulted.
func TestChallengeV2InputRescue(t *testing.T) {
	i := func(v int) *int { return &v }
	f := func(v float64) *float64 { return &v }
	cases := []struct {
		name  string
		sig   *humanitySignals
		tells string
		want  bool
	}{
		{"E4 human (41 events, 714 px)", &humanitySignals{PTR: i(41), MV: f(714)}, "sw_renderer,outer_zero", true},
		{"at both bars", &humanitySignals{PTR: i(rescueMinPointerEvents), MV: f(rescueMinMovePx)}, "sw_renderer,outer_zero", true},
		{"one event short", &humanitySignals{PTR: i(rescueMinPointerEvents - 1), MV: f(rescueMinMovePx)}, "sw_renderer,outer_zero", false},
		{"a pixel short", &humanitySignals{PTR: i(rescueMinPointerEvents), MV: f(rescueMinMovePx - 1)}, "sw_renderer,outer_zero", false},
		// Events without movement: a pointer parked over the page, or an
		// event stream with movementX/Y left at zero.
		{"events, no movement", &humanitySignals{PTR: i(200), MV: f(0)}, "sw_renderer,outer_zero", false},
		{"device-claim group", &humanitySignals{PTR: i(12), MV: f(400)}, "sw_renderer,touch_lie", true},
		// The certain tells: the browser declares its own automation, so
		// input never outweighs them — alone or in company.
		{"webdriver", &humanitySignals{PTR: i(41), MV: f(714)}, "webdriver", false},
		{"webdriver among others", &humanitySignals{PTR: i(41), MV: f(714)}, "sw_renderer,webdriver,outer_zero", false},
		{"headless UA", &humanitySignals{PTR: i(41), MV: f(714)}, "headless_ua", false},
		// Absent is never input (D5b's mirror image: absence neither
		// convicts nor exculpates).
		{"no payload", nil, "headless_ua", false},
		{"ptr absent", &humanitySignals{MV: f(714)}, "sw_renderer,outer_zero", false},
		{"mv absent", &humanitySignals{PTR: i(41)}, "sw_renderer,outer_zero", false},
		// A tell name that merely CONTAINS a certain one is not it.
		{"substring is not a tell", &humanitySignals{PTR: i(41), MV: f(714)}, "sw_renderer,not_webdriver", true},
	}
	for _, c := range cases {
		if got := challengeV2InputRescue(c.sig, c.tells); got != c.want {
			t.Errorf("%s: rescue=%v, want %v", c.name, got, c.want)
		}
	}
}

// End to end at the gate. The FP class the first E4 read found: Windows
// Chrome/109 on old hardware — software renderer and no window size, exactly
// the fail score — with a person moving the mouse. Under an arm that solve
// now takes the solved path (clearance, redirect) marked v2_rescued=input, and
// the good-bot waiver is never consulted for it. The same machine WITHOUT
// input, and any certain tell, is still rejected.
func TestVerify_V2GateRescuesRealInput(t *testing.T) {
	base, capt := startVerifyServer(t)
	const (
		armedHost = "mathematica.example.gr"
		markHost  = "forum.example.gr"
		win7      = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
		// sw_renderer 60 + outer_zero 40 = 100 = defaultV2FailScore.
		oldPC = `"glr":"Google SwiftShader","ow":0,"oh":0,"tch":0,"key":0`
		moved = `{"v":1,"wd":false,` + oldPC + `,"ptr":41,"mv":714}`
		still = `{"v":1,"wd":false,` + oldPC + `,"ptr":0,"mv":0}`
		bot   = `{"v":1,"wd":true,` + oldPC + `,"ptr":41,"mv":714}`
	)
	setV2HostArmed(t, func(host string) bool { return host == armedHost })
	var waiverCalls atomic.Int32
	setV2GoodBot(t, func(context.Context, string, string) (string, string) {
		waiverCalls.Add(1)
		return "", ""
	})

	resp := postVerify(t, base, "203.0.113.20", armedHost, win7, moved)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a failing solve with real input was not rescued: status=%d X-CFM-V2=%q", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == "cfm_clearance" && c.MaxAge > 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("a rescued solve must take the clearance path, cookies=%v", resp.Cookies())
	}
	solved, rejects := capt.counts()
	if solved != 1 || rejects != 0 {
		t.Fatalf("rescued solve: solved=%d rejects=%d, want 1/0", solved, rejects)
	}
	s := capt.solved[0]
	if s.V2Rescued != v2RescuedInput || s.V2Grain != v2GrainVhost || s.HumanityScore < defaultV2FailScore || s.V2Waived != "" {
		t.Fatalf("rescued solve not attributed: rescued=%q grain=%q hs=%d waived=%q", s.V2Rescued, s.V2Grain, s.HumanityScore, s.V2Waived)
	}
	// The line keeps the failing score and its tells, so a rescued solve
	// reads as exactly that — never as a clean pass.
	if suf := s.HumanitySuffix(); !strings.Contains(suf, " v2=vhost v2_rescued=input") ||
		!strings.Contains(suf, "tells=sw_renderer,outer_zero") {
		t.Errorf("solve line does not show the rescue: %q", suf)
	}
	if waiverCalls.Load() != 0 {
		t.Fatalf("the good-bot waiver ran for a rescued solve: calls=%d", waiverCalls.Load())
	}

	// Every grain: a rung mark (a WAF challenge_v2 hit) rescues the same way —
	// the question is whether a person is at the controls, not who armed it.
	MarkChallengeV2("203.0.113.21", markHost)
	if resp = postVerify(t, base, "203.0.113.21", markHost, win7, moved); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a rescued solve under a mark: status=%d, want 303", resp.StatusCode)
	}

	// Same machine, no input → rejected, as before.
	resp = postVerify(t, base, "203.0.113.22", armedHost, win7, still)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("no input: status=%d X-CFM-V2=%q, want 403 + reject", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	// A certain tell is never rescued, however much the pointer moved.
	resp = postVerify(t, base, "203.0.113.23", armedHost, win7, bot)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("webdriver with input: status=%d X-CFM-V2=%q, want 403 + reject", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	headless := strings.Replace(win7, "Chrome/", "HeadlessChrome/", 1)
	resp = postVerify(t, base, "203.0.113.24", armedHost, headless, `{"v":1,"wd":false,"ptr":41,"mv":714,"tch":0,"key":0}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("headless UA with input: status=%d, want 403", resp.StatusCode)
	}
	solved, rejects = capt.counts()
	if solved != 2 || rejects != 3 {
		t.Fatalf("solved=%d rejects=%d, want 2/3", solved, rejects)
	}
	for _, r := range capt.rejects {
		if r.V2Rescued != "" {
			t.Fatalf("a reject carries v2_rescued=%q", r.V2Rescued)
		}
	}

	// Unarmed: the rescue is recorded on the solve (it rides the would_v2
	// shadow line), and the solve clears as any unarmed solve does.
	if resp = postVerify(t, base, "203.0.113.25", "blog.example.gr", win7, moved); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unarmed rescued solve: status=%d", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.V2Rescued != v2RescuedInput || s.V2Grain != "" {
		t.Fatalf("unarmed solve: rescued=%q grain=%q, want input/unarmed", s.V2Rescued, s.V2Grain)
	}
	// A passing score is never "rescued" — there was nothing to rescue it from.
	if resp = postVerify(t, base, "203.0.113.26", armedHost, win7, `{"v":1,"wd":false,"ptr":41,"mv":714,"tch":0,"key":0}`); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("passing armed solve: status=%d", resp.StatusCode)
	}
	if s := capt.solved[len(capt.solved)-1]; s.V2Rescued != "" {
		t.Fatalf("a passing solve was marked rescued: %q", s.V2Rescued)
	}
}

// The rescue marker reaches all three surfaces: the history row, the would_v2
// shadow line (space-free, before src=, parsed back by abuse_shadow) and — via
// HumanitySuffix — the solve line.
func TestV2Rescued_Surfaces(t *testing.T) {
	e := newSolveTestEngine(t)
	e.RecordChallengeSolved(ChallengeSolve{
		IP: "203.0.113.20", Host: "mathematica.example.gr", URI: "/",
		HumanityScored: true, HumanityScore: 100, HumanityTells: "sw_renderer,outer_zero",
		V2Grain: v2GrainVhost, V2Rescued: v2RescuedInput,
	})
	if p := latestSolveEvent(t, e).Payload; p["v2"] != v2GrainVhost || p["v2_rescued"] != v2RescuedInput {
		t.Fatalf("history payload v2=%v v2_rescued=%v, want vhost/input", p["v2"], p["v2_rescued"])
	}
	if _, ok := (ChallengeSolve{HumanityScored: true, HumanityScore: 100}).historyPayload()["v2_rescued"]; ok {
		t.Fatal("an unrescued solve must not persist v2_rescued")
	}

	s := ChallengeSolve{UAFamily: "Chrome", V2Rescued: v2RescuedInput, SrcResolved: true, Src: []string{"vhost:suspicious_vhost"}, Scope: "web"}
	suf := s.ShadowContextSuffix()
	if !strings.HasSuffix(suf, " v2_rescued=input src=vhost:suspicious_vhost scope=web") {
		t.Fatalf("shadow suffix: %q", suf)
	}
	line := "2026-09-29 10:00:00 [abuse-shadow] signal=humanity host=h ip=1.2.3.4 hs=100 tells=sw_renderer,outer_zero fp=- verdict=would_v2" + suf
	if ent, ok := abuseshadow.Parse(line); !ok || ent.Rescued != v2RescuedInput || ent.Verdict != "would_v2" || ent.Src != "vhost:suspicious_vhost" {
		t.Fatalf("parsed %+v from %q", ent, line)
	}
	if strings.Contains((ChallengeSolve{}).ShadowContextSuffix(), "v2_rescued") {
		t.Fatal("an unrescued shadow line must not carry the key")
	}
}
