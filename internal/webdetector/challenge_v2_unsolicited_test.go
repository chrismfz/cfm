package webdetector

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	unsolUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	unsolFailing = `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`           // webdriver + no input: certain, fails
	unsolClean   = `{"v":1,"wd":false,"ptr":7,"tch":0,"key":2,"mv":180}` // real input: scores clean
)

// hasClearanceCookie reports whether the verify SET a clearance cookie (the
// test env has no clearance secret, so its value may be empty: the header is
// what a withheld solve must not carry).
func hasClearanceCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "cfm_clearance") {
			return true
		}
	}
	return false
}

// A farm pre-solving the page while nothing challenges it (src=-) banked a
// v1-scored clearance cookie that later carried it past a v2 arm. Now a
// failing unsolicited web solve is withheld: 303 to next, no cookie, one
// challenge_v2_reject row with v2=unsolicited — and never a 403 the page
// would retry into.
func TestVerify_UnsolicitedFailingSolveGetsNoCookie(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	base, capt := startVerifyServerWithBridge(t, b)

	resp := postVerify(t, base, "203.0.113.10", "shop.example", unsolUA, unsolFailing)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303 to next (withheld, not refused)", resp.StatusCode)
	}
	if resp.Header.Get("X-CFM-V2") != "" {
		t.Error("an unsolicited withhold must not read as a v2 reject (the page would retry)")
	}
	if hasClearanceCookie(resp) {
		t.Fatal("a failing unsolicited solve got a clearance cookie")
	}
	solved, rejects := capt.counts()
	if solved != 0 || rejects != 1 {
		t.Fatalf("solved=%d rejects=%d, want 0/1", solved, rejects)
	}
	if g := capt.rejects[0].V2Grain; g != v2GrainUnsolicited {
		t.Errorf("reject grain=%q, want %q", g, v2GrainUnsolicited)
	}
	if v := capt.rejects[0].SrcValue(); v != "-" {
		t.Errorf("src=%q, want -", v)
	}
}

// A clean unsolicited solve is armed and passes: it gets its cookie, and the
// solve line names the grain so an armed-and-passed solve is greppable.
func TestVerify_UnsolicitedCleanSolvePasses(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	base, capt := startVerifyServerWithBridge(t, b)

	resp := postVerify(t, base, "203.0.113.11", "shop.example", unsolUA, unsolClean)
	if resp.StatusCode != http.StatusSeeOther || !hasClearanceCookie(resp) {
		t.Fatalf("status=%d cookie=%v, want 303 with a cookie", resp.StatusCode, hasClearanceCookie(resp))
	}
	if solved, _ := capt.counts(); solved != 1 || capt.solved[0].V2Grain != v2GrainUnsolicited {
		t.Fatalf("solved=%d grain=%q, want 1 solve under the unsolicited grain", solved, capt.solved[0].V2Grain)
	}
}

// Not armed: a solve some challenge covers (it answers that challenge, under
// that challenge's own tier), a panel-scope solve (the panels' human-entry
// challenge is not in the snapshot, so every panel solve reads src=-), and
// any solve with the knob off. Each gets its cookie as before.
func TestVerify_UnsolicitedGrainScope(t *testing.T) {
	withoutV2All(t) // this test is about a named grain's own scope
	t.Run("covered by a vhost challenge", func(t *testing.T) {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		b.ChallengeVhostWithReason("covered.example", time.Hour, "manual")
		base, capt := startVerifyServerWithBridge(t, b)
		resp := postVerify(t, base, "203.0.113.12", "covered.example", unsolUA, unsolFailing)
		if !hasClearanceCookie(resp) {
			t.Fatalf("status=%d: a solve answering a (v1) vhost challenge lost its cookie", resp.StatusCode)
		}
		if _, rejects := capt.counts(); rejects != 0 {
			t.Fatal("a covered v1 solve was rejected")
		}
	})
	t.Run("panel scope", func(t *testing.T) {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		base, capt := startVerifyServerWithBridge(t, b)
		hdr := map[string]string{"X-CFM-Panel-Port": "2096", "X-Forwarded-Port": "2096"}
		resp := postVerifyHdr(t, base, "203.0.113.13", "shop.example", unsolUA, unsolFailing, hdr)
		if !hasClearanceCookie(resp) {
			t.Fatalf("status=%d: a panel solve was armed by the unsolicited grain", resp.StatusCode)
		}
		if _, rejects := capt.counts(); rejects != 0 {
			t.Fatal("a panel solve was rejected")
		}
	})
	t.Run("knob off", func(t *testing.T) {
		ConfigureChallengeV2Unsolicited(false)
		t.Cleanup(func() { ConfigureChallengeV2Unsolicited(true) })
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		base, capt := startVerifyServerWithBridge(t, b)
		resp := postVerify(t, base, "203.0.113.14", "shop.example", unsolUA, unsolFailing)
		if !hasClearanceCookie(resp) {
			t.Fatalf("status=%d: CHALLENGE_V2_UNSOLICITED=0 still withheld the cookie", resp.StatusCode)
		}
		if _, rejects := capt.counts(); rejects != 0 {
			t.Fatal("knob off still rejected")
		}
	})
}

// A withheld solve reaches the WITHHELD stream (the solver-farm detector's
// evidence: a farm pre-solving on fresh IPs is the cluster it convicts) and
// never the solve stream (it cleared nothing: challenge_cookie_discard would
// read a client that never got a cookie as one that discarded it). A solve
// that passes takes only the solve stream.
func TestVerify_WithheldSolvePublishedToWithheldStreamOnly(t *testing.T) {
	resetWithheldOnceForTest()
	t.Cleanup(resetWithheldOnceForTest)
	ResetChallengeSolveSubscribers()
	t.Cleanup(ResetChallengeSolveSubscribers)
	var mu sync.Mutex
	var solved, withheld []string
	SubscribeChallengeSolveEvents(func(s ChallengeSolve) { mu.Lock(); solved = append(solved, s.IP); mu.Unlock() })
	SubscribeChallengeWithheldEvents(func(s ChallengeSolve) { mu.Lock(); withheld = append(withheld, s.IP); mu.Unlock() })

	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	base, _ := startVerifyServerWithBridge(t, b)
	postVerify(t, base, "203.0.113.20", "shop.example", unsolUA, unsolFailing)
	postVerify(t, base, "203.0.113.21", "shop.example", unsolUA, unsolClean)

	mu.Lock()
	defer mu.Unlock()
	if len(withheld) != 1 || withheld[0] != "203.0.113.20" {
		t.Errorf("withheld stream = %v, want only the failing 203.0.113.20", withheld)
	}
	if len(solved) != 1 || solved[0] != "203.0.113.21" {
		t.Errorf("solve stream = %v, want only the passing 203.0.113.21", solved)
	}

	// The manager's reload reset drops withheld subscribers too (else every
	// reload would add one, feeding retired detectors' buffers forever).
	ResetChallengeSolveSubscribers()
	solveSubsMu.RLock()
	n := len(withheldSubs)
	solveSubsMu.RUnlock()
	if n != 0 {
		t.Errorf("withheld subscribers after reset = %d, want 0", n)
	}
}

// A withheld client gets no cookie, so a farm exit that comes back pre-solves
// again; the cookie used to spare that repeat for its lifetime. The withheld
// stream publishes once per (ip, host) per withheldDedupTTL, so the evidence
// (the solver-farm finding's solves-per-IP, ~1.0 for a farm) is not lifted
// toward a returning human audience's. A different host is a new pair. The
// event says CHALLENGE_WITHHELD, never CHALLENGE_SOLVED.
func TestPublishChallengeWithheld_OncePerPairAndLabelled(t *testing.T) {
	resetWithheldOnceForTest()
	t.Cleanup(resetWithheldOnceForTest)
	ResetChallengeSolveSubscribers()
	t.Cleanup(ResetChallengeSolveSubscribers)
	var got []ChallengeSolve
	SubscribeChallengeWithheldEvents(func(s ChallengeSolve) { got = append(got, s) })

	s := ChallengeSolve{IP: "198.51.100.77", Host: "dedup-a.example"}
	publishChallengeWithheldEvent(s)
	publishChallengeWithheldEvent(s) // the same exit back on the same host
	s2 := s
	s2.Host = "dedup-b.example"
	publishChallengeWithheldEvent(s2)

	if len(got) != 2 || got[0].Host != "dedup-a.example" || got[1].Host != "dedup-b.example" {
		t.Fatalf("published %d (%v), want one per (ip, host)", len(got), got)
	}
	if r := got[0].WithheldInputEvent().Reason; r != "CHALLENGE_WITHHELD" {
		t.Errorf("withheld event reason=%q, want CHALLENGE_WITHHELD", r)
	}
	if r := got[0].InputEvent().Reason; r != "CHALLENGE_SOLVED" {
		t.Errorf("solve event reason changed: %q", r)
	}

	// With no withheld subscriber (a reload's gap), the slot is NOT claimed:
	// the next solve, once a subscriber is back, is still published.
	ResetChallengeSolveSubscribers()
	gap := ChallengeSolve{IP: "198.51.100.78", Host: "dedup-a.example"}
	publishChallengeWithheldEvent(gap)
	SubscribeChallengeWithheldEvents(func(s ChallengeSolve) { got = append(got, s) })
	publishChallengeWithheldEvent(gap)
	if len(got) != 3 || got[2].IP != "198.51.100.78" {
		t.Fatalf("after a subscriber-less publish: %d events, want the gap client published once a reader is back", len(got))
	}
}

// resetWithheldOnceForTest empties the withheld dedup store, so a test (and a
// rerun of it in the same process, -count) starts from no published pair.
func resetWithheldOnceForTest() {
	withheldOnce.mu.Lock()
	withheldOnce.m = map[string]time.Time{}
	withheldOnce.mu.Unlock()
}
