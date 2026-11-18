package webdetector

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	unsolUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	unsolFailing = `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`          // webdriver + no input: certain, fails
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
