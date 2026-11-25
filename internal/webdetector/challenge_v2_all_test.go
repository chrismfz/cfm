package webdetector

import (
	"net/http"
	"testing"
	"time"
)

// withoutV2All turns CHALLENGE_V2_ALL off for one test: the tests of a named
// grain's scope (what it covers and what it leaves unarmed) predate the all
// grain, which arms whatever they leave.
func withoutV2All(t *testing.T) {
	t.Helper()
	ConfigureChallengeV2All(false)
	t.Cleanup(func() { ConfigureChallengeV2All(true) })
}

// "v2 everywhere" (2026-11-25): a failing solve that no named grain covers is
// rejected under the all grain — a v1 vhost arm, the panel ports' own
// challenge — instead of earning a cookie scored at v1.
func TestVerify_AllGrainArmsWhatNoGrainNames(t *testing.T) {
	t.Run("v1 vhost challenge", func(t *testing.T) {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		b.ChallengeVhostWithReason("v1.example", time.Hour, "manual")
		base, capt := startVerifyServerWithBridge(t, b)
		resp := postVerify(t, base, "203.0.113.40", "v1.example", unsolUA, unsolFailing)
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" || hasClearanceCookie(resp) {
			t.Fatalf("status=%d v2=%q cookie=%v, want a 403 v2 reject with no cookie", resp.StatusCode, resp.Header.Get("X-CFM-V2"), hasClearanceCookie(resp))
		}
		if _, rejects := capt.counts(); rejects != 1 || capt.rejects[0].V2Grain != v2GrainAll {
			t.Fatalf("rejects=%d, want one under the all grain", rejects)
		}
	})
	t.Run("panel scope", func(t *testing.T) {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		base, capt := startVerifyServerWithBridge(t, b)
		hdr := map[string]string{"X-CFM-Panel-Port": "2096", "X-Forwarded-Port": "2096"}
		resp := postVerifyHdr(t, base, "203.0.113.41", "shop.example", unsolUA, unsolFailing, hdr)
		if resp.StatusCode != http.StatusForbidden || hasClearanceCookie(resp) {
			t.Fatalf("status=%d cookie=%v, want a panel reject", resp.StatusCode, hasClearanceCookie(resp))
		}
		if _, rejects := capt.counts(); rejects != 1 || capt.rejects[0].V2Grain != v2GrainAll {
			t.Fatal("the panel reject is not under the all grain")
		}
	})
	t.Run("a clean solve passes and names the grain", func(t *testing.T) {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		b.ChallengeVhostWithReason("v1.example", time.Hour, "manual")
		base, capt := startVerifyServerWithBridge(t, b)
		resp := postVerify(t, base, "203.0.113.42", "v1.example", unsolUA, unsolClean)
		if !hasClearanceCookie(resp) {
			t.Fatalf("status=%d: a clean solve lost its cookie", resp.StatusCode)
		}
		if solved, _ := capt.counts(); solved != 1 || capt.solved[0].V2Grain != v2GrainAll {
			t.Fatal("a clean solve under the all grain does not name it")
		}
	})
	t.Run("a named grain keeps its name", func(t *testing.T) {
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		base, capt := startVerifyServerWithBridge(t, b)
		postVerify(t, base, "203.0.113.43", "shop.example", unsolUA, unsolFailing)
		if _, rejects := capt.counts(); rejects != 1 || capt.rejects[0].V2Grain != v2GrainUnsolicited {
			t.Fatal("an unsolicited solve was relabelled by the all grain")
		}
	})
	t.Run("knob off", func(t *testing.T) {
		withoutV2All(t)
		b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
		b.ChallengeVhostWithReason("v1.example", time.Hour, "manual")
		base, capt := startVerifyServerWithBridge(t, b)
		resp := postVerify(t, base, "203.0.113.44", "v1.example", unsolUA, unsolFailing)
		if !hasClearanceCookie(resp) {
			t.Fatalf("status=%d: CHALLENGE_V2_ALL=0 still rejected a v1 solve", resp.StatusCode)
		}
		if _, rejects := capt.counts(); rejects != 0 {
			t.Fatal("knob off still rejected")
		}
	})
}

// The good-bot waiver covers the all grain like geo and vhost: the Google
// fetchers on a webmail panel were the one non-farm population unarmed.
func TestChallengeV2WaiverBar_AllGrainIsWaivable(t *testing.T) {
	if bar := challengeV2WaiverBar(v2GrainAll, "203.0.113.45", "shop.example", "panel:2096"); bar != "" {
		t.Fatalf("waiver bar for the all grain = %q, want none", bar)
	}
}
