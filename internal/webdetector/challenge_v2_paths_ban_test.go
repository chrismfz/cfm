package webdetector

import (
	"testing"
	"time"
)

func resetV2PathsRejects(t *testing.T) {
	t.Helper()
	reset := func() {
		v2PathsRejects.mu.Lock()
		v2PathsRejects.m = map[string]v2PathsRejectState{}
		v2PathsRejects.mu.Unlock()
		ConfigureChallengeV2PathsRejectBan(3)
	}
	reset()
	t.Cleanup(reset)
}

// Only a web-scope reject from a malpath-marked IP counts, and the third
// (one visit's retries) asks for the ban, once.
func TestChallengeV2PathsRejectBan(t *testing.T) {
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	now := time.Now()
	const ip = "203.0.113.120"
	rej := ChallengeSolve{IP: ip, Host: "a.example", Scope: "web"}

	// Not marked: a reject under another grain (a traffic-rule mark, a vhost
	// arm) never counts.
	MarkChallengeV2(ip, "a.example")
	MarkChallengeV2IP(ip)
	for i := 0; i < 5; i++ {
		if _, ban := NoteChallengeV2PathsReject(rej, now); ban {
			t.Fatalf("a reject with no malpath mark asked for a ban")
		}
	}

	markChallengeV2Path(ip, 10*time.Minute)
	if _, ban := NoteChallengeV2PathsReject(ChallengeSolve{IP: ip, Scope: "panel:2083"}, now); ban {
		t.Fatalf("a panel-scope reject counted")
	}
	for i := 1; i <= 2; i++ {
		if n, ban := NoteChallengeV2PathsReject(rej, now.Add(time.Duration(i)*time.Second)); ban || n != i {
			t.Fatalf("reject %d: n=%d ban=%v", i, n, ban)
		}
	}
	if n, ban := NoteChallengeV2PathsReject(rej, now.Add(3*time.Second)); !ban || n != 3 {
		t.Fatalf("third reject: n=%d ban=%v, want the ban", n, ban)
	}
	// The count starts over.
	if n, ban := NoteChallengeV2PathsReject(rej, now.Add(4*time.Second)); ban || n != 1 {
		t.Fatalf("after the ban: n=%d ban=%v", n, ban)
	}
	// Rejects spread past the window do not add up (a mark that outlives it).
	markChallengeV2Path(ip, time.Hour)
	if n, _ := NoteChallengeV2PathsReject(rej, now.Add(v2PathsRejectWindow+5*time.Second)); n != 1 {
		t.Fatalf("a reject past the window: n=%d, want 1", n)
	}

	ConfigureChallengeV2PathsRejectBan(0)
	for i := 0; i < 5; i++ {
		if _, ban := NoteChallengeV2PathsReject(rej, now); ban {
			t.Fatalf("CHALLENGE_V2_PATHS_REJECT_BAN=0 still banned")
		}
	}
}

// An operator unblock drops every rung mark on the IP and its reject count,
// and leaves another IP's alone (IPv6: no prefix collision).
func TestForceUnblockClearsChallengeV2Marks(t *testing.T) {
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	b := NewNginxBridge("/tmp/cfm-test-v2-unblock.sock", "tok", time.Minute, time.Minute)
	const ip, other = "2001:db8::1", "2001:db8::10"
	for _, x := range []string{ip, other} {
		MarkChallengeV2(x, "a.example")
		MarkChallengeV2IP(x)
		markChallengeV2Path(x, 10*time.Minute)
	}
	NoteChallengeV2PathsReject(ChallengeSolve{IP: ip, Scope: "web"}, time.Now())

	res := b.ForceUnblock(ip)
	if challengeV2Marked(ip, "a.example") || challengeV2IPMarked(ip) {
		t.Fatalf("an unblock left a rung mark on %s", ip)
	}
	if !challengeV2Marked(other, "a.example") || !challengeV2IPMarked(other) {
		t.Fatalf("an unblock of %s cleared %s", ip, other)
	}
	v2PathsRejects.mu.Lock()
	_, counted := v2PathsRejects.m[ip]
	v2PathsRejects.mu.Unlock()
	if counted {
		t.Fatalf("an unblock left the reject count")
	}
	found := false
	for _, f := range res.Cleared {
		if f.Plane == "challenge_v2_mark" && f.Detail == "3 mark(s)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unblock report does not name the marks: %+v", res.Cleared)
	}
}
