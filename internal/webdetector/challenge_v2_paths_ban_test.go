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
		ConfigureChallengeV2PathsRejectBan(2)
	}
	reset()
	t.Cleanup(reset)
}

// Only a web-scope reject from a malpath-marked IP counts. It counts visits
// (the page's retries within a minute are one); the first failed visit asks
// for the hold, the second within the window for the ban, once.
func TestChallengeV2PathsRejectBan(t *testing.T) {
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	now := time.Now()
	const ip = "203.0.113.120"
	rej := ChallengeSolve{IP: ip, Host: "a.example", Scope: "web"}
	at := func(d time.Duration) V2PathsReject { return NoteChallengeV2PathsReject(rej, now.Add(d)) }

	// Not malpath-marked: a reject under another grain (a traffic-rule mark,
	// a WAF mark) never counts.
	MarkChallengeV2(ip, "a.example")
	MarkChallengeV2IP(ip)
	for i := 0; i < 5; i++ {
		if r := at(time.Duration(i) * 2 * time.Minute); r.Visits != 0 || r.Hold() || r.Ban {
			t.Fatalf("a reject with no malpath mark counted: %+v", r)
		}
	}

	markChallengeV2Path(ip, 2*time.Hour)
	if r := NoteChallengeV2PathsReject(ChallengeSolve{IP: ip, Scope: "panel:2083"}, now); r.Visits != 0 {
		t.Fatalf("a panel-scope reject counted: %+v", r)
	}
	// First visit: four retries within ~20 s are one visit, held once.
	if r := at(0); r.Visits != 1 || !r.Hold() || r.Ban {
		t.Fatalf("first reject: %+v, want visit 1 with a hold", r)
	}
	for _, d := range []time.Duration{5 * time.Second, 12 * time.Second, 20 * time.Second} {
		if r := at(d); r.Visits != 1 || r.Hold() || r.Ban {
			t.Fatalf("a retry at %v: %+v, want the same visit and no new hold", d, r)
		}
	}
	// The second failed visit (it waited for the challenge, came back) bans.
	if r := at(11 * time.Minute); r.Visits != 2 || !r.Ban || r.Hold() {
		t.Fatalf("second visit: %+v, want the ban", r)
	}
	// The count starts over.
	if r := at(12 * time.Minute); r.Visits != 1 || r.Ban {
		t.Fatalf("after the ban: %+v", r)
	}
	// Visits spread past the window do not add up.
	if r := at(12*time.Minute + v2PathsRejectWindow + time.Minute); r.Visits != 1 || r.Ban {
		t.Fatalf("a visit past the window: %+v, want a new first visit", r)
	}

	ConfigureChallengeV2PathsRejectBan(0)
	for i := 0; i < 5; i++ {
		if r := at(3*time.Hour + time.Duration(i)*2*time.Minute); r.Ban || r.Hold() {
			t.Fatalf("CHALLENGE_V2_PATHS_REJECT_BAN=0 still acted: %+v", r)
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
