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
// (the page's retries and its reload, within v2PathsRejectVisitGap, are
// one); every counted reject asks for the hold, the second visit within the
// window for the ban, once.
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
	// First visit: the page's retries, and the reload its give-up text asks
	// for ("wait a minute"), are one visit; each refreshes the hold.
	if r := at(0); r.Visits != 1 || !r.NewVisit || !r.Hold() || r.Ban {
		t.Fatalf("first reject: %+v, want visit 1 with a hold", r)
	}
	for _, d := range []time.Duration{5 * time.Second, 12 * time.Second, 20 * time.Second, 50 * time.Second, 2*time.Minute + 30*time.Second} {
		if r := at(d); r.Visits != 1 || r.NewVisit || !r.Hold() || r.Ban {
			t.Fatalf("a retry at %v: %+v, want the same visit, held", d, r)
		}
	}
	// The second failed visit (it left, came back) bans.
	if r := at(13 * time.Minute); r.Visits != 2 || !r.Ban || r.Hold() {
		t.Fatalf("second visit: %+v, want the ban", r)
	}
	// The count starts over.
	if r := at(14 * time.Minute); r.Visits != 1 || r.Ban {
		t.Fatalf("after the ban: %+v", r)
	}
	// Visits spread past the window do not add up.
	if r := at(14*time.Minute + v2PathsRejectWindow + time.Minute); r.Visits != 1 || r.Ban {
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

// The hold: never shortened by a later challenge, never over a block, and a
// web solve starts the reject count over.
func TestHoldChallengeIP(t *testing.T) {
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	b := NewNginxBridge("/tmp/cfm-test-v2-hold.sock", "tok", time.Minute, time.Minute)
	const ip = "203.0.113.130"

	if !b.HoldChallengeIP(ip, time.Hour) {
		t.Fatalf("no hold")
	}
	// A detector's 10m re-challenge, then TWO WAF challenge pushes and an
	// unrelated detector challenge over it (a floor keyed on the reason was
	// undone by the second write).
	b.ChallengeIPWithReason(ip, 10*time.Minute, "CHALLENGE_PATHS")
	b.mu.Lock()
	b.ipState[ip] = b.pushedIPEntryLocked(ip, "challenge", time.Now().Add(5*time.Minute), "WAF_XSS", 302)
	b.ipState[ip] = b.pushedIPEntryLocked(ip, "challenge", time.Now().Add(5*time.Minute), "WAF_XSS", 302)
	b.mu.Unlock()
	b.ChallengeIPWithReason(ip, 5*time.Minute, "CHALLENGE_ERR_RATIO")
	b.mu.Lock()
	e := b.ipState[ip]
	b.mu.Unlock()
	if e.Reason != "CHALLENGE_ERR_RATIO" {
		t.Fatalf("the hold hid what challenged the client: reason %q", e.Reason)
	}
	if time.Until(e.Expires) < 59*time.Minute {
		t.Fatalf("a later challenge shortened the hold to %v", time.Until(e.Expires))
	}
	if _, ok := challengeV2PathMarks.get(ip, time.Now().Add(50*time.Minute)); !ok {
		t.Fatalf("the hold's mark does not last the hour")
	}
	if !b.clearanceRevokedLocked(ip, time.Now().Add(50*time.Minute)) {
		t.Fatalf("the hold's revocation does not last the hour")
	}

	// A block is never weakened by a hold.
	const blocked = "203.0.113.131"
	b.mu.Lock()
	b.ipState[blocked] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(time.Hour)}
	b.mu.Unlock()
	if b.HoldChallengeIP(blocked, time.Hour) {
		t.Fatalf("a hold over a live block")
	}
	if a, _ := b.GetIPDecision(blocked); a != "block" {
		t.Fatalf("the block became %q", a)
	}

	// A web solve forgets the reject count.
	markChallengeV2Path(ip, time.Hour)
	NoteChallengeV2PathsReject(ChallengeSolve{IP: ip, Scope: "web"}, time.Now())
	b.ClearIP(ip)
	v2PathsRejects.mu.Lock()
	_, counted := v2PathsRejects.m[ip]
	v2PathsRejects.mu.Unlock()
	if counted {
		t.Fatalf("a solve left the reject count")
	}
}

// A client that fails without ever pausing is not one endless visit: once its
// visit has gone on for v2PathsRejectVisitGap, the next reject is the second
// visit, and the window never restarts mid-visit.
func TestChallengeV2PathsRejectBanContinuousFailer(t *testing.T) {
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	const ip = "203.0.113.140"
	markChallengeV2Path(ip, 6*time.Hour)
	now := time.Now()
	rej := ChallengeSolve{IP: ip, Scope: "web"}
	banned := false
	for m := 0; m <= 30; m += 5 {
		if r := NoteChallengeV2PathsReject(rej, now.Add(time.Duration(m)*time.Minute)); r.Ban {
			banned = true
			if m != 10 {
				t.Fatalf("banned at +%dm, want +10m (the visit's age reached the gap)", m)
			}
			break
		}
	}
	if !banned {
		t.Fatalf("a reject every 5 minutes never banned")
	}
}

// A hold survives a config reload (a new bridge): RestoreMalpathHolds puts it
// back; a solve ends it, its mark with it, and nothing is restored after.
func TestMalpathHoldSurvivesReload(t *testing.T) {
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	t.Cleanup(func() { malpathHolds.deleteWhere(func(string) bool { return true }) })
	const ip = "203.0.113.141"
	old := NewNginxBridge("/tmp/cfm-test-v2-hold.sock", "tok", time.Minute, time.Minute)
	if !old.HoldChallengeIP(ip, time.Hour) {
		t.Fatalf("no hold")
	}
	fresh := NewNginxBridge("/tmp/cfm-test-v2-hold.sock", "tok", time.Minute, time.Minute)
	if n := fresh.RestoreMalpathHolds(); n != 1 {
		t.Fatalf("restored %d holds, want 1", n)
	}
	if a, _ := fresh.GetIPDecision(ip); a != "challenge" || !fresh.ClearanceRevoked(ip) {
		t.Fatalf("after a reload: decision %q, revoked %v", a, fresh.ClearanceRevoked(ip))
	}
	fresh.mu.RLock()
	left := time.Until(fresh.ipState[ip].Expires)
	fresh.mu.RUnlock()
	if left < 59*time.Minute {
		t.Fatalf("the restored hold has %v left", left)
	}

	fresh.ClearIP(ip) // solved
	if _, ok := challengeV2PathMarks.get(ip, time.Now()); ok {
		t.Fatalf("a solve left the malpath mark")
	}
	again := NewNginxBridge("/tmp/cfm-test-v2-hold.sock", "tok", time.Minute, time.Minute)
	if n := again.RestoreMalpathHolds(); n != 0 {
		t.Fatalf("a solved hold came back after a reload (%d)", n)
	}
}
