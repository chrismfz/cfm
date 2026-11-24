package webdetector

import (
	"net/http"
	"testing"
	"time"
)

func resetUnsolvedHold(t *testing.T, mode string) {
	t.Helper()
	reset := func(m string) {
		unsolvedViews.mu.Lock()
		unsolvedViews.m = map[string]*unsolvedViewState{}
		unsolvedViews.mu.Unlock()
		unsolvedHolds.deleteWhere(func(string) bool { return true })
		ConfigureChallengeUnsolvedHold(m, unsolvedHoldDefaultViews, unsolvedHoldDefaultWindow, unsolvedHoldDefaultTTL, unsolvedHoldDefaultMax)
	}
	reset(mode)
	t.Cleanup(func() { reset("log") })
}

func newUnsolvedHoldBridge(t *testing.T) *NginxBridge {
	t.Helper()
	return NewNginxBridge("/tmp/cfm-test-unsolved-hold.sock", "tok", time.Minute, time.Minute)
}

func ipEntry(b *NginxBridge, ip string) (bridgeIPEntry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	e, ok := b.ipState[ip]
	return e, ok
}

// views feeds n challenge-page views at now (+1s each) and returns the last answer.
func views(b *NginxBridge, ip string, now time.Time, n int) UnsolvedHold {
	var out UnsolvedHold
	for i := 0; i < n; i++ {
		out = b.NoteUnsolvedChallengeView(ip, "shop.example", now.Add(time.Duration(i)*time.Second))
	}
	return out
}

// log (the default) counts and says it would hold, and changes nothing.
func TestUnsolvedHold_LogModeChangesNothing(t *testing.T) {
	resetUnsolvedHold(t, "log")
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.50"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "uniq_paths(230/220)")
	before, _ := ipEntry(b, ip)
	now := time.Now()

	if r := views(b, ip, now, unsolvedHoldDefaultViews-1); !r.Counted || r.Hold {
		t.Fatalf("below the threshold: %+v", r)
	}
	r := b.NoteUnsolvedChallengeView(ip, "shop.example", now.Add(30*time.Second))
	if !r.Hold || r.Held {
		t.Fatalf("at the threshold in log mode: %+v, want hold=true held=false", r)
	}
	after, _ := ipEntry(b, ip)
	if !after.Expires.Equal(before.Expires) || !after.HoldUntil.IsZero() {
		t.Fatalf("log mode changed the entry: %+v -> %+v", before, after)
	}
	if _, ok := unsolvedHolds.get(ip, now); ok {
		t.Fatal("log mode stored a hold")
	}
}

// enforce holds the challenge for the TTL, keeps its reason, and a later
// shorter challenge write cannot cut it short.
func TestUnsolvedHold_EnforceHoldsAndIsNotShortened(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.51"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "uniq_paths(230/220)")
	now := time.Now()

	r := views(b, ip, now, unsolvedHoldDefaultViews)
	if !r.Hold || !r.Held {
		t.Fatalf("at the threshold: %+v, want held", r)
	}
	e, _ := ipEntry(b, ip)
	if e.Action != "challenge" || e.Reason != "uniq_paths(230/220)" {
		t.Fatalf("entry after the hold: %+v (reason must be kept)", e)
	}
	if got := e.Expires.Sub(now); got < 59*time.Minute || got > 61*time.Minute+time.Duration(unsolvedHoldDefaultViews)*time.Second {
		t.Fatalf("held for %v, want ~1h", got)
	}
	if e.HoldUntil.IsZero() {
		t.Fatal("no HoldUntil floor")
	}
	// A detector's re-challenge with its own shorter TTL keeps the hold.
	b.ChallengeIPWithReason(ip, 10*time.Minute, "")
	if e2, _ := ipEntry(b, ip); e2.Expires.Before(e.Expires) {
		t.Fatalf("a 10m re-challenge shortened the hold: %v -> %v", e.Expires, e2.Expires)
	}
	if _, ok := unsolvedHolds.get(ip, now); !ok {
		t.Fatal("the hold was not stored for a reload")
	}
}

// It only extends a live per-IP challenge: never starts one, never counts a
// client with no entry (a vhost challenge alone), never touches a block.
func TestUnsolvedHold_OnlyALivePerIPChallenge(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	b := newUnsolvedHoldBridge(t)
	now := time.Now()

	if r := views(b, "203.0.113.52", now, 50); r.Counted || r.Hold {
		t.Fatalf("an IP with no per-IP challenge was counted: %+v", r)
	}
	if _, ok := ipEntry(b, "203.0.113.52"); ok {
		t.Fatal("a challenge was started")
	}

	const blocked = "203.0.113.53"
	b.BlockIP(blocked, time.Hour)
	if r := views(b, blocked, now, 50); r.Counted {
		t.Fatalf("a blocked IP was counted: %+v", r)
	}
	if e, _ := ipEntry(b, blocked); e.Action != "block" {
		t.Fatalf("the block was replaced: %+v", e)
	}

	const bypassed = "203.0.113.54"
	b.SetBypassFunc(func(ip string) bool { return ip == bypassed })
	b.mu.Lock()
	b.ipState[bypassed] = bridgeIPEntry{Action: "challenge", Expires: now.Add(20 * time.Minute)}
	b.mu.Unlock()
	if r := views(b, bypassed, now, 50); r.Counted {
		t.Fatalf("an IGNORE_IPS address was counted: %+v", r)
	}
}

// Views spread wider than the window start the count over.
func TestUnsolvedHold_WindowResets(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	ConfigureChallengeUnsolvedHold("enforce", 20, time.Minute, time.Hour, 24*time.Hour)
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.55"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	now := time.Now()
	views(b, ip, now, 15)
	if r := views(b, ip, now.Add(3*time.Minute), 15); r.Hold || r.Views != 15 {
		t.Fatalf("15 + 15 views three minutes apart (1m window): %+v, want a fresh count of 15", r)
	}
}

// A solve (ClearIP: the verify's release) and a manual clear end the hold
// and the count; the next challenge needs the full count again.
func TestUnsolvedHold_SolveEndsIt(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.56"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	now := time.Now()
	if r := views(b, ip, now, unsolvedHoldDefaultViews); !r.Held {
		t.Fatalf("not held: %+v", r)
	}
	b.ClearIP(ip)
	if _, ok := ipEntry(b, ip); ok {
		t.Fatal("the solve left the entry")
	}
	if _, ok := unsolvedHolds.get(ip, now); ok {
		t.Fatal("the solve left the stored hold (a reload would re-impose it)")
	}
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	if r := views(b, ip, now, unsolvedHoldDefaultViews-1); r.Hold {
		t.Fatalf("the count was not started over: %+v", r)
	}
}

// Renewals never take the hold past MAX from its first renewal.
func TestUnsolvedHold_MaxCapsTheEpisode(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	ConfigureChallengeUnsolvedHold("enforce", 20, 10*time.Minute, time.Hour, time.Hour)
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.57"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	t0 := time.Now()
	first := views(b, ip, t0, 20)
	second := views(b, ip, t0.Add(30*time.Minute), 20)
	if !first.Held || !second.Held {
		t.Fatalf("renewals: %+v / %+v", first, second)
	}
	capAt := t0.Add(19 * time.Second).Add(time.Hour) // the first renewal's view
	if second.Until.After(capAt) {
		t.Fatalf("the second renewal ends %v, past the 1h cap %v", second.Until, capAt)
	}
	if first.Capped || !second.Capped {
		t.Fatalf("capped flags: first %v second %v, want false / true (nothing left to extend)", first.Capped, second.Capped)
	}
}

// The holds survive a config reload in enforce mode, and are dropped when the
// node is switched back to log.
func TestUnsolvedHold_SurvivesReload(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	old := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.58"
	old.ChallengeIPWithReason(ip, 20*time.Minute, "uniq_paths(230/220)")
	if r := views(old, ip, time.Now(), unsolvedHoldDefaultViews); !r.Held {
		t.Fatalf("not held: %+v", r)
	}

	fresh := newUnsolvedHoldBridge(t)
	if n := fresh.RestoreUnsolvedHolds(); n != 1 {
		t.Fatalf("restored %d, want 1", n)
	}
	e, ok := ipEntry(fresh, ip)
	if !ok || e.Action != "challenge" || e.Reason != "uniq_paths(230/220)" || time.Until(e.Expires) < 50*time.Minute {
		t.Fatalf("restored entry: %+v", e)
	}

	ConfigureChallengeUnsolvedHold("log", 20, 10*time.Minute, time.Hour, 24*time.Hour)
	again := newUnsolvedHoldBridge(t)
	if n := again.RestoreUnsolvedHolds(); n != 0 {
		t.Fatalf("log mode restored %d holds", n)
	}
	if _, ok := unsolvedHolds.get(ip, time.Now()); ok {
		t.Fatal("switching to log kept the stored hold")
	}
}

func TestConfigureChallengeUnsolvedHold_Clamps(t *testing.T) {
	resetUnsolvedHold(t, "log")
	ConfigureChallengeUnsolvedHold("bogus", 1, time.Second, time.Second, time.Second)
	c := unsolvedHoldCfg.Load()
	if c.Mode != unsolvedHoldLog || c.Views != unsolvedHoldMinViews || c.Window != time.Minute || c.TTL != 5*time.Minute || c.Max != 5*time.Minute {
		t.Fatalf("clamped config: %+v", *c)
	}
	ConfigureChallengeUnsolvedHold(" OFF ", 20, time.Minute, time.Hour, 24*time.Hour)
	if unsolvedHoldCfg.Load().Mode != unsolvedHoldOff {
		t.Fatal("OFF not read as off")
	}
	b := newUnsolvedHoldBridge(t)
	b.ChallengeIPWithReason("203.0.113.59", 20*time.Minute, "x")
	if r := views(b, "203.0.113.59", time.Now(), 50); r.Counted {
		t.Fatalf("off mode counted: %+v", r)
	}
}

// End to end through the real page handler: the scraper's shape (load the
// page again and again, never solve) holds the challenge; a person on the
// same address who solves ends it.
func TestUnsolvedHold_PageHandlerEndToEnd(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetThrottleStores(t)
	b := newUnsolvedHoldBridge(t)
	const ip, host = "83.212.158.22", "enleukoiko.gr"
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "uniq_paths(230/220)")
	base, _ := startVerifyServerWithBridge(t, b)

	for i := 0; i < unsolvedHoldDefaultViews; i++ {
		req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next=%2Fshop%2F%3Fper_page%3D"+string(rune('a'+i)), nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Forwarded-Host", host)
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("view %d: %d, want the page", i, resp.StatusCode)
		}
	}
	e, _ := ipEntry(b, ip)
	if time.Until(e.Expires) < 50*time.Minute {
		t.Fatalf("after %d unsolved views the challenge ends in %v, want ~1h", unsolvedHoldDefaultViews, time.Until(e.Expires))
	}

	resp := postVerify(t, base, ip, host, ua, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther { // a good verify sends the client to next
		t.Fatalf("the solve: %d, want 303", resp.StatusCode)
	}
	if _, ok := ipEntry(b, ip); ok {
		t.Fatal("a solve on the address did not end the held challenge")
	}
	if _, ok := unsolvedHolds.get(ip, time.Now()); ok {
		t.Fatal("a solve left the stored hold")
	}
}

// A malpath hold over an unsolved hold keeps its own length for its side
// effects (v2 mark, clearance revocation, stored malpath hold): the merged
// HoldUntil floor (a day here) must not stretch them. The entry keeps the day.
func TestUnsolvedHold_DoesNotStretchAMalpathHold(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	resetChallengeV2Marks(t)
	resetV2PathsRejects(t)
	ConfigureChallengeUnsolvedHold("enforce", 20, 10*time.Minute, 24*time.Hour, 24*time.Hour)
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.60"
	t.Cleanup(func() { endMalpathHold(ip) })
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	if r := views(b, ip, time.Now(), 20); !r.Held {
		t.Fatalf("not held: %+v", r)
	}
	if !b.HoldChallengeIP(ip, time.Hour) {
		t.Fatal("malpath hold refused")
	}
	now := time.Now()
	limit := now.Add(time.Hour + time.Minute)
	for name, exp := range map[string]time.Time{
		"v2 path mark":  challengeV2PathMarks.live(now)[ip],
		"malpath store": malpathHolds.live(now)[ip],
	} {
		if exp.IsZero() || exp.After(limit) {
			t.Fatalf("%s ends %v, want ~1h (not the day-long unsolved hold)", name, exp)
		}
	}
	b.mu.RLock()
	rev := b.clrRevoked[ip]
	b.mu.RUnlock()
	if rev.IsZero() || rev.After(limit) {
		t.Fatalf("clearance revocation ends %v, want ~1h", rev)
	}
	if e, _ := ipEntry(b, ip); time.Until(e.Expires) < 23*time.Hour {
		t.Fatalf("the entry lost the unsolved hold: ends in %v", time.Until(e.Expires))
	}
}

// A reload restores the entry's WAF rule id with its reason.
func TestUnsolvedHold_RestoreKeepsTheRuleID(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	old := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.61"
	old.mu.Lock()
	old.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: time.Now().Add(20 * time.Minute), Reason: "waf", WAFRuleID: 302}
	old.mu.Unlock()
	if r := views(old, ip, time.Now(), 20); !r.Held {
		t.Fatalf("not held: %+v", r)
	}
	fresh := newUnsolvedHoldBridge(t)
	fresh.RestoreUnsolvedHolds()
	if e, _ := ipEntry(fresh, ip); e.WAFRuleID != 302 || e.Reason != "waf" {
		t.Fatalf("restored %+v, want reason waf and rule 302", e)
	}
}

// A clear in any scope deletes the entry, so it ends the stored hold too: a
// reload must not re-impose a challenge the live state no longer has.
func TestUnsolvedHold_PanelClearEndsTheStoredHold(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.62"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	if r := views(b, ip, time.Now(), 20); !r.Held {
		t.Fatalf("not held: %+v", r)
	}
	b.ClearIPScoped(ip, "shop.example", "panel:2083")
	if _, ok := unsolvedHolds.get(ip, time.Now()); ok {
		t.Fatal("a panel clear left the stored hold")
	}
}

// IPv6: the views are counted per /64 (firewall.CountKey), so rotating the
// address inside it does not reset the count; the address that crosses is
// the one held.
func TestUnsolvedHold_IPv6CountsPer64(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	b := newUnsolvedHoldBridge(t)
	const a, c = "2001:db8:1:2::a", "2001:db8:1:2::c"
	b.ChallengeIPWithReason(a, 20*time.Minute, "x")
	b.ChallengeIPWithReason(c, 20*time.Minute, "x")
	now := time.Now()
	views(b, a, now, 10)
	r := views(b, c, now.Add(10*time.Second), 10)
	if !r.Held {
		t.Fatalf("10 + 10 views in one /64: %+v, want held", r)
	}
	if e, _ := ipEntry(b, c); time.Until(e.Expires) < 50*time.Minute {
		t.Fatalf("the crossing address is not held: %v", time.Until(e.Expires))
	}
}

// Restore never shortens a longer challenge the fresh bridge already has.
func TestUnsolvedHold_RestoreDoesNotShorten(t *testing.T) {
	resetUnsolvedHold(t, "enforce")
	old := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.63"
	old.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	if r := views(old, ip, time.Now(), 20); !r.Held {
		t.Fatalf("not held: %+v", r)
	}
	fresh := newUnsolvedHoldBridge(t)
	long := time.Now().Add(3 * time.Hour)
	fresh.mu.Lock()
	fresh.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: long, Reason: "manual"}
	fresh.mu.Unlock()
	fresh.RestoreUnsolvedHolds()
	if e, _ := ipEntry(fresh, ip); e.Expires.Before(long) {
		t.Fatalf("restore shortened a 3h challenge to %v", time.Until(e.Expires))
	}
}

// log mode shows the MAX cap too, so the burn-in can judge it.
func TestUnsolvedHold_LogModeShowsTheCap(t *testing.T) {
	resetUnsolvedHold(t, "log")
	ConfigureChallengeUnsolvedHold("log", 20, 10*time.Minute, time.Hour, time.Hour)
	b := newUnsolvedHoldBridge(t)
	const ip = "203.0.113.64"
	b.ChallengeIPWithReason(ip, 20*time.Minute, "x")
	t0 := time.Now()
	first := views(b, ip, t0, 20)
	second := views(b, ip, t0.Add(5*time.Minute), 20)
	if !first.Hold || first.Capped || !second.Hold || !second.Capped {
		t.Fatalf("log-mode cap: first %+v second %+v, want the second capped", first, second)
	}
}
