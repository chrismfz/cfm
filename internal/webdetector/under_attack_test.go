package webdetector

import (
	"fmt"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

func newAttackTestEngine() *Engine {
	cfg := Config{
		UnderAttack:                 true,
		UnderAttackSolvesMin:        15,
		UnderAttackConfirmTicks:     3,
		UnderAttackHolddown:         30 * time.Minute,
		UnderAttackErrFloor:         0.5,
		UnderAttackBotCeil:          0.05,
		ChallengeSuspiciousUniqIPOn: 300,
	}
	e := &Engine{cfg: cfg}
	e.attack = newUnderAttackTracker()
	return e
}

func seedSolves(e *Engine, host string, n int, now time.Time) {
	for i := 0; i < n; i++ {
		e.attack.solves.record(host, fmt.Sprintf("203.0.113.%d", i), now)
	}
}

func drainAlerts(out chan core.Alert) []core.Alert {
	var got []core.Alert
	for {
		select {
		case a := <-out:
			got = append(got, a)
		default:
			return got
		}
	}
}

func countKind(alerts []core.Alert, kind string) int {
	n := 0
	for _, a := range alerts {
		if string(a.Kind) == kind {
			n++
		}
	}
	return n
}

// The §4 calibration contract: MUST fire on the e-athlos shape (challenge armed
// AND defeated AND pressure AND claims-browser), MUST NOT fire on the stereotiki
// shape (a real crawl: low uniqIP, low error, bot-declared population) even when
// (wrongly) fed a full solve storm and treated as challenged.
func TestUnderAttack_CalibrationContract(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 16)

	// --- e-athlos: MUST fire after CONFIRM_TICKS ---
	e := newAttackTestEngine()
	host := "e-athlos.com"
	row := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003, RPS: 102}
	seedSolves(e, host, 30, t0)
	for i := 0; i < e.cfg.UnderAttackConfirmTicks; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), host, true, row, out)
	}
	alerts := drainAlerts(out)
	if got := countKind(alerts, "WEB/VHOST_UNDER_ATTACK_ON"); got != 1 {
		t.Fatalf("e-athlos: want exactly 1 UNDER_ATTACK_ON, got %d (%d total)", got, len(alerts))
	}
	if on, _, _ := e.VhostAttackState(host); !on {
		t.Fatal("e-athlos: state should be ON after entry")
	}

	// --- stereotiki: MUST NOT fire, even with a solve storm + treated challenged ---
	e2 := newAttackTestEngine()
	sh := "www.stereotiki.gr"
	srow := SuspiciousRow{Host: sh, UniqueIPs: 155, ErrRatio: 0.008, BotRatio: 0.90, RPS: 5}
	seedSolves(e2, sh, 30, t0) // even if it somehow "solved" a lot
	for i := 0; i < 6; i++ {
		e2.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), sh, true, srow, out)
	}
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 0 {
		t.Fatalf("stereotiki: must never fire, got %d ON alerts", got)
	}
	if on, _, _ := e2.VhostAttackState(sh); on {
		t.Fatal("stereotiki: state must stay OFF")
	}
}

// A vhost that is NOT challenge-armed can never enter (leg 1), even under a full
// solve storm + melting pressure — UNDER_ATTACK is reachable only from CHALLENGED.
func TestUnderAttack_NotChallengedNeverEnters(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "shop.example"
	row := SuspiciousRow{Host: host, UniqueIPs: 5000, ErrRatio: 1.0, BotRatio: 0.0, RPS: 200}
	seedSolves(e, host, 40, t0)
	for i := 0; i < 6; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), host, false /*not challenged*/, row, out)
	}
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 0 {
		t.Fatalf("not-challenged vhost entered under attack (%d ON alerts)", got)
	}
}

// Entry needs CONFIRM_TICKS *consecutive* qualifying ticks; a single
// non-qualifying tick resets the counter.
func TestUnderAttack_ConfirmTicksHysteresis(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	good := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}
	calm := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 0.0, BotRatio: 0.003} // pressure off
	seedSolves(e, host, 30, t0)

	tick := 0
	step := func(row SuspiciousRow) {
		e.evalUnderAttack(t0.Add(time.Duration(tick)*2*time.Second), host, true, row, out)
		tick++
	}
	step(good) // confirm 1
	step(good) // confirm 2
	step(calm) // resets to 0
	if on, _, _ := e.VhostAttackState(host); on {
		t.Fatal("entered before 3 consecutive qualifying ticks")
	}
	step(good) // 1
	step(good) // 2
	step(good) // 3 -> enter
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 1 {
		t.Fatalf("want 1 ON after 3 consecutive, got %d", got)
	}
}

// Exit: when the challenge itself clears (leg 1 false), the state leaves at once.
func TestUnderAttack_ExitOnChallengeCleared(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	row := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}
	seedSolves(e, host, 30, t0)
	for i := 0; i < 3; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), host, true, row, out)
	}
	_ = drainAlerts(out)
	e.evalUnderAttack(t0.Add(10*time.Second), host, false /*challenge cleared*/, row, out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_OFF"); got != 1 {
		t.Fatalf("want 1 OFF on challenge clear, got %d", got)
	}
	if on, _, _ := e.VhostAttackState(host); on {
		t.Fatal("state should be OFF after challenge cleared")
	}
}

// Exit: pressure must stay below floor for HOLDDOWN before leaving.
func TestUnderAttack_ExitOnPressureHolddown(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	hot := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}
	cool := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 0.0, BotRatio: 0.003} // err below floor
	seedSolves(e, host, 30, t0)
	for i := 0; i < 3; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), host, true, hot, out)
	}
	_ = drainAlerts(out)

	// Pressure drops but holddown not yet elapsed → still ON.
	e.evalUnderAttack(t0.Add(1*time.Minute), host, true, cool, out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_OFF"); got != 0 {
		t.Fatal("exited before holddown elapsed")
	}
	if on, _, _ := e.VhostAttackState(host); !on {
		t.Fatal("should still be ON within holddown")
	}
	// Past the holddown with pressure still low → exit.
	e.evalUnderAttack(t0.Add(1*time.Minute+e.cfg.UnderAttackHolddown+time.Second), host, true, cool, out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_OFF"); got != 1 {
		t.Fatalf("want 1 OFF after holddown, got %d", got)
	}
}

// Manual override: `attack on` forces the state regardless of legs; `attack off`
// leaves it and suppresses auto re-entry for the holddown, then expires back to
// auto control.
func TestUnderAttack_ManualOverride(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 16)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	quiet := SuspiciousRow{Host: host, UniqueIPs: 0, ErrRatio: 0, BotRatio: 0} // fails every leg

	// Force ON with nothing qualifying.
	e.SetVhostAttackOverride(host, true, t0, 0)
	e.evalUnderAttack(t0, host, false, quiet, out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 1 {
		t.Fatalf("attack on: want 1 forced ON, got %d", got)
	}

	// Force OFF: leaves + suppresses re-entry (holddown measured from t0+2s).
	e.SetVhostAttackOverride(host, false, t0.Add(2*time.Second), 0)
	e.evalUnderAttack(t0.Add(2*time.Second), host, false, quiet, out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_OFF"); got != 1 {
		t.Fatalf("attack off: want 1 OFF, got %d", got)
	}

	// A real qualifying storm within the suppression window must NOT re-enter.
	hot := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}
	seedSolves(e, host, 30, t0)
	for i := 0; i < 5; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(4+i)*time.Second), host, true, hot, out)
	}
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 0 {
		t.Fatalf("suppressed window re-entered: %d ON alerts", got)
	}

	// After the holddown, suppression expires → a storm re-enters.
	base := t0.Add(2*time.Second + e.cfg.UnderAttackHolddown + 10*time.Second)
	seedSolves(e, host, 30, base)
	for i := 0; i < e.cfg.UnderAttackConfirmTicks; i++ {
		e.evalUnderAttack(base.Add(time.Duration(i)*2*time.Second), host, true, hot, out)
	}
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 1 {
		t.Fatalf("post-suppression storm should re-enter: got %d ON", got)
	}
}

func firstOfKind(alerts []core.Alert, kind string) (core.Alert, bool) {
	for _, a := range alerts {
		if string(a.Kind) == kind {
			return a, true
		}
	}
	return core.Alert{}, false
}

// deescalateUnderAttack (called from the genuine full-suppress sites) must clear
// an UNDER_ATTACK state and emit OFF; it is a no-op on an already-off host.
func TestUnderAttack_DeescalateOnSuppress(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	hot := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}
	seedSolves(e, host, 30, t0)
	for i := 0; i < 3; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), host, true, hot, out)
	}
	_ = drainAlerts(out)
	if on, _, _ := e.VhostAttackState(host); !on {
		t.Fatal("precondition: should be ON")
	}

	e.deescalateUnderAttack(t0.Add(10*time.Second), host, "challenge suppressed (bypass)", out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_OFF"); got != 1 {
		t.Fatalf("de-escalate should emit 1 OFF, got %d", got)
	}
	on, _, ev := e.VhostAttackState(host)
	if on {
		t.Fatal("still ON after de-escalate")
	}
	if ev != "challenge suppressed (bypass)" {
		t.Fatalf("exit evidence = %q", ev)
	}

	// Idempotent: de-escalating an already-off host emits nothing.
	e.deescalateUnderAttack(t0.Add(12*time.Second), host, "challenge suppressed (bypass)", out)
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_OFF"); got != 0 {
		t.Fatalf("second de-escalate should be a no-op, got %d OFF", got)
	}
}

// A pending confirm streak goes stale after a long gap (the vhost fell out of
// the candidate set and returned): entry must require CONFIRM_TICKS fresh
// consecutive ticks, not resume the old partial streak.
func TestUnderAttack_ConfirmResetsAfterGap(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	hot := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}

	seedSolves(e, host, 30, t0)
	e.evalUnderAttack(t0, host, true, hot, out)                    // confirm 1
	e.evalUnderAttack(t0.Add(2*time.Second), host, true, hot, out) // confirm 2

	// Big gap → the next qualifying tick resets confirm before ++, so it is 1, not entering.
	gap := t0.Add(2*time.Second + underAttackConfirmResetGap + time.Second)
	seedSolves(e, host, 30, gap)
	e.evalUnderAttack(gap, host, true, hot, out)
	if on, _, _ := e.VhostAttackState(host); on {
		t.Fatal("entered on a stale confirm streak after a gap")
	}
	e.evalUnderAttack(gap.Add(2*time.Second), host, true, hot, out) // 2
	e.evalUnderAttack(gap.Add(4*time.Second), host, true, hot, out) // 3 -> enter
	if got := countKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON"); got != 1 {
		t.Fatalf("want 1 ON after 3 fresh consecutive ticks, got %d", got)
	}
}

// An operator-forced transition is recorded mode=manual (not auto) so the audit
// trail attributes it correctly.
func TestUnderAttack_OverrideRecordedManual(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	quiet := SuspiciousRow{Host: host}

	e.SetVhostAttackOverride(host, true, t0, 0)
	e.evalUnderAttack(t0, host, false, quiet, out)
	a, ok := firstOfKind(drainAlerts(out), "WEB/VHOST_UNDER_ATTACK_ON")
	if !ok {
		t.Fatal("no forced ON alert")
	}
	if a.Extra["mode"] != "manual" {
		t.Fatalf("forced ON mode = %q, want manual", a.Extra["mode"])
	}
}

// After an exit, VhostAttackState returns the exit evidence, not the stale
// "challenge defeated…" entry line.
func TestUnderAttack_ExitEvidenceConsistent(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	out := make(chan core.Alert, 8)
	e := newAttackTestEngine()
	host := "e-athlos.com"
	hot := SuspiciousRow{Host: host, UniqueIPs: 2540, ErrRatio: 1.0, BotRatio: 0.003}
	seedSolves(e, host, 30, t0)
	for i := 0; i < 3; i++ {
		e.evalUnderAttack(t0.Add(time.Duration(i)*2*time.Second), host, true, hot, out)
	}
	e.evalUnderAttack(t0.Add(10*time.Second), host, false, hot, out) // exit: challenge cleared
	_ = drainAlerts(out)
	on, _, ev := e.VhostAttackState(host)
	if on {
		t.Fatal("should be OFF")
	}
	if ev != "challenge cleared" {
		t.Fatalf("stale/wrong exit evidence: %q", ev)
	}
}

// The solve-rate feed counts distinct IPs in the window and excludes
// self-declared bot UAs (§5), and prunes stale entries.
func TestUnderAttackSolves_RateWindowAndBotExempt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := newAttackTestEngine()
	host := "shop.example"

	// Distinct-in-window with a controlled clock.
	e.attack.solves.record(host, "1.1.1.1", now)
	e.attack.solves.record(host, "1.1.1.2", now)
	e.attack.solves.record(host, "1.1.1.1", now) // duplicate IP → still 2 distinct
	if got := e.attack.solves.ratePerMin(host, now); got != 2 {
		t.Fatalf("distinct-in-window: got %d want 2", got)
	}
	// Entries age out of the window.
	if got := e.attack.solves.ratePerMin(host, now.Add(2*time.Minute)); got != 0 {
		t.Fatalf("stale entries not pruned: got %d want 0", got)
	}

	// Bot-UA exemption via the real record path (uses time.Now(); use a fresh
	// host and read at time.Now() so the two clocks don't mix).
	h2 := "shop2.example"
	e.RecordUnderAttackSolve(ChallengeSolve{Host: h2, IP: "9.9.9.9", UA: "Googlebot/2.1 (+http://www.google.com/bot.html)"})
	e.RecordUnderAttackSolve(ChallengeSolve{Host: h2, IP: "8.8.8.8", UA: "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"})
	if got := e.attack.solves.ratePerMin(h2, time.Now()); got != 1 {
		t.Fatalf("bot-exempt: got %d want 1 (browser counted, bot skipped)", got)
	}
}
