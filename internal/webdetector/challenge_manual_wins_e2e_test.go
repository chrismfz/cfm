package webdetector

import (
	"path/filepath"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// End-to-end coverage of the "manual wins over exclude" guard by driving the
// real tick (emitIPChallenges), closing review finding #6: the predicate tests
// prove manualChallengeCoversClear/hostChallengeExcluded return the right
// booleans, but only this exercises the actual guard BEHAVIOUR — that the guard
// keeps (does not clear) the bridge entry for a manual+excluded candidate, and
// still clears an excluded candidate with no manual. A regression that dropped
// the keep branch or called ClearVhost would fail here but pass the predicates.
func newTickTestEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine(Config{
		Every:         time.Second,
		Window:        2 * time.Minute,
		// Non-existent sock → bridge Enabled, POSTs fail fast, but the local
		// vhState is updated before posting (same trick as the socket-only test).
		OpenRestySock: "/nonexistent/cfm_manualwins_test.sock",
		// haveVhostAuto → the per-host candidate loop (where the guards live) runs.
		ChallengeSuspiciousVHost: true,
	})
	if e.nginxBridge == nil {
		t.Fatal("precondition: expected an nginx bridge in OpenResty mode")
	}
	if e.vhostUnderAttack == nil {
		e.vhostUnderAttack = map[string]bool{}
	}
	if e.vhostLastChange == nil {
		e.vhostLastChange = map[string]time.Time{}
	}
	// Use an isolated tempdir-backed exclude store. NewEngine's default store
	// (via FillDefaults) points at the SHARED real path
	// /var/lib/cfm/webdetector_challenge_excludes.json and its Add persists
	// there, so tests sharing it both pollute a system path and see
	// non-deterministic "already exists" Add failures across runs. A per-test
	// tempdir keeps Add deterministic and writes nothing outside the test.
	e.challengeExcludes = newExcludeStore(filepath.Join(t.TempDir(), "ch.json"))
	return e
}

func bridgeHasVhost(e *Engine, host string) bool {
	for _, v := range e.nginxBridge.Status().ActiveVhosts {
		if v == host {
			return true
		}
	}
	return false
}

func TestEmitIPChallenges_ManualKeptOverExclude(t *testing.T) {
	e := newTickTestEngine(t)
	host := "shop.gr"

	// Host is excluded from auto challenges AND explicitly manually challenged,
	// and is a live candidate (under-attack flag makes it one).
	if !e.challengeExcludes.Add("host", host, map[string]struct{}{host: {}}) {
		t.Fatal("add exclude failed")
	}
	e.ManualChallengeVhost(host, time.Hour, "manual") // pushes apex + www to the bridge
	e.vhostUnderAttack[host] = true

	if !bridgeHasVhost(e, host) {
		t.Fatal("precondition: manual challenge should be on the bridge before the tick")
	}

	out := make(chan core.Alert, 16)
	e.emitIPChallenges(time.Now(), out)

	// The exclude guard must have KEPT the manual challenge, not cleared it.
	if !bridgeHasVhost(e, host) {
		t.Fatal("regression: exclude guard cleared a manually-challenged host (manual must win over exclude)")
	}
}

// countOffAlerts drains out and returns how many WEB/VHOST_CHALLENGE_OFF alerts
// it carried for host.
func countOffAlerts(out chan core.Alert, host string) int {
	n := 0
	for {
		select {
		case a := <-out:
			if string(a.Kind) == "WEB/VHOST_CHALLENGE_OFF" && a.Key == host {
				n++
			}
		default:
			return n
		}
	}
}

// The auto cool-down (offOK) must NOT emit a "challenge lifted"
// (WEB/VHOST_CHALLENGE_OFF) alert when a manual challenge still holds the vhost
// — the challenge did not lift. A negative control (same setup, no manual)
// proves the alert WOULD otherwise fire, so its absence is the fix, not the
// test failing to reach the path. An empty longwin row scores 0, so
// offOK=(0<=off) is true with default thresholds — no score plumbing needed.
func TestEmitIPChallenges_AutoCooldownKeepsManual_NoOffAlert(t *testing.T) {
	mk := func() *Engine {
		e := newTickTestEngine(t)
		e.cfg.ChallengeNotify = true
		e.longwin = NewLongWindow(10*time.Minute, time.Minute, nil) // empty → score 0 → offOK
		return e
	}

	t.Run("manual held → no OFF alert, challenge kept", func(t *testing.T) {
		e := mk()
		host := "held.gr"
		e.ManualChallengeVhost(host, time.Hour, "manual")
		e.vhostUnderAttack[host] = true // currently ON → offOK path

		out := make(chan core.Alert, 16)
		e.emitIPChallenges(time.Now(), out)

		if got := countOffAlerts(out, host); got != 0 {
			t.Fatalf("regression: auto cool-down emitted %d false CHALLENGE_OFF alert(s) while manual held the vhost", got)
		}
		if !bridgeHasVhost(e, host) {
			t.Fatal("manual challenge should still be on the bridge after the auto cool-down")
		}
	})

	t.Run("negative control: no manual → OFF alert fires", func(t *testing.T) {
		e := mk()
		host := "lifts.gr"
		e.nginxBridge.ChallengeVhostWithReason(host, time.Hour, "suspicious_vhost")
		e.vhostUnderAttack[host] = true

		out := make(chan core.Alert, 16)
		e.emitIPChallenges(time.Now(), out)

		if got := countOffAlerts(out, host); got == 0 {
			t.Fatal("control failed: expected a CHALLENGE_OFF alert when auto cools with no manual (path not reached?)")
		}
		if bridgeHasVhost(e, host) {
			t.Fatal("auto cool-down with no manual should have cleared the vhost")
		}
	})
}

func TestEmitIPChallenges_ExcludeClearsWhenNoManual(t *testing.T) {
	e := newTickTestEngine(t)
	host := "plain.gr"

	// A vhost challenge is present (e.g. from the suspicious scorer), the host is
	// excluded and a candidate, but there is NO manual challenge → the exclude
	// guard must clear it.
	e.nginxBridge.ChallengeVhostWithReason(host, time.Hour, "suspicious_vhost")
	if !bridgeHasVhost(e, host) {
		t.Fatal("precondition: challenge should be on the bridge before the tick")
	}
	if !e.challengeExcludes.Add("host", host, map[string]struct{}{host: {}}) {
		t.Fatal("add exclude failed")
	}
	e.vhostUnderAttack[host] = true

	out := make(chan core.Alert, 16)
	e.emitIPChallenges(time.Now(), out)

	if bridgeHasVhost(e, host) {
		t.Fatal("exclude guard should have cleared a non-manual excluded host")
	}
}
