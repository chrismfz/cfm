package webdetector

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/detectors/core"
)

func newForceAttackEngine(t *testing.T, path string) *Engine {
	t.Helper()
	e := &Engine{cfg: Config{UnderAttack: true}, attack: newUnderAttackTracker(), attackOverrides: newAttackOverrideStore(path)}
	e.manualChal.init("")
	return e
}

func manualReason(e *Engine, host string) (bool, string) {
	active, _, reason := e.manualChal.active(host)
	return active, reason
}

// `attack on` arms the vhost's challenge when none covers it, for the same
// window; `attack off` removes that arm.
func TestForceVhostAttack_ArmsAndDisarmsItsChallenge(t *testing.T) {
	e := newForceAttackEngine(t, "")
	armed, exp := e.ForceVhostAttackAs("shop.example", true, 2*time.Hour, "admin")
	if !armed || time.Until(exp) <= time.Hour {
		t.Fatalf("attack on: armed=%v expires=%v", armed, exp)
	}
	if active, reason := manualReason(e, "shop.example"); !active || reason != attackArmReason {
		t.Fatalf("no challenge armed: active=%v reason=%q", active, reason)
	}
	if m, _, _ := e.vhostAttackKind("shop.example", time.Now()); !m {
		t.Fatal("override not set")
	}
	// A second `attack on` refreshes its own arm.
	if armed, _ := e.ForceVhostAttackAs("shop.example", true, 3*time.Hour, "admin"); !armed {
		t.Error("re-run of attack on must refresh the arm it made")
	}
	e.ForceVhostAttackAs("shop.example", false, 0, "admin")
	if active, _ := manualReason(e, "shop.example"); active {
		t.Error("attack off left the challenge it armed")
	}
	if m, _, _ := e.vhostAttackKind("shop.example", time.Now()); m {
		t.Error("attack off left the override")
	}
}

// An operator's own manual challenge is theirs: `attack on` does not take it
// over, and `attack off` never removes it.
func TestForceVhostAttack_LeavesAnOperatorsChallenge(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.ManualChallengeVhostAs("shop.example", time.Hour, "manual", "v2", "admin")
	if armed, _ := e.ForceVhostAttackAs("shop.example", true, 2*time.Hour, "admin"); armed {
		t.Fatal("attack on armed over an existing manual challenge")
	}
	e.ForceVhostAttackAs("shop.example", false, 0, "admin")
	if active, reason := manualReason(e, "shop.example"); !active || reason != "manual" {
		t.Fatalf("attack off removed the operator's challenge: active=%v reason=%q", active, reason)
	}

	// Armed by `attack on`, then re-armed by hand: `attack off` keeps theirs.
	e2 := newForceAttackEngine(t, "")
	e2.ForceVhostAttackAs("b.example", true, time.Hour, "admin")
	e2.ManualChallengeVhostAs("b.example", time.Hour, "manual", "", "admin")
	e2.ForceVhostAttackAs("b.example", false, 0, "admin")
	if active, reason := manualReason(e2, "b.example"); !active || reason != "manual" {
		t.Fatalf("attack off removed a hand re-arm: active=%v reason=%q", active, reason)
	}
}

// A www. host covered by its apex's manual challenge is not armed again.
func TestForceVhostAttack_ApexArmCoversWWW(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.ManualChallengeVhostAs("shop.example", time.Hour, "manual", "", "admin")
	if armed, _ := e.ForceVhostAttackAs("www.shop.example", true, time.Hour, "admin"); armed {
		t.Error("www. under an apex arm was armed again")
	}
}

// The override survives a reload: a new Engine on the same store restores it
// with its remaining window.
func TestForceVhostAttack_SurvivesAReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webdetector_attack_overrides.json")
	e1 := newForceAttackEngine(t, path)
	e1.ForceVhostAttackAs("shop.example", true, 2*time.Hour, "admin")
	e1.ForceVhostAttackAs("gone.example", true, time.Hour, "admin")
	e1.ForceVhostAttackAs("gone.example", false, 0, "admin")

	e2 := newForceAttackEngine(t, path)
	e2.restoreAttackOverrides()
	if m, _, _ := e2.vhostAttackKind("shop.example", time.Now()); !m {
		t.Fatal("override lost on reload")
	}
	if exp := overrideExpiry(e2, "shop.example"); time.Until(exp) <= time.Hour || time.Until(exp) > 2*time.Hour {
		t.Errorf("restored with the wrong window: %v", time.Until(exp))
	}
	if m, _, _ := e2.vhostAttackKind("gone.example", time.Now()); m {
		t.Error("a cleared override came back")
	}
	ent, ok := e2.attackOverrides.get("shop.example")
	if !ok || !ent.ArmedChallenge || ent.Actor != "admin" {
		t.Errorf("persisted entry: %+v ok=%v", ent, ok)
	}
	// `attack off` on the restored engine still removes the challenge its
	// `attack on` armed (here re-armed, as restoreManualChallenges would).
	e2.ManualChallengeVhostAs("shop.example", time.Until(ent.ArmExpiresAt), attackArmReason, "", "admin")
	e2.ForceVhostAttackAs("shop.example", false, 0, "admin")
	if active, _ := manualReason(e2, "shop.example"); active {
		t.Error("attack off after a reload left the arm")
	}
}

// An expired entry is never restored.
func TestAttackOverrideStore_DropsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	s := newAttackOverrideStore(path)
	s.set(attackOverrideEntry{Host: "old.example", ExpiresAt: time.Now().Add(-time.Minute)})
	s.set(attackOverrideEntry{Host: "new.example", ExpiresAt: time.Now().Add(time.Hour)})
	got := loadAttackOverrideFileForTest(path).snapshot()
	if len(got) != 1 || got[0].Host != "new.example" {
		t.Fatalf("restored %+v, want only new.example", got)
	}
}

// A cfm.allow bypass drops the persisted override and the challenge its
// `attack on` armed (the bypass only clears the bridge), so nothing comes back
// with no override behind it.
func TestDeescalateDropsThePersistedOverrideAndItsArm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	e := newForceAttackEngine(t, path)
	e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	e.deescalateUnderAttack(time.Now(), "shop.example", "challenge suppressed (bypass)", nil)
	if _, ok := e.attackOverrides.get("shop.example"); ok {
		t.Fatal("suppression left the persisted override")
	}
	if len(loadAttackOverrideFileForTest(path).snapshot()) != 0 {
		t.Fatal("suppression left it on disk")
	}
	if active, _ := manualReason(e, "shop.example"); active {
		t.Fatal("suppression left the challenge attack on armed")
	}
}

// The under_attack reason alone does not make an arm the override's: an
// operator's own arm with that reason is neither refreshed by `attack on`
// nor removed by `attack off`.
func TestForceVhostAttack_OperatorsUnderAttackArmIsTheirs(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.ManualChallengeVhostAs("shop.example", 168*time.Hour, attackArmReason, "", "admin")
	_, before, _ := e.manualChal.active("shop.example")
	if armed, _ := e.ForceVhostAttackAs("shop.example", true, 0, "tenant"); armed {
		t.Fatal("attack on took over an operator's under_attack arm")
	}
	if _, after, _ := e.manualChal.active("shop.example"); !after.Equal(before) {
		t.Fatalf("operator's arm re-armed: %v -> %v", before, after)
	}
	e.ForceVhostAttackAs("shop.example", false, 0, "tenant")
	if active, _ := manualReason(e, "shop.example"); !active {
		t.Fatal("attack off removed an operator's under_attack arm")
	}
	// Nor with no record at all.
	e2 := newForceAttackEngine(t, "")
	e2.ManualChallengeVhostAs("shop.example", time.Hour, attackArmReason, "", "admin")
	e2.ForceVhostAttackAs("shop.example", false, 0, "admin")
	if active, _ := manualReason(e2, "shop.example"); !active {
		t.Fatal("attack off with no record removed an under_attack arm")
	}
}

// A second `attack on` refreshes the arm the first one made.
func TestForceVhostAttack_RefreshesItsOwnArm(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	armed, exp := e.ForceVhostAttackAs("shop.example", true, 3*time.Hour, "admin")
	_, armExp, _ := e.manualChal.active("shop.example")
	if !armed || armExp.Sub(exp) > time.Second || exp.Sub(armExp) > time.Second {
		t.Fatalf("armed=%v arm %v override %v", armed, armExp, exp)
	}
	e.ForceVhostAttackAs("shop.example", false, 0, "admin")
	if active, _ := manualReason(e, "shop.example"); active {
		t.Fatal("attack off left the refreshed arm")
	}
}

// An operator's tier pin decides the tier of the arm: a manual v2 arm
// outranks every pin, so a v1 pin must make it a v1 arm.
func TestForceVhostAttack_FollowsATierPin(t *testing.T) {
	def, _ := manualDefaultRungFor("shop.example") // no pin: the node default
	for _, tc := range []struct{ pin, want string }{{"v1", ""}, {"v2", "v2"}, {"", def}} {
		e := newForceAttackEngine(t, "")
		e.tierPins = sharedTierPinStore("")
		if tc.pin != "" {
			if _, _, _, refusal, _ := e.tierPins.applyPin("shop.example", tc.pin, time.Hour, "admin", nil, nil); refusal != "" {
				t.Fatal(refusal)
			}
		}
		e.ForceVhostAttackAs("shop.example", true, 0, "admin")
		if got := e.manualChal.rung("shop.example"); got != tc.want {
			t.Errorf("pin %q: arm rung %q, want %q", tc.pin, got, tc.want)
		}
	}
}

// A reload's window: an `attack on` through the old Engine after the new one
// loaded the file must not be overwritten by the new Engine's next save (one
// store per file), so the following reload restores it.
func TestForceVhostAttack_ReloadWindowKeepsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webdetector_attack_overrides.json")
	old := newForceAttackEngine(t, path)
	nu := newForceAttackEngine(t, path)
	old.ForceVhostAttackAs("a.example", true, time.Hour, "admin")
	nu.ForceVhostAttackAs("b.example", true, time.Hour, "admin")
	if got := len(loadAttackOverrideFileForTest(path).snapshot()); got != 2 {
		t.Fatalf("file holds %d overrides, want 2", got)
	}
}

// The arm expires with the override.
func TestForceVhostAttack_ArmExpiresWithTheOverride(t *testing.T) {
	e := newForceAttackEngine(t, "")
	_, exp := e.ForceVhostAttackAs("shop.example", true, 90*time.Minute, "admin")
	_, armExp, _ := e.manualChal.active("shop.example")
	if d := armExp.Sub(exp); d < -time.Second || d > time.Second {
		t.Fatalf("arm expires %v, override %v", armExp, exp)
	}
}

// A restored override is seeded as already ON: the first tick sees no
// transition, so a reload sends no second ON alert or history row.
func TestRestoreAttackOverrides_NoSecondOnAlert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	e1 := newForceAttackEngine(t, path)
	e1.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	out1 := make(chan core.Alert, 4)
	e1.evalUnderAttack(time.Now(), "shop.example", true, SuspiciousRow{Host: "shop.example"}, out1)
	if len(out1) != 1 {
		t.Fatalf("attack on sent %d ON alerts, want 1", len(out1))
	}

	e2 := newForceAttackEngine(t, path)
	e2.restoreAttackOverrides()
	out := make(chan core.Alert, 4)
	e2.evalUnderAttack(time.Now(), "shop.example", true, SuspiciousRow{Host: "shop.example"}, out)
	if len(out) != 0 {
		t.Fatalf("a reload sent %d alert(s): %+v", len(out), <-out)
	}
	if on, _, _ := e2.VhostAttackState("shop.example"); !on {
		t.Fatal("restored vhost not under attack")
	}

	// Control: a fresh `attack on` does send its ON on the first tick.
	e3 := newForceAttackEngine(t, "")
	e3.ForceVhostAttackAs("fresh.example", true, time.Hour, "admin")
	out3 := make(chan core.Alert, 4)
	e3.evalUnderAttack(time.Now(), "fresh.example", true, SuspiciousRow{Host: "fresh.example"}, out3)
	if len(out3) != 1 {
		t.Fatalf("a fresh attack on sent %d alerts, want 1", len(out3))
	}
}

// The CLI's --ttl reaches the API as ttl=, and is refused on `attack off`.
func TestRunAttackWebTop_TTLFlag(t *testing.T) {
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.RawQuery)
		_, _ = w.Write([]byte(`{"host":"x.gr","attack":true,"ttl":"2h0m0s","expires_at":"2026-11-17T12:00:00Z","challenge_armed":true}`))
	}))
	defer ts.Close()
	for _, args := range [][]string{{"on", "x.gr", "--ttl", "2h"}, {"on", "x.gr", "--ttl=2h"}} {
		got = nil
		if err := runAttackWebTop(ts.URL, args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if len(got) != 1 || !strings.Contains(got[0], "ttl=2h") || !strings.Contains(got[0], "on=1") {
			t.Fatalf("%v sent %v", args, got)
		}
	}
	if err := runAttackWebTop(ts.URL, []string{"off", "x.gr", "--ttl", "2h"}); err == nil {
		t.Error("--ttl on attack off must be refused")
	}
	if err := runAttackWebTop(ts.URL, []string{"on", "x.gr", "--bogus"}); err == nil {
		t.Error("an unknown flag must be refused")
	}
}

// A reload before the old Engine's first tick: the ON was never alerted, so
// the new Engine sends it (once).
func TestRestoreAttackOverrides_UnannouncedGetsItsOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	e1 := newForceAttackEngine(t, path)
	e1.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	e2 := newForceAttackEngine(t, path)
	e2.restoreAttackOverrides()
	out := make(chan core.Alert, 4)
	e2.evalUnderAttack(time.Now(), "shop.example", true, SuspiciousRow{Host: "shop.example"}, out)
	e2.evalUnderAttack(time.Now(), "shop.example", true, SuspiciousRow{Host: "shop.example"}, out)
	if len(out) != 1 {
		t.Fatalf("got %d ON alerts across the reload, want 1", len(out))
	}
}

// A restart: both stores come back from their files (JSON round trip), and
// `attack off` still recognises and removes the arm its `attack on` made.
func TestForceVhostAttack_SurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	opath, mpath := filepath.Join(dir, "o.json"), filepath.Join(dir, "m.json")
	e1 := newForceAttackEngine(t, opath)
	e1.manualChal.init(mpath)
	if armed, _ := e1.ForceVhostAttackAs("shop.example", true, 2*time.Hour, "admin"); !armed {
		t.Fatal("not armed")
	}
	resetAttackOverrideStoresForTest()
	t.Cleanup(resetAttackOverrideStoresForTest)
	e2 := newForceAttackEngine(t, opath)
	e2.manualChal.init(mpath)
	e2.restoreAttackOverrides()
	ent, ok := e2.attackOverrides.get("shop.example")
	if !ok || !e2.ownsArm("shop.example", ent) {
		t.Fatalf("after a restart the arm is not the override's: %+v ok=%v", ent, ok)
	}
	e2.ForceVhostAttackAs("shop.example", false, 0, "admin")
	if active, _ := manualReason(e2, "shop.example"); active {
		t.Fatal("attack off after a restart left the arm")
	}
}

// A second `attack on` after the operator re-armed the vhost by hand leaves
// their arm (reason, expiry) alone.
func TestForceVhostAttack_SecondOnKeepsAHandReArm(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	e.ManualChallengeVhostAs("shop.example", 3*time.Hour, "manual", "", "admin")
	_, before, _ := e.manualChal.active("shop.example")
	if armed, _ := e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin"); armed {
		t.Fatal("the second attack on took over a hand re-arm")
	}
	_, after, reason := e.manualChal.active("shop.example")
	if reason != "manual" || !after.Equal(before) {
		t.Fatalf("hand re-arm changed: reason %q, %v -> %v", reason, before, after)
	}
}

// A refresh keeps the arm's tier: a pin set after the first `attack on` does
// not re-tier it.
func TestForceVhostAttack_RefreshKeepsTheArmsTier(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.tierPins = sharedTierPinStore("")
	e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	first := e.manualChal.rung("shop.example")
	other := "v1"
	if first == "" {
		other = "v2"
	}
	if _, _, _, refusal, _ := e.tierPins.applyPin("shop.example", other, time.Hour, "admin", nil, nil); refusal != "" {
		t.Fatal(refusal)
	}
	e.ForceVhostAttackAs("shop.example", true, 2*time.Hour, "admin")
	if got := e.manualChal.rung("shop.example"); got != first {
		t.Fatalf("refresh re-tiered the arm: %q -> %q", first, got)
	}
}

// A vhost already in the automatic ON state gets `attack on`: no ON transition
// comes for the override, so it is persisted as announced, and a restart (the
// store read back from its file) sends no ON alert.
func TestForceVhostAttack_AutoOnThenAttackOnRestartsQuietly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	e1 := newForceAttackEngine(t, path)
	since := time.Now().Add(-time.Hour).Truncate(time.Second)
	e1.attack.mu.Lock()
	e1.attack.hosts["shop.example"] = &attackVhost{on: true, since: since}
	e1.attack.mu.Unlock()
	e1.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")

	resetAttackOverrideStoresForTest()
	t.Cleanup(resetAttackOverrideStoresForTest)
	e2 := newForceAttackEngine(t, path)
	ent, ok := e2.attackOverrides.get("shop.example")
	if !ok || !ent.Announced || !ent.Since.Equal(since) {
		t.Fatalf("persisted announcement: %+v ok=%v", ent, ok)
	}
	e2.restoreAttackOverrides()
	out := make(chan core.Alert, 4)
	e2.evalUnderAttack(time.Now(), "shop.example", true, SuspiciousRow{Host: "shop.example"}, out)
	if len(out) != 0 {
		t.Fatalf("restart sent %d alert(s)", len(out))
	}
	if _, s, _ := e2.VhostAttackState("shop.example"); !s.Equal(since) {
		t.Fatalf("since reset on restore: %v, want %v", s, since)
	}
}

// A refresh keeps the announcement, also when the ON alert was sent between
// its read and its write (the store keeps it).
func TestForceVhostAttack_RefreshKeepsTheAnnouncement(t *testing.T) {
	e := newForceAttackEngine(t, "")
	e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	e.evalUnderAttack(time.Now(), "shop.example", true, SuspiciousRow{Host: "shop.example"}, make(chan core.Alert, 4))
	e.ForceVhostAttackAs("shop.example", true, 2*time.Hour, "admin")
	if ent, _ := e.attackOverrides.get("shop.example"); !ent.Announced {
		t.Fatal("a refresh lost the announcement")
	}
	// The store keeps it even against a write that carries none.
	ent, _ := e.attackOverrides.get("shop.example")
	ent.Announced = false
	e.attackOverrides.set(ent)
	if got, _ := e.attackOverrides.get("shop.example"); !got.Announced {
		t.Fatal("set dropped an announcement")
	}
}

// An expired record does not lend its announcement to a new override.
func TestAttackOverrideStore_ExpiredAnnouncementNotInherited(t *testing.T) {
	s := newAttackOverrideStore("")
	s.set(attackOverrideEntry{Host: "h.example", ExpiresAt: time.Now().Add(-time.Minute), Announced: true})
	s.set(attackOverrideEntry{Host: "h.example", ExpiresAt: time.Now().Add(time.Hour)})
	if got, _ := s.get("h.example"); got.Announced {
		t.Fatal("a new override inherited an expired announcement")
	}
}
