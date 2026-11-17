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
