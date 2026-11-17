package webdetector

import (
	"path/filepath"
	"testing"
	"time"
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
	e2.ManualChallengeVhostAs("shop.example", time.Hour, attackArmReason, "", "admin")
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
	got := newAttackOverrideStore(path).snapshot()
	if len(got) != 1 || got[0].Host != "new.example" {
		t.Fatalf("restored %+v, want only new.example", got)
	}
}

// A full suppression (cfm.allow, exclude) drops the persisted override too,
// or the next reload would bring it back.
func TestDeescalateDropsThePersistedOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	e := newForceAttackEngine(t, path)
	e.ForceVhostAttackAs("shop.example", true, time.Hour, "admin")
	e.deescalateUnderAttack(time.Now(), "shop.example", "challenge suppressed (excluded)", nil)
	if _, ok := e.attackOverrides.get("shop.example"); ok {
		t.Fatal("suppression left the persisted override")
	}
	if len(newAttackOverrideStore(path).snapshot()) != 0 {
		t.Fatal("suppression left it on disk")
	}
}
