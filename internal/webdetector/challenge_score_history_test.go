package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// End-to-end: a per-IP challenge score that reaches would_deny is persisted to the
// durable history store as event_type=challenge_score, keyed by the convicting
// fingerprint — the evidence ledger's SECOND source (after solver_farm). A score that
// only reaches would_harden is NOT persisted (lean: T2-only; would_harden stays
// log-only). And the per-IP hourly throttle stops a still-denying IP from writing a
// second row within the hour even when it is due to LOG again.
func TestChallengeScoreDurableCapture_DenyOnlyKeyedByFingerprint(t *testing.T) {
	ResetChallengeScoreMarks()
	ResetSolverFarmMarks()
	t.Cleanup(ResetSolverFarmMarks)
	t.Cleanup(ResetChallengeScoreMarks)

	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{cfg: Config{AbuseShadow: true}, history: hs}

	// The detector has convicted fingerprint c28caa00.
	MarkSolverFarmFingerprint("c28caa00", time.Minute)

	// IP-A: three convicted-fingerprint solves → ~120 ≥ T2 (would_deny).
	for i := 0; i < 3; i++ {
		e.RecordChallengeScoreSolve(ChallengeSolve{IP: "203.0.113.10", Host: "shop.example", TLSFP: "c28caa00"})
	}
	// IP-B: two convicted-fingerprint solves → ~80 ∈ [T1,T2) (would_harden only).
	for i := 0; i < 2; i++ {
		e.RecordChallengeScoreSolve(ChallengeSolve{IP: "203.0.113.20", Host: "shop.example", TLSFP: "c28caa00"})
	}

	e.emitChallengeScoreShadow(time.Now())

	rows, err := hs.QueryEvents("", "", "challenge_score", 50)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("persisted %d challenge_score rows, want 1 (would_deny only): %+v", len(rows), rows)
	}
	row := rows[0]
	if row.IP != "203.0.113.10" {
		t.Errorf("persisted IP = %q, want the would_deny IP 203.0.113.10", row.IP)
	}
	if row.Payload["fingerprint"] != "c28caa00" {
		t.Errorf("payload fingerprint = %v, want c28caa00", row.Payload["fingerprint"])
	}
	if row.Payload["fp_convicted"] != true {
		t.Errorf("payload fp_convicted = %v, want true", row.Payload["fp_convicted"])
	}
	if row.Payload["verdict"] != "would_deny" {
		t.Errorf("payload verdict = %v, want would_deny", row.Payload["verdict"])
	}
	if row.Score < chalScoreT2 {
		t.Errorf("persisted score = %v, want ≥ T2 %v", row.Score, chalScoreT2)
	}

	// Re-emit 11 minutes later: IP-A is due to LOG again (>10m) but NOT due to persist
	// (<1h) and is still decaying above T2 — so the hourly throttle must keep the row
	// count at 1. The 11-minute gap also clears the 2-minute emit run-throttle on its
	// own, so no need to reach into chalScoreLastRun.
	e.emitChallengeScoreShadow(time.Now().Add(11 * time.Minute))
	rows2, _ := hs.QueryEvents("", "", "challenge_score", 50)
	if len(rows2) != 1 {
		t.Errorf("second emit (log-due, persist-throttled) wrote %d rows, want still 1", len(rows2))
	}
}

// A would_deny driven with NO fingerprint (UA-lie / vhost-farm only, no X-CFM-TLS) is
// still persisted — it is a durable, IP-anchored deny record — but carries an empty
// fingerprint and fp_convicted=false, so the fleet rollup treats it as
// not-fingerprint-attributable (mirrors solver_farm's empty-fingerprint rows).
func TestChallengeScoreDurableCapture_NoFingerprintStillPersists(t *testing.T) {
	ResetChallengeScoreMarks()
	ResetSolverFarmMarks()
	t.Cleanup(ResetSolverFarmMarks)
	t.Cleanup(ResetChallengeScoreMarks)

	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{cfg: Config{AbuseShadow: true}, history: hs}

	// The vhost is a solver farm, but the solves carry no fingerprint. UA-lie (30) +
	// vhost-farm (15) = 45/solve; three solves → ~135 ≥ T2, no fp anywhere.
	MarkSolverFarm("farm.example", time.Minute)
	for i := 0; i < 3; i++ {
		e.RecordChallengeScoreSolve(ChallengeSolve{IP: "203.0.113.30", Host: "farm.example", UAImpossible: true, TLSFP: ""})
	}
	e.emitChallengeScoreShadow(time.Now())

	rows, err := hs.QueryEvents("", "", "challenge_score", 50)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("persisted %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Payload["fingerprint"] != "" {
		t.Errorf("payload fingerprint = %v, want empty", rows[0].Payload["fingerprint"])
	}
	if rows[0].Payload["fp_convicted"] != false {
		t.Errorf("payload fp_convicted = %v, want false", rows[0].Payload["fp_convicted"])
	}
	if rows[0].Payload["verdict"] != "would_deny" {
		t.Errorf("payload verdict = %v, want would_deny", rows[0].Payload["verdict"])
	}
}
