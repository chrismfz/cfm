package webdetector

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func TestChalSolveDelta(t *testing.T) {
	base := ChallengeSolve{IP: "1.2.3.4", Host: "h"} // SolveMS 0 = unknown, UA ok
	if d, fast, ua := chalSolveDelta(base, false); d != chalScoreWSolve || fast || ua {
		t.Errorf("plain solve = %v fast=%v ua=%v, want %v/false/false", d, fast, ua, chalScoreWSolve)
	}
	// A fast solve adds wFast; unknown latency (<=0) must NOT count as fast.
	fastS := ChallengeSolve{IP: "1.2.3.4", SolveMS: chalScoreFastMS - 1}
	if d, fast, _ := chalSolveDelta(fastS, false); !fast || d != chalScoreWSolve+chalScoreWFast {
		t.Errorf("fast solve = %v fast=%v, want %v/true", d, fast, chalScoreWSolve+chalScoreWFast)
	}
	if _, fast, _ := chalSolveDelta(ChallengeSolve{SolveMS: 0}, false); fast {
		t.Errorf("unknown latency counted as fast")
	}
	// Exactly at the floor is NOT fast (strict <).
	if _, fast, _ := chalSolveDelta(ChallengeSolve{SolveMS: chalScoreFastMS}, false); fast {
		t.Errorf("solve exactly at fast floor counted as fast")
	}
	// UA-impossible + farm stack.
	imp := ChallengeSolve{IP: "1.2.3.4", UAImpossible: true}
	if d, _, ua := chalSolveDelta(imp, true); !ua || d != chalScoreWSolve+chalScoreWUAImp+chalScoreWFarm {
		t.Errorf("ua+farm = %v ua=%v, want %v", d, ua, chalScoreWSolve+chalScoreWUAImp+chalScoreWFarm)
	}
	// Everything at once.
	all := ChallengeSolve{IP: "1.2.3.4", SolveMS: 100, UAImpossible: true}
	if d, _, _ := chalSolveDelta(all, true); d != chalScoreWSolve+chalScoreWFast+chalScoreWUAImp+chalScoreWFarm {
		t.Errorf("all-signals delta = %v, want %v", d, chalScoreWSolve+chalScoreWFast+chalScoreWUAImp+chalScoreWFarm)
	}
}

func TestChalDecay(t *testing.T) {
	now := time.Now()
	if got := chalDecay(100, now.Add(-chalScoreHalfLife), now); math.Abs(got-50) > 1e-6 {
		t.Errorf("one half-life = %v, want 50", got)
	}
	if got := chalDecay(100, now.Add(-2*chalScoreHalfLife), now); math.Abs(got-25) > 1e-6 {
		t.Errorf("two half-lives = %v, want 25", got)
	}
	if got := chalDecay(100, now, now); got != 100 {
		t.Errorf("no elapsed = %v, want 100", got)
	}
	if got := chalDecay(100, time.Time{}, now); got != 0 {
		t.Errorf("zero last = %v, want 0", got)
	}
}

func TestChalScoreVerdict(t *testing.T) {
	if v := chalScoreVerdict(chalScoreT1 - 0.1); v != "" {
		t.Errorf("below T1 = %q, want empty", v)
	}
	if v := chalScoreVerdict(chalScoreT1); v != "would_harden" {
		t.Errorf("at T1 = %q, want would_harden", v)
	}
	if v := chalScoreVerdict(chalScoreT2); v != "would_deny" {
		t.Errorf("at T2 = %q, want would_deny", v)
	}
}

// Re-solves accumulate (each solve adds, the decay fades a lone one) — the core
// cookie-discard signal expressed as a climbing score.
func TestChalScoreBump_AccumulateAndDecay(t *testing.T) {
	ResetChallengeScoreMarks()
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		challengeScoreMarks.bump("9.9.9.9", chalScoreWSolve, false, false, false, t0.Add(time.Duration(i)*time.Second))
	}
	rows := challengeScoreMarks.collectDue(t0.Add(3*time.Second), 0, 0)
	if len(rows) != 1 || rows[0].solves != 3 || math.Abs(rows[0].score-30) > 0.1 {
		t.Fatalf("accumulate = %+v, want 1 row score~30 solves3", rows)
	}
	// A half-life later, the same IP with no new solves decays to ~15.
	rows = challengeScoreMarks.collectDue(t0.Add(chalScoreHalfLife), 0, 0)
	if len(rows) != 1 || math.Abs(rows[0].score-15) > 0.5 {
		t.Errorf("after one half-life = %+v, want score~15", rows)
	}
}

// collectDue prunes IPs decayed below epsilon and only returns those at/above the floor.
func TestChalScoreCollectDue_PruneAndFloor(t *testing.T) {
	ResetChallengeScoreMarks()
	t0 := time.Now()
	challengeScoreMarks.bump("low", 20, false, false, false, t0)  // below T1
	challengeScoreMarks.bump("high", 60, false, false, false, t0) // above T1
	challengeScoreMarks.bump("ghost", 2, false, false, false, t0)

	rows := challengeScoreMarks.collectDue(t0, chalScoreT1, 0)
	if len(rows) != 1 || rows[0].ip != "high" {
		t.Fatalf("floor filter = %+v, want only 'high'", rows)
	}
	// Far in the future everything decays below epsilon → pruned; store emptied.
	_ = challengeScoreMarks.collectDue(t0.Add(20*chalScoreHalfLife), 0, 0)
	if n := len(challengeScoreMarks.collectDue(t0.Add(20*chalScoreHalfLife), 0, 0)); n != 0 {
		t.Errorf("expected all pruned, got %d rows", n)
	}
}

// The per-IP log throttle lives on the mark: an over-threshold IP logs once, then
// not again until logEvery has passed — and the throttle state is bounded by the
// store (no growth in the shared suppress map).
func TestChalScoreLogThrottle(t *testing.T) {
	ResetChallengeScoreMarks()
	t0 := time.Now()
	// Seed high enough that the score is still ≥ T1 after one logEvery of decay
	// (120·2^(-10/30) ≈ 95), so this test isolates the THROTTLE, not decay.
	challengeScoreMarks.bump("7.7.7.7", 120, false, false, false, t0)

	if n := len(challengeScoreMarks.collectDue(t0, chalScoreT1, chalScoreLogEvery)); n != 1 {
		t.Fatalf("first pass returned %d, want 1", n)
	}
	// Within logEvery → suppressed (score still well above T1).
	if n := len(challengeScoreMarks.collectDue(t0.Add(chalScoreLogEvery/2), chalScoreT1, chalScoreLogEvery)); n != 0 {
		t.Errorf("second pass within logEvery returned %d, want 0", n)
	}
	// After logEvery → due again (score still ≈95 ≥ T1).
	if n := len(challengeScoreMarks.collectDue(t0.Add(chalScoreLogEvery+time.Second), chalScoreT1, chalScoreLogEvery)); n != 1 {
		t.Errorf("third pass after logEvery returned %d, want 1", n)
	}
}

// The store cap rejects NEW IPs once full (prune is the snapshot's job); existing
// IPs still update. Bounds memory under a huge distinct-IP flood.
func TestChalScoreCapRejection(t *testing.T) {
	ResetChallengeScoreMarks()
	now := time.Now()
	for i := 0; i < maxChalScoreMarks; i++ {
		challengeScoreMarks.bump(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), chalScoreWSolve, false, false, false, now)
	}
	challengeScoreMarks.mu.Lock()
	full := len(challengeScoreMarks.ips)
	challengeScoreMarks.mu.Unlock()
	if full != maxChalScoreMarks {
		t.Fatalf("store holds %d, want cap %d", full, maxChalScoreMarks)
	}
	// A brand-new IP at the cap is rejected…
	challengeScoreMarks.bump("203.0.113.1", chalScoreWSolve, false, false, false, now)
	challengeScoreMarks.mu.Lock()
	after := len(challengeScoreMarks.ips)
	challengeScoreMarks.mu.Unlock()
	if after != maxChalScoreMarks {
		t.Errorf("cap breached: %d, want %d", after, maxChalScoreMarks)
	}
	// …but an EXISTING IP still accumulates (not blocked by the cap).
	challengeScoreMarks.bump("10.0.0.0", chalScoreWSolve, false, false, false, now)
	rows := challengeScoreMarks.collectDue(now, 0, 0)
	var got *chalScoreRow
	for i := range rows {
		if rows[i].ip == "10.0.0.0" {
			got = &rows[i]
		}
	}
	if got == nil || got.solves != 2 {
		t.Errorf("existing IP at cap not updated: %+v", got)
	}
}

// bump (event goroutines) and collectDue (tick goroutine) hit the same mutex; -race
// must stay clean.
func TestChalScoreConcurrent(t *testing.T) {
	ResetChallengeScoreMarks()
	now := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				challengeScoreMarks.bump(fmt.Sprintf("192.168.%d.%d", g, i%64), chalScoreWSolve, i%2 == 0, i%3 == 0, i%5 == 0, now.Add(time.Duration(i)*time.Millisecond))
				if i%50 == 0 {
					_ = challengeScoreMarks.collectDue(now.Add(time.Duration(i)*time.Millisecond), chalScoreT1, 0)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestChalScore_ResetIsolation(t *testing.T) {
	ResetChallengeScoreMarks()
	challengeScoreMarks.bump("1.1.1.1", 100, false, false, false, time.Now())
	ResetChallengeScoreMarks()
	if n := len(challengeScoreMarks.collectDue(time.Now(), 0, 0)); n != 0 {
		t.Errorf("reset left %d rows", n)
	}
}

// The event callback folds a solve in, and stays silent when the master is off.
func TestRecordChallengeScoreSolve_Gate(t *testing.T) {
	ResetChallengeScoreMarks()
	on := &Engine{cfg: Config{AbuseShadow: true}}
	on.RecordChallengeScoreSolve(ChallengeSolve{IP: "5.5.5.5", UAImpossible: true})
	if rows := challengeScoreMarks.collectDue(time.Now(), 0, 0); len(rows) != 1 || rows[0].uaImp != 1 {
		t.Fatalf("solve not recorded / breakdown wrong: %+v", rows)
	}
	ResetChallengeScoreMarks()
	off := &Engine{cfg: Config{AbuseShadow: false}}
	off.RecordChallengeScoreSolve(ChallengeSolve{IP: "5.5.5.5"})
	if n := len(challengeScoreMarks.collectDue(time.Now(), 0, 0)); n != 0 {
		t.Errorf("master off still recorded (%d rows)", n)
	}
}
