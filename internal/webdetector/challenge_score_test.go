package webdetector

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func TestChalSolveDelta(t *testing.T) {
	// A no-tell solve scores NOTHING (no flat per-solve base): a benign NAT where
	// every user solves once must never accumulate.
	base := ChallengeSolve{IP: "1.2.3.4", Host: "h"} // SolveMS 0 = unknown, UA ok, no farm, no farmFP
	if d, fast, ua := chalSolveDelta(base, false, false); d != 0 || fast || ua {
		t.Errorf("plain solve = %v fast=%v ua=%v, want 0/false/false", d, fast, ua)
	}
	// CORROBORATION GATE: a fast solve with NO strong tell scores 0 — fast is an
	// amplifier, not an opener. (~15-23% of honest browser solves are fast at
	// difficulty 16, so fast alone would light up a busy NAT egress.) fast=true is
	// still reported so the caller sees the tell fired, but it adds no weight alone.
	fastOnly := ChallengeSolve{IP: "1.2.3.4", SolveMS: chalScoreFastMS - 1}
	if d, fast, _ := chalSolveDelta(fastOnly, false, false); !fast || d != 0 {
		t.Errorf("fast-only = %v fast=%v, want 0/true (amplifier, no strong tell)", d, fast)
	}
	if _, fast, _ := chalSolveDelta(ChallengeSolve{SolveMS: 0}, false, false); fast {
		t.Errorf("unknown latency counted as fast")
	}
	// Exactly at the floor is NOT fast (strict <).
	if d, fast, _ := chalSolveDelta(ChallengeSolve{SolveMS: chalScoreFastMS}, false, false); fast || d != 0 {
		t.Errorf("solve exactly at fast floor = %v fast=%v, want 0/false", d, fast)
	}
	// Farm (vhost) alone (a strong tell) opens a score: wFarm.
	if d, _, _ := chalSolveDelta(ChallengeSolve{IP: "1.2.3.4"}, true, false); d != chalScoreWFarm {
		t.Errorf("farm-only = %v, want %v", d, chalScoreWFarm)
	}
	// Fingerprint conviction alone (the SPINE) opens a score: wFarmFP, the dominant
	// single tell (> vhost-farm and > UA-lie).
	if d, fast, ua := chalSolveDelta(ChallengeSolve{IP: "1.2.3.4", TLSFP: "c28caa00"}, false, true); d != chalScoreWFarmFP || fast || ua {
		t.Errorf("farmFP-only = %v, want %v (spine opener)", d, chalScoreWFarmFP)
	}
	if chalScoreWFarmFP <= chalScoreWFarm || chalScoreWFarmFP <= chalScoreWUAImp {
		t.Errorf("fingerprint spine weight %v must dominate farm(%v) and uaImp(%v)", chalScoreWFarmFP, chalScoreWFarm, chalScoreWUAImp)
	}
	// Fast AMPLIFIES the fingerprint spine (farmFP is a strong tell): wFarmFP+wFast.
	if d, fast, _ := chalSolveDelta(ChallengeSolve{SolveMS: chalScoreFastMS - 1}, false, true); !fast || d != chalScoreWFarmFP+chalScoreWFast {
		t.Errorf("farmFP+fast = %v fast=%v, want %v", d, fast, chalScoreWFarmFP+chalScoreWFast)
	}
	// Fast AMPLIFIES a strong tell: farm+fast = wFarm+wFast.
	if d, fast, _ := chalSolveDelta(ChallengeSolve{SolveMS: chalScoreFastMS - 1}, true, false); !fast || d != chalScoreWFarm+chalScoreWFast {
		t.Errorf("farm+fast = %v fast=%v, want %v", d, fast, chalScoreWFarm+chalScoreWFast)
	}
	// UA-lie + fast = wUAImp+wFast.
	if d, _, ua := chalSolveDelta(ChallengeSolve{UAImpossible: true, SolveMS: 100}, false, false); !ua || d != chalScoreWUAImp+chalScoreWFast {
		t.Errorf("ua+fast = %v ua=%v, want %v", d, ua, chalScoreWUAImp+chalScoreWFast)
	}
	// UA-impossible + farm stack (both strong, no fast).
	imp := ChallengeSolve{IP: "1.2.3.4", UAImpossible: true}
	if d, _, ua := chalSolveDelta(imp, true, false); !ua || d != chalScoreWUAImp+chalScoreWFarm {
		t.Errorf("ua+farm = %v ua=%v, want %v", d, ua, chalScoreWUAImp+chalScoreWFarm)
	}
	// Everything at once: spine + vhost-farm + UA-lie + fast amplifier.
	all := ChallengeSolve{IP: "1.2.3.4", SolveMS: 100, UAImpossible: true, TLSFP: "c28caa00"}
	want := chalScoreWFarmFP + chalScoreWFast + chalScoreWUAImp + chalScoreWFarm
	if d, _, _ := chalSolveDelta(all, true, true); d != want {
		t.Errorf("all-signals delta = %v, want %v", d, want)
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

// Store mechanic: tell-bearing solves accumulate (each adds its delta, the decay
// fades a lone one). The store just sums the deltas it is fed; which solves EARN a
// delta is chalSolveDelta's job (tested above — a no-tell solve is never bumped).
func TestChalScoreBump_AccumulateAndDecay(t *testing.T) {
	ResetChallengeScoreMarks()
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		challengeScoreMarks.bump("9.9.9.9", 10.0, false, false, false, false, t0.Add(time.Duration(i)*time.Second))
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
	challengeScoreMarks.bump("low", 20, false, false, false, false, t0)  // below T1
	challengeScoreMarks.bump("high", 60, false, false, false, false, t0) // above T1
	challengeScoreMarks.bump("ghost", 2, false, false, false, false, t0)

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
	challengeScoreMarks.bump("7.7.7.7", 120, false, false, false, false, t0)

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
		challengeScoreMarks.bump(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), 10.0, false, false, false, false, now)
	}
	challengeScoreMarks.mu.Lock()
	full := len(challengeScoreMarks.ips)
	challengeScoreMarks.mu.Unlock()
	if full != maxChalScoreMarks {
		t.Fatalf("store holds %d, want cap %d", full, maxChalScoreMarks)
	}
	// A brand-new IP at the cap is rejected…
	challengeScoreMarks.bump("203.0.113.1", 10.0, false, false, false, false, now)
	challengeScoreMarks.mu.Lock()
	after := len(challengeScoreMarks.ips)
	challengeScoreMarks.mu.Unlock()
	if after != maxChalScoreMarks {
		t.Errorf("cap breached: %d, want %d", after, maxChalScoreMarks)
	}
	// …but an EXISTING IP still accumulates (not blocked by the cap).
	challengeScoreMarks.bump("10.0.0.0", 10.0, false, false, false, false, now)
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
				challengeScoreMarks.bump(fmt.Sprintf("192.168.%d.%d", g, i%64), 10.0, i%2 == 0, i%3 == 0, i%5 == 0, i%7 == 0, now.Add(time.Duration(i)*time.Millisecond))
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
	challengeScoreMarks.bump("1.1.1.1", 100, false, false, false, false, time.Now())
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

// The NAT/CGNAT guardrail, end-to-end: a busy shared egress that produces a heavy
// stream of HONEST FAST solves (no UA-lie, not on a solver-farm vhost) must NEVER be
// recorded — let alone reach a verdict — because fast is amplifier-only. This is the
// scenario the 3rd review flagged: ~15-23% of honest solves are fast at difficulty
// 16, so without the corroboration gate this egress would climb to would_deny.
func TestRecordChallengeScoreSolve_FastOnlyNATNeverConvicts(t *testing.T) {
	ResetChallengeScoreMarks()
	e := &Engine{cfg: Config{AbuseShadow: true}}
	now := time.Now()
	for i := 0; i < 500; i++ { // a flood of honest fast solves from one CGNAT egress
		e.RecordChallengeScoreSolve(ChallengeSolve{IP: "100.64.0.1", SolveMS: 50})
	}
	if rows := challengeScoreMarks.collectDue(now, 0, 0); len(rows) != 0 {
		t.Fatalf("fast-only NAT egress recorded/convicted: %+v", rows)
	}
}

// Operator-trusted IPs (IGNORE_IPS / IGNORE_NETS via bypassFunc) are skipped before
// any store work, even when the solve carries a strong tell.
func TestRecordChallengeScoreSolve_BypassSkipped(t *testing.T) {
	ResetChallengeScoreMarks()
	e := &Engine{cfg: Config{AbuseShadow: true}}
	e.SetBypassFunc(func(ip string) bool { return ip == "9.9.9.9" })
	e.RecordChallengeScoreSolve(ChallengeSolve{IP: "9.9.9.9", UAImpossible: true}) // strong tell, but trusted
	if n := len(challengeScoreMarks.collectDue(time.Now(), 0, 0)); n != 0 {
		t.Errorf("bypassed IP still recorded (%d rows)", n)
	}
	// A non-bypassed IP with the same tell IS recorded (proves the skip is selective).
	e.RecordChallengeScoreSolve(ChallengeSolve{IP: "8.8.8.8", UAImpossible: true})
	if n := len(challengeScoreMarks.collectDue(time.Now(), 0, 0)); n != 1 {
		t.Errorf("non-bypassed IP not recorded (%d rows)", n)
	}
}

// The fingerprint-anchored spine, end-to-end: a solve whose TLSFP is a CONVICTED
// solver-farm fingerprint opens the score at the spine weight, with no other tell
// (no UA-lie, benign vhost). A solve whose fingerprint is NOT convicted, and which
// carries no other tell, is not scored at all.
func TestRecordChallengeScoreSolve_FingerprintSpine(t *testing.T) {
	ResetChallengeScoreMarks()
	ResetSolverFarmMarks()
	t.Cleanup(ResetSolverFarmMarks)
	e := &Engine{cfg: Config{AbuseShadow: true}}

	// The detector has convicted fingerprint c28caa00 (a live mark).
	MarkSolverFarmFingerprint("c28caa00", time.Minute)

	// A solve carrying that fingerprint, no other tell, on a benign vhost.
	e.RecordChallengeScoreSolve(ChallengeSolve{IP: "203.0.113.7", Host: "benign.example", TLSFP: "c28caa00"})
	rows := challengeScoreMarks.collectDue(time.Now(), 0, 0)
	if len(rows) != 1 || rows[0].farmFP != 1 || rows[0].farm != 0 || rows[0].uaImp != 0 {
		t.Fatalf("fingerprint spine not recorded cleanly: %+v", rows)
	}
	if math.Abs(rows[0].score-chalScoreWFarmFP) > 0.1 { // tiny decay between bump and collect
		t.Errorf("spine score = %v, want ~%v", rows[0].score, chalScoreWFarmFP)
	}

	// A DIFFERENT (unconvicted) fingerprint with no other tell is not scored.
	ResetChallengeScoreMarks()
	e.RecordChallengeScoreSolve(ChallengeSolve{IP: "203.0.113.8", Host: "benign.example", TLSFP: "deadbeef"})
	if n := len(challengeScoreMarks.collectDue(time.Now(), 0, 0)); n != 0 {
		t.Errorf("unconvicted fingerprint scored (%d rows), want 0", n)
	}

	// An empty TLSFP (no X-CFM-TLS stamp) never matches a conviction.
	e.RecordChallengeScoreSolve(ChallengeSolve{IP: "203.0.113.9", Host: "benign.example", TLSFP: ""})
	if n := len(challengeScoreMarks.collectDue(time.Now(), 0, 0)); n != 0 {
		t.Errorf("empty fingerprint scored (%d rows), want 0", n)
	}
}
