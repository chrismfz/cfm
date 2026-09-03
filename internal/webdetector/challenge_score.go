package webdetector

import (
	"math"
	"sync"
	"time"

	"cfm/internal/logging"
)

// challenge_score.go — Track-2 Stage 1a: a daemon-side, per-IP, LOG-ONLY
// "challenge-abuse score" (docs/challenge-score.md). It fuses the challenge-time
// signals CFM already records — how often an IP re-solves, how implausibly fast,
// with a self-contradictory UA, from a solver-farm vhost — into one decaying
// per-IP score, and logs `signal=challenge_score … verdict=would_harden|would_deny`
// where that score crosses a threshold. Nothing here hardens, denies, or blocks;
// it measures the headless / solver-farm class ("the challenge was solved and the
// abuse continued") before any enforcement, exactly like the abuse_shadow signals.
//
// Daemon-side and event-fed: the challenge-solve stream is already published
// (SubscribeChallengeSolveEvents) and carries the full typed solve (solve latency,
// UA-lie flag, host). We subscribe like solver-farm / under-attack do and fold each
// solve into a decaying per-IP store — O(1), inline-safe on the verify path. The two
// remaining tells the design names (post-clearance silence, Sec-Fetch) are edge-only
// and come in a later edge-Lua stage; this stage collects everything the daemon can
// already see.
//
// Rides the existing ABUSE_SHADOW master — NO new config knob; weights/thresholds
// are in-code burn-in constants (the raw per-solve solve_ms is already in
// cfm.challenges.log for calibrating the "fast" floor). Emits via LogfABUSESHADOW
// into cfm.abuse_shadow.log (no new log file / logrotate change); the abuse_shadow
// MCP tool surfaces it via by-signal / by-verdict counts.

const (
	chalScoreHalfLife    = 30 * time.Minute // per-IP score decay half-life
	chalScoreRunInterval = 2 * time.Minute  // throttle the emit pass (marks feed continuously)
	chalScoreEpsilon     = 1.0              // decayed below this → pruned
	maxChalScoreMarks    = 10000            // IP-keyed store cap (IP is attacker-influenced)

	// Per-solve weights (burn-in STARTING values — tune from the logged distribution,
	// not config). A solve is mild on its own; the score climbs when an IP RE-solves
	// (each solve adds, the decay fades a lone one) and when the solve looks non-human.
	chalScoreWSolve = 10.0 // any solve
	chalScoreWFast  = 15.0 // solve latency below the human floor (native/GPU solver)
	chalScoreWUAImp = 25.0 // self-contradictory User-Agent (a lie, not just old)
	chalScoreWFarm  = 15.0 // the solve's vhost currently looks like a solver farm

	// chalScoreFastMS: an issue→submit gap below this is "too fast". It includes HTML
	// delivery + browser startup + POST RTT, so it is deliberately low; a lone lucky
	// browser barely trips it and the per-solve weight is small — the real signal is
	// the COUNT of fast solves from one IP. Calibrate from cfm.challenges.log solve_ms.
	chalScoreFastMS = 800

	// Shadow thresholds on the decayed score.
	chalScoreT1 = 50.0 // would_harden (soft rung)
	chalScoreT2 = 90.0 // would_deny (hard rung)

	// chalScoreLogEvery re-logs a persistent offender at most this often. The
	// per-IP throttle state lives ON the mark (below), inside the capped + pruned
	// store, so it dies with the score — unlike the shared shouldLogVhostSuppress
	// map, which is never pruned and would grow one entry per attacker IP forever.
	chalScoreLogEvery = 10 * time.Minute
)

// chalScoreMark is one IP's decaying score plus the signal breakdown (logged so the
// burn-in shows WHY an IP scored — how many fast / UA-lie / farm solves) and its
// last-logged time (the per-IP log throttle, bounded by the store's own cap/prune).
type chalScoreMark struct {
	score                     float64
	last                      time.Time
	lastLogged                time.Time
	solves, fast, uaImp, farm int
}

type chalScoreStore struct {
	mu  sync.Mutex
	ips map[string]chalScoreMark
}

var challengeScoreMarks = &chalScoreStore{ips: make(map[string]chalScoreMark)}

// chalDecay applies the half-life decay of score from last→now.
func chalDecay(score float64, last, now time.Time) float64 {
	if score <= 0 || last.IsZero() {
		return 0
	}
	dt := now.Sub(last).Seconds()
	if dt <= 0 {
		return score
	}
	return score * math.Pow(0.5, dt/chalScoreHalfLife.Seconds())
}

// chalSolveDelta is the PURE per-solve score contribution and which tells fired.
func chalSolveDelta(s ChallengeSolve, farm bool) (delta float64, fast, uaImp bool) {
	delta = chalScoreWSolve
	if ms, ok := s.SolveLatencyMS(); ok && ms < chalScoreFastMS {
		fast = true
		delta += chalScoreWFast
	}
	if s.UAImpossible {
		uaImp = true
		delta += chalScoreWUAImp
	}
	if farm {
		delta += chalScoreWFarm
	}
	return delta, fast, uaImp
}

// chalScoreVerdict maps a decayed score to its shadow verdict ("" below T1).
func chalScoreVerdict(score float64) string {
	switch {
	case score >= chalScoreT2:
		return "would_deny"
	case score >= chalScoreT1:
		return "would_harden"
	default:
		return ""
	}
}

// bump folds one solve into ip's decaying score. O(1) — pruning is the snapshot's
// job, since this runs inline on the latency-sensitive verify path.
func (m *chalScoreStore) bump(ip string, delta float64, fast, uaImp, farm bool, now time.Time) {
	if ip == "" || delta <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	mk, ok := m.ips[ip]
	if !ok && len(m.ips) >= maxChalScoreMarks {
		return // cap; the snapshot prunes expired entries every interval
	}
	mk.score = chalDecay(mk.score, mk.last, now) + delta
	mk.last = now
	mk.solves++
	if fast {
		mk.fast++
	}
	if uaImp {
		mk.uaImp++
	}
	if farm {
		mk.farm++
	}
	m.ips[ip] = mk
}

// chalScoreRow is one IP's decayed score + breakdown at snapshot time.
type chalScoreRow struct {
	ip                        string
	score                     float64
	solves, fast, uaImp, farm int
}

// collectDue decays every IP to now, PRUNES those below epsilon, and returns those
// at or above reportFloor that are due to log (not logged within logEvery),
// stamping lastLogged on the ones it returns. One O(n) pass under the lock, once
// per emit interval — it does both the prune and the per-IP log throttle, so the
// throttle state stays inside the capped/pruned store. logEvery ≤ 0 means "always
// due" (used by tests).
func (m *chalScoreStore) collectDue(now time.Time, reportFloor float64, logEvery time.Duration) []chalScoreRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []chalScoreRow
	for ip, mk := range m.ips {
		d := chalDecay(mk.score, mk.last, now)
		if d < chalScoreEpsilon {
			delete(m.ips, ip)
			continue
		}
		if d < reportFloor {
			continue
		}
		if logEvery > 0 && !mk.lastLogged.IsZero() && now.Sub(mk.lastLogged) < logEvery {
			continue // over threshold but logged too recently
		}
		mk.lastLogged = now
		m.ips[ip] = mk
		out = append(out, chalScoreRow{ip: ip, score: d, solves: mk.solves, fast: mk.fast, uaImp: mk.uaImp, farm: mk.farm})
	}
	return out
}

func (m *chalScoreStore) reset() {
	m.mu.Lock()
	m.ips = make(map[string]chalScoreMark)
	m.mu.Unlock()
}

var (
	chalScoreRunMu   sync.Mutex
	chalScoreLastRun time.Time
)

// ResetChallengeScoreMarks drops every per-IP score and the emit throttle. The
// detectors manager calls it on teardown so a reload leaves no stale state
// (mirrors ResetAbuseShadowMarks).
func ResetChallengeScoreMarks() {
	challengeScoreMarks.reset()
	chalScoreRunMu.Lock()
	chalScoreLastRun = time.Time{}
	chalScoreRunMu.Unlock()
}

// RecordChallengeScoreSolve folds one solved challenge into the per-IP score. It is
// the SubscribeChallengeSolveEvents callback — inline on the verify path, so it is
// O(1): a farm-mark read plus one map update. Gated on the ABUSE_SHADOW master.
func (e *Engine) RecordChallengeScoreSolve(s ChallengeSolve) {
	if !e.cfg.AbuseShadow || s.IP == "" {
		return
	}
	farm := IsSolverFarm(s.Host)
	delta, fast, uaImp := chalSolveDelta(s, farm)
	challengeScoreMarks.bump(s.IP, delta, fast, uaImp, farm, time.Now())
}

// emitChallengeScoreShadow logs the per-IP would_harden / would_deny lines, from the
// per-tick shadow block but throttled to once per interval (the marks feed
// continuously). Log-only.
func (e *Engine) emitChallengeScoreShadow(now time.Time) {
	if !e.cfg.AbuseShadow {
		return
	}
	chalScoreRunMu.Lock()
	if !chalScoreLastRun.IsZero() && now.Sub(chalScoreLastRun) < chalScoreRunInterval {
		chalScoreRunMu.Unlock()
		return
	}
	chalScoreLastRun = now
	chalScoreRunMu.Unlock()

	// collectDue does the decay/prune AND the per-IP log throttle in one locked
	// pass; the throttle lives on the mark (bounded store), not the never-pruned
	// shouldLogVhostSuppress map.
	for _, r := range challengeScoreMarks.collectDue(now, chalScoreT1, chalScoreLogEvery) {
		verdict := chalScoreVerdict(r.score)
		if verdict == "" {
			continue // floored at T1, so this can't happen — defensive
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=challenge_score ip=%s score=%.1f solves=%d fast=%d uaimp=%d farm=%d verdict=%s",
			r.ip, r.score, r.solves, r.fast, r.uaImp, r.farm, verdict,
		)
	}
}
