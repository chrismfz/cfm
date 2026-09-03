package webdetector

import (
	"math"
	"sync"
	"time"

	"cfm/internal/logging"
)

// challenge_score.go — Track-2 Stage 1a: a daemon-side, per-IP, LOG-ONLY
// "challenge-abuse score" (docs/challenge-score.md). It fuses the daemon-visible
// challenge-time TELLS CFM already records — an implausibly-fast solve, a
// self-contradictory (UA-lie) solve, a solve from a solver-farm vhost — into one
// decaying per-IP score, and logs `signal=challenge_score … verdict=would_harden|
// would_deny` where that score crosses a threshold. Nothing here hardens, denies,
// or blocks; it measures the headless / solver-farm class before any enforcement,
// exactly like the abuse_shadow signals.
//
// What it deliberately does NOT score: raw solve VOLUME. A flat per-solve weight
// would make a benign shared egress (CGNAT / corporate NAT), where many real users
// each solve once, accumulate to would_deny — the exact false "solver farm" the
// design's §7 guardrail warns about. So only the discriminating tells score, and
// operator-trusted IPs (IGNORE_IPS/IGNORE_NETS) are skipped entirely. The one
// signal that genuinely needs to tell a re-solving headless from a busy NAT —
// re-solve cadence with canonical-host collapse — is the cookie_discard detector's
// job and joins later as a daemon seed, not proxied here by counting solves.
//
// Daemon-side and event-fed: the challenge-solve stream is already published
// (SubscribeChallengeSolveEvents) and carries the full typed solve (solve latency,
// UA-lie flag, host). We subscribe like solver-farm / under-attack do and fold each
// tell-bearing solve into the store. The callback takes the store mutex directly
// (not a queue): it is O(1) map work, and the only cross-goroutine contention is
// the once-per-interval collectDue scan below — which touches only tell-bearing IPs
// (a small set, since benign no-tell solves are never recorded), so the lock is
// held sub-millisecond. If the verify path ever needs zero contention, switch the
// callback to a buffered enqueue like the solver-farm detector.
//
// Rides the existing ABUSE_SHADOW master — NO new config knob; weights/thresholds
// are in-code burn-in constants (the raw per-solve solve_ms is already in
// cfm.challenges.log to calibrate the "fast" floor). Emits via LogfABUSESHADOW into
// cfm.abuse_shadow.log (no new log / logrotate); the abuse_shadow MCP tool surfaces
// it via by-signal / by-verdict counts.

const (
	chalScoreHalfLife    = 30 * time.Minute // per-IP score decay half-life
	chalScoreRunInterval = 2 * time.Minute  // throttle the emit pass (marks feed continuously)
	chalScoreEpsilon     = 1.0              // decayed below this → pruned
	maxChalScoreMarks    = 10000            // IP-keyed store cap (IP is attacker-influenced)

	// Per-solve tell weights (burn-in STARTING values, tuned from the logged
	// distribution — not config). NO flat per-solve base (see the volume note above):
	// only these discriminating tells score.
	chalScoreWFast  = 10.0 // solve latency below the human floor (native/GPU); noisy per-event, so low
	chalScoreWUAImp = 30.0 // self-contradictory User-Agent — a lie, not just old — the strongest tell
	chalScoreWFarm  = 15.0 // the solve's vhost currently looks like a solver farm

	// chalScoreFastMS: an issue→submit gap below this is "too fast". It includes HTML
	// delivery + browser startup + POST RTT, so it is deliberately low; a lone lucky
	// browser barely trips it and the weight is small — the real signal is the COUNT
	// of fast solves from one IP. Calibrate from cfm.challenges.log solve_ms.
	chalScoreFastMS = 800

	// Shadow thresholds on the decayed score.
	chalScoreT1 = 50.0 // would_harden (soft rung)
	chalScoreT2 = 90.0 // would_deny (hard rung)

	// chalScoreLogEvery re-logs a persistent offender at most this often. The per-IP
	// throttle state lives ON the mark (below), inside the capped + pruned store, so
	// it dies with the score — unlike the shared shouldLogVhostSuppress map, which is
	// never pruned and would grow one entry per attacker IP forever.
	chalScoreLogEvery = 10 * time.Minute
)

// halfLifeDecayFactor is the exponential-decay multiplier for an elapsed dt at a
// given half-life: 0.5^(dt/halfLife). Shared by the per-IP challenge score and the
// fingerprinter baseline so the two can't drift (CLAUDE.md §5). dt ≤ 0 or a
// non-positive half-life yields 1 (no decay).
func halfLifeDecayFactor(dt, halfLife time.Duration) float64 {
	if halfLife <= 0 || dt <= 0 {
		return 1
	}
	return math.Pow(0.5, dt.Seconds()/halfLife.Seconds())
}

// chalScoreMark is one IP's decaying score plus the tell breakdown (logged so the
// burn-in shows WHY an IP scored) and its last-logged time (the per-IP log throttle,
// bounded by the store's own cap/prune).
type chalScoreMark struct {
	score                     float64
	last                      time.Time
	lastLogged                time.Time
	solves, fast, uaImp, farm int
}

type chalScoreStore struct {
	mu      sync.Mutex
	ips     map[string]chalScoreMark
	dropped int // solves dropped because the store was at cap; reported by emit, then reset
}

var challengeScoreMarks = &chalScoreStore{ips: make(map[string]chalScoreMark)}

// chalDecay applies the half-life decay of score from last→now.
func chalDecay(score float64, last, now time.Time) float64 {
	if score <= 0 || last.IsZero() {
		return 0
	}
	return score * halfLifeDecayFactor(now.Sub(last), chalScoreHalfLife)
}

// chalSolveDelta is the PURE per-solve score contribution and which tells fired.
// Returns 0 when a solve carries no discriminating tell (that solve is not scored).
func chalSolveDelta(s ChallengeSolve, farm bool) (delta float64, fast, uaImp bool) {
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

// bump folds one tell-bearing solve into ip's decaying score. O(1) — pruning is the
// snapshot's job, since this runs inline on the latency-sensitive verify path. A new
// IP at the cap is dropped (counted) rather than evicting an existing entry, matching
// the maxShadowMarks precedent; the store stays small because only tell-bearing
// solves reach here.
func (m *chalScoreStore) bump(ip string, delta float64, fast, uaImp, farm bool, now time.Time) {
	if ip == "" || delta <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	mk, ok := m.ips[ip]
	if !ok && len(m.ips) >= maxChalScoreMarks {
		m.dropped++ // reported by emit so a full store isn't silently blind
		return
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

// chalScoreRow is one IP's decayed score + breakdown at collect time.
type chalScoreRow struct {
	ip                        string
	score                     float64
	solves, fast, uaImp, farm int
}

// collectDue decays every IP to now, PRUNES those below epsilon, and returns those
// at or above reportFloor that are due to log (not logged within logEvery),
// stamping lastLogged on the ones it returns. One O(n) pass under the lock, once per
// emit interval — it does the prune AND the per-IP log throttle, so the throttle
// state stays inside the capped/pruned store. logEvery ≤ 0 means "always due".
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

// takeDropped returns and clears the at-cap drop count.
func (m *chalScoreStore) takeDropped() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dropped
	m.dropped = 0
	return d
}

func (m *chalScoreStore) reset() {
	m.mu.Lock()
	m.ips = make(map[string]chalScoreMark)
	m.dropped = 0
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
// O(1): a bypass check, a farm-mark read, and (only for a tell-bearing solve) one
// map update. Gated on the ABUSE_SHADOW master; operator-trusted IPs are skipped.
func (e *Engine) RecordChallengeScoreSolve(s ChallengeSolve) {
	if !e.cfg.AbuseShadow || s.IP == "" {
		return
	}
	// Never score an operator-trusted IP (IGNORE_IPS / IGNORE_NETS) — the shared-
	// egress / NAT guard the design requires (docs/challenge-score.md §7).
	if e.isBypassed(s.IP) {
		return
	}
	farm := IsSolverFarm(s.Host)
	delta, fast, uaImp := chalSolveDelta(s, farm)
	if delta <= 0 {
		return // no discriminating tell on this solve — not scored
	}
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
	// Surface a full store so a reader isn't misled by silent truncation.
	if dropped := challengeScoreMarks.takeDropped(); dropped > 0 {
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=challenge_score note=store_cap_reached cap=%d dropped=%d verdict=would_shadow",
			maxChalScoreMarks, dropped,
		)
	}
}
