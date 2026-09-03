package webdetector

// Under-Attack Mode — campaign fingerprinter (increment I2, SHADOW-ONLY).
//
// When a vhost is UNDER_ATTACK (I1), this computes the attacking population's
// common denominators over the flagged window and proposes candidate deny
// predicates, each scored coverage(attack) × (1 − collision(baseline)). Nothing
// is enforced — candidates + scores are logged so the operator (and a future
// I3) can see which predicate would cleanly separate the attack from legit
// traffic. See docs/under-attack-mode.md §6.2.
//
// Substrate reality (see the I2 investigation, folded into the doc):
//   - The design's "replay a predicate against pre-attack traffic via the
//     simulate endpoint" does NOT exist — simulate answers the inverse question
//     and the only per-request sample is a global ring that attack traffic
//     evicts. So collision is measured against a ROLLING PER-VHOST BASELINE
//     histogram maintained here: the vhost's normal-traffic base-path and UA
//     distributions, updated while it is not under attack and frozen once it
//     escalates (so it stays pre-attack).
//   - The enforcement predicate type (TrafficRuleMatch) can key on PathAny /
//     UAAny / Methods but has NO tls_fp field, and the query string is stripped
//     before aggregation — so I2 ships base-path and UA-pool candidates.
//     tls_fp and query-shape candidates are deferred (they need new plumbing and,
//     for tls_fp, a new predicate field).
//
// Candidates are SINGLE-FEATURE (one base-path, or the UA pool): coverage and
// collision are then exact marginal fractions of the attack / baseline
// histograms. Conjunction predicates need a joint distribution the engine does
// not retain — deferred.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	// fpBaselineHalfLife sets how fast the rolling baseline forgets: each fold is
	// decayed so a request's weight halves after this much wall-clock, keeping the
	// denominator a stable "recent normal" without ever going stale.
	fpBaselineHalfLife = 30 * time.Minute
	// fpMinRunInterval floors how often the pass runs (it also runs at most once
	// per config Window); the baseline folds one window of traffic per run.
	fpMinRunInterval = 60 * time.Second
	// fpMaxKeys caps distinct base-paths / UAs per baseline (memory guard).
	fpMaxKeys = 512
	// fpPruneEpsilon drops a decayed key once its weight falls below this.
	fpPruneEpsilon = 0.5
	// fpMinBaselineTotal: below this decayed request count the baseline is too
	// thin to trust as a collision denominator — candidates log collision=n/a and
	// never claim would-arm.
	fpMinBaselineTotal = 500
	// fpMinCandidateCoverage: don't bother proposing a predicate that covers less
	// than this share of the attack.
	fpMinCandidateCoverage = 0.20
	// fpMaxBasePathCandidates caps the base-path predicates logged per vhost.
	fpMaxBasePathCandidates = 4
	// fpUAPoolTopN bounds the UA-pool candidate to the top-N attack UAs.
	fpUAPoolTopN = 40
	// fpBaselineStale drops a baseline whose vhost has gone quiet this long.
	fpBaselineStale = 2 * time.Hour
	// fpMaxBaselines caps the number of per-vhost baselines held (memory guard on
	// a host with very many vhosts); least-recently-updated ones are evicted.
	fpMaxBaselines = 4096
)

// fpBaseline is a rolling, decayed histogram of a vhost's NORMAL traffic — the
// collision denominator. Not updated while the vhost is under attack, so it
// stays pre-attack.
type fpBaseline struct {
	paths   map[string]float64 // base-path -> decayed count
	uas     map[string]float64 // NormalizeUA(ua) -> decayed count
	total   float64            // decayed request count
	updated time.Time
}

// fpState holds every vhost's baseline plus the run throttle. Touched only by
// the emit-tick goroutine, but guarded so a future reader surface is safe.
type fpState struct {
	mu        sync.Mutex
	baselines map[string]*fpBaseline
	lastRun   time.Time
}

func newFPState() *fpState { return &fpState{baselines: make(map[string]*fpBaseline)} }

// fpSnapshot is one window's per-vhost feature distribution.
type fpSnapshot struct {
	basePaths map[string]int // base-path -> count
	uas       map[string]int // NormalizeUA -> count
	total     int            // requests (path occurrences)
	reqAll    int            // requests counted for the dynamic fraction denominator
	reqDyn    int            // dynamic-only requests (0 when ipsDyn tracking is off)
}

// fpBasePath reduces a (query-stripped) path to its first segment: "/shop/x" ->
// "/shop/", "/wp-login.php" -> "/wp-login.php", "/" -> "/". This is the grouping
// a PathAny prefix predicate would key on.
func fpBasePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return "/" + p[:i] + "/"
	}
	return "/" + p
}

// snapshotFingerprint captures per-vhost base-path / UA / dynamic-fraction
// distributions from the short window, mirroring the abuse-shadow snap.
func (e *Engine) snapshotFingerprint() map[string]*fpSnapshot {
	out := make(map[string]*fpSnapshot)
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		s := &fpSnapshot{basePaths: make(map[string]int), uas: make(map[string]int)}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			for p, n := range b.paths {
				s.basePaths[fpBasePath(p)] += n
				s.total += n
			}
			for ua, n := range b.uasNormReqs {
				s.uas[ua] += n
			}
			s.reqAll += b.total
			for _, n := range b.ipsDyn {
				s.reqDyn += n
			}
		}
		if s.total == 0 {
			continue
		}
		out[host] = s
	}
	e.mu.RUnlock()
	return out
}

// runFingerprint updates baselines for normal vhosts and fingerprints the ones
// currently under attack. Throttled to once per max(Window, fpMinRunInterval).
// Called from the emit tick.
func (e *Engine) runFingerprint(now time.Time) {
	if e == nil || e.fp == nil || !e.cfg.UnderAttack || !e.cfg.UnderAttackFingerprint {
		return
	}
	interval := e.cfg.Window
	if interval < fpMinRunInterval {
		interval = fpMinRunInterval
	}
	e.fp.mu.Lock()
	if !e.fp.lastRun.IsZero() && now.Sub(e.fp.lastRun) < interval {
		e.fp.mu.Unlock()
		return
	}
	e.fp.lastRun = now
	e.fp.mu.Unlock()

	snaps := e.snapshotFingerprint()
	decay := halfLifeDecayFactor(interval, fpBaselineHalfLife)
	for host, snap := range snaps {
		if on, _, _ := e.VhostAttackState(host); on {
			e.fingerprintVhost(now, host, snap)
			// Keep the frozen pre-attack baseline alive: it is deliberately not
			// folded while under attack, so touch its clock or the idle-prune
			// would delete it out from under a long attack (the case that most
			// needs the collision denominator).
			e.fp.touch(host, now)
		} else {
			e.fp.updateBaseline(host, snap, decay, now)
		}
	}
	e.fp.pruneBaselines(now)
}

// updateBaseline folds one window's distribution into the vhost's rolling
// baseline with decay, capping the maps.
func (s *fpState) updateBaseline(host string, snap *fpSnapshot, decay float64, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.baselines[host]
	if b == nil {
		b = &fpBaseline{paths: make(map[string]float64), uas: make(map[string]float64)}
		s.baselines[host] = b
	}
	fpDecayMap(b.paths, decay)
	fpDecayMap(b.uas, decay)
	b.total *= decay
	for k, n := range snap.basePaths {
		b.paths[k] += float64(n)
	}
	for k, n := range snap.uas {
		b.uas[k] += float64(n)
	}
	b.total += float64(snap.total)
	b.updated = now
	fpCapMap(b.paths, fpMaxKeys)
	fpCapMap(b.uas, fpMaxKeys)
}

// baselineCopy returns a stable copy of a vhost's baseline for scoring.
func (s *fpState) baselineCopy(host string) (paths map[string]float64, total float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.baselines[host]
	if b == nil {
		return nil, 0
	}
	out := make(map[string]float64, len(b.paths))
	for k, v := range b.paths {
		out[k] = v
	}
	return out, b.total
}

// baselineUACopy returns a stable copy of a vhost's baseline UA histogram.
func (s *fpState) baselineUACopy(host string) (uas map[string]float64, total float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.baselines[host]
	if b == nil {
		return nil, 0
	}
	out := make(map[string]float64, len(b.uas))
	for k, v := range b.uas {
		out[k] = v
	}
	return out, b.total
}

// touch advances a baseline's clock without folding traffic, so an under-attack
// (frozen) baseline is not idle-pruned mid-attack.
func (s *fpState) touch(host string, now time.Time) {
	s.mu.Lock()
	if b := s.baselines[host]; b != nil {
		b.updated = now
	}
	s.mu.Unlock()
}

func (s *fpState) pruneBaselines(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for host, b := range s.baselines {
		if b.total < fpPruneEpsilon || now.Sub(b.updated) > fpBaselineStale {
			delete(s.baselines, host)
		}
	}
	// Bound the vhost count too (not just per-map keys): evict the least-recently
	// updated baselines down to the cap. Under-attack baselines are touch()ed each
	// run, so their recent clock keeps them out of the eviction set.
	if len(s.baselines) <= fpMaxBaselines {
		return
	}
	type hu struct {
		host    string
		updated time.Time
	}
	all := make([]hu, 0, len(s.baselines))
	for h, b := range s.baselines {
		all = append(all, hu{h, b.updated})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].updated.Before(all[j].updated) })
	for _, e := range all[:len(all)-fpMaxBaselines] {
		delete(s.baselines, e.host)
	}
}

// fpCandidate is one proposed single-feature deny predicate + its scores.
type fpCandidate struct {
	kind       string // "path" | "ua_pool"
	value      string
	coverage   float64 // attack share the predicate matches
	collision  float64 // baseline share it would also match
	baselineOK bool    // false → baseline too thin to measure collision
}

func (c fpCandidate) score() float64 {
	if !c.baselineOK {
		return c.coverage // partial: coverage only, no safety credit
	}
	return c.coverage * (1 - c.collision)
}

func (e *Engine) fpWouldArm(c fpCandidate) bool {
	return c.baselineOK &&
		c.coverage >= e.cfg.UnderAttackFPCoverageMin &&
		c.collision <= e.cfg.UnderAttackFPCollisionMax
}

// fingerprintVhost builds and logs candidate predicates for one under-attack vhost.
func (e *Engine) fingerprintVhost(now time.Time, host string, snap *fpSnapshot) {
	cands, dynFrac, uaEntropy, baseTotal, baselineOK := e.fpCandidates(host, snap)
	e.logFingerprint(now, host, snap, dynFrac, uaEntropy, baseTotal, baselineOK, cands)
}

// fpCandidates computes the scored candidate predicates for a vhost's attack
// snapshot against its rolling baseline (split from logging so it is testable).
func (e *Engine) fpCandidates(host string, snap *fpSnapshot) (cands []fpCandidate, dynFrac, uaEntropy, baseTotal float64, baselineOK bool) {
	var basePaths map[string]float64
	basePaths, baseTotal = e.fp.baselineCopy(host)
	baselineOK = baseTotal >= fpMinBaselineTotal

	// dyn_frac is a reported signal only (never a candidate). ipsDyn is populated
	// solely when AbuseShadow + AbuseShadowRateOutlier are on, so it logs n/a
	// otherwise — acceptable, the path/UA candidates do not depend on it.
	dynFrac = -1.0
	if snap.reqAll > 0 && snap.reqDyn > 0 {
		dynFrac = float64(snap.reqDyn) / float64(snap.reqAll)
	}
	// Uniformity is over the UA-carrying requests, not all requests: no-UA traffic
	// must not dilute the metric and understate a synthetic pool's uniformity.
	uaEntropy = fpNormEntropy(snap.uas, fpSumInt(snap.uas))

	// A candidate below the configured arm coverage floor can never arm, so use
	// the smaller of the noise floor and the configured floor — never let the
	// hardcoded noise floor suppress a candidate the operator's threshold accepts.
	covFloor := fpMinCandidateCoverage
	if e.cfg.UnderAttackFPCoverageMin < covFloor {
		covFloor = e.cfg.UnderAttackFPCoverageMin
	}

	// Base-path candidates: the dominant paths the attack concentrates on.
	for _, bp := range fpTopKeys(snap.basePaths, fpMaxBasePathCandidates) {
		cov := float64(snap.basePaths[bp]) / float64(snap.total)
		if cov < covFloor {
			continue
		}
		col := 0.0
		if baselineOK && baseTotal > 0 {
			col = basePaths[bp] / baseTotal
		}
		cands = append(cands, fpCandidate{kind: "path", value: bp, coverage: cov, collision: col, baselineOK: baselineOK})
	}
	// UA-pool candidate: the attack's dominant UA set (synthetic uniformity is
	// the tell; the entropy is logged alongside).
	uaBaseline, uaBaseTotal := e.fp.baselineUACopy(host)
	uaBaselineOK := uaBaseTotal >= fpMinBaselineTotal
	uaPool := fpTopKeys(snap.uas, fpUAPoolTopN)
	if len(uaPool) > 0 {
		uaCov := fpFractionSet(snap.uas, float64(snap.total), uaPool)
		uaCol := 0.0
		if uaBaselineOK && uaBaseTotal > 0 {
			uaCol = fpFractionSet(uaBaseline, uaBaseTotal, uaPool)
		}
		cands = append(cands, fpCandidate{
			kind:       "ua_pool",
			value:      fmt.Sprintf("n=%d entropy=%.2f", len(uaPool), uaEntropy),
			coverage:   uaCov,
			collision:  uaCol,
			baselineOK: uaBaselineOK,
		})
	}
	return cands, dynFrac, uaEntropy, baseTotal, baselineOK
}

func (e *Engine) logFingerprint(now time.Time, host string, snap *fpSnapshot, dynFrac, uaEntropy, baseTotal float64, baselineOK bool, cands []fpCandidate) {
	baseNote := "baseline=insufficient"
	if baselineOK {
		baseNote = "baseline=ok"
	}
	logging.LogfCHALLENGES(
		"[under-attack][fingerprint] host=%s attack_reqs=%d dyn_frac=%s ua_uniformity=%.2f base_paths=%d %s(total=%.0f) candidates=%d",
		host, snap.total, fpFmtFrac(dynFrac), uaEntropy, len(snap.basePaths), baseNote, baseTotal, len(cands),
	)
	for _, c := range cands {
		arm := "no"
		if e.fpWouldArm(c) {
			arm = "yes"
		} else if !c.baselineOK {
			arm = "no(insufficient-baseline)"
		} else if c.coverage < e.cfg.UnderAttackFPCoverageMin {
			arm = "no(coverage<min)"
		} else if c.collision > e.cfg.UnderAttackFPCollisionMax {
			arm = "no(collision>max)"
		}
		col := fpFmtFrac(-1)
		if c.baselineOK {
			col = fmt.Sprintf("%.4f", c.collision)
		}
		logging.LogfCHALLENGES(
			"[under-attack][fingerprint]   candidate host=%s kind=%s value=%q coverage=%.3f collision=%s score=%.3f arm=%s",
			host, c.kind, c.value, c.coverage, col, c.score(), arm,
		)
	}
}

// ---- small numeric helpers ----

func fpDecayMap(m map[string]float64, decay float64) {
	for k, v := range m {
		nv := v * decay
		if nv < fpPruneEpsilon {
			delete(m, k)
		} else {
			m[k] = nv
		}
	}
}

// fpCapMap keeps at most max keys, dropping the lowest-weight ones.
func fpCapMap(m map[string]float64, max int) {
	if len(m) <= max {
		return
	}
	type kv struct {
		k string
		v float64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	for _, e := range all[max:] {
		delete(m, e.k)
	}
}

// fpTopKeys returns up to n keys of an int histogram, highest count first.
func fpTopKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if n > len(all) {
		n = len(all)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, all[i].k)
	}
	return out
}

// fpFractionSet returns the share of `total` covered by the given keys. total is
// float64 so the attack (int counts) and baseline (decayed float counts)
// denominators are compared on the same, untruncated basis.
func fpFractionSet[T int | float64](m map[string]T, total float64, keys []string) float64 {
	if total <= 0 {
		return 0
	}
	var sum float64
	for _, k := range keys {
		sum += float64(m[k])
	}
	return sum / total
}

// fpSumInt totals an int histogram.
func fpSumInt(m map[string]int) int {
	s := 0
	for _, v := range m {
		s += v
	}
	return s
}

// fpNormEntropy is the Shannon entropy of a distribution normalized to [0,1]
// (1 = perfectly uniform = synthetic UA pool; low = a few UAs dominate).
func fpNormEntropy(m map[string]int, total int) float64 {
	if total <= 0 || len(m) < 2 {
		return 0
	}
	var h float64
	for _, n := range m {
		if n <= 0 {
			continue
		}
		p := float64(n) / float64(total)
		h -= p * math.Log2(p)
	}
	return h / math.Log2(float64(len(m)))
}

func fpFmtFrac(f float64) string {
	if f < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", f)
}
