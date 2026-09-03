package webdetector

import (
	"sync"
	"time"

	"cfm/internal/logging"
)

// abuse_shadow_fused.go — Track-1 score fusion, LOG-ONLY (docs/traffic-classifier.md
// → "Track-1 shadow fusion"). It measures how often the vhost-level shadow signals
// (facet / cost / dc), fused as weighted contributors on top of the live suspicious
// score, WOULD newly arm a vhost that the live score alone did not — WITHOUT
// touching the live arm. It writes one `signal=fused_score … verdict=…` line per
// corroborated would-arm vhost to the existing cfm.abuse_shadow.log; nothing here
// challenges, blocks, or changes the score.
//
// It rides the existing ABUSE_SHADOW master (no new config knob — weights and
// baseline geometry are hardcoded constants below, tuned in-code from burn-in data,
// not operator surface). The live arm keeps reading only SuspiciousRow.Score =
// clamp01(raw/6); the fused value is a SEPARATE parallel computation, so adding it
// can never rescale the live 0.70 line (scoring.go's /6.0 divisor hazard).
//
// Mechanism:
//   fused = clamp01(base_score + Δ)
//   Δ     = fusedWeight · Σ clamp(robustZ_x, 0, zClamp)   (capped at fusedGroupCap)
// where robustZ_x is the modified robust-z (vhost_baseline.go) of signal x's current
// magnitude against THIS vhost's own recent history. Contributions are clamped ≥0
// (a signal dropping below baseline is not evidence of abuse), so Δ ≥ 0 and fusion
// only ever ADDS arms (net-new catches); lowering an over-armed verified-crawler
// vhost is the verified-crawler fork's job, already shipped.
//
// Guardrails:
//   - Corroboration is over the VHOST-LEVEL shapes only — ≥2 of {facet, cost, dc}
//     must co-fire. rate_outlier (shadow) still CONTRIBUTES to Δ but does NOT count
//     toward the gate: a single aggressive IP trips BOTH facet (it sprays the URL
//     space) AND rate_outlier (it out-rates the vhost median), so counting them as
//     two would let one actor authorise an arm. The three vhost shapes are
//     genuinely independent (facet = URL-space, cost = origin 5xx, dc = a
//     ≥5-IP datacenter share), so ≥2 of them is real corroboration. This is also
//     the planetgym guard (lone facet = 1 shape) and "ASN alone never decides"
//     (lone dc = 1 shape).
//   - The arm also inherits the LIVE arm's uniqIP floor: a fused score over the
//     line on a vhost below ChallengeSuspiciousMinUniqIP could never actually fire
//     once wired, so it is not counted as a would_arm (keeps the burn-in honest).
//   - Self-baseline freeze: a vhost trains its baseline only while UNCORROBORATED,
//     so an active flood never trains the baseline to accept itself; a frozen vhost
//     is still Touch()'d so a >30-min sustained flood is not pruned out from under
//     its good baseline. A quiet vhost keeps learning (mostly zeros), so its first
//     real corroborated spike reads as a large deviation.
//     KNOWN BLIND SPOT (log-only, acceptable): a vhost corroborated on (nearly)
//     every window — e.g. a legit cloud-hosted app permanently at dc>0 AND cost>0
//     — never fills a baseline and so yields z=0 / Δ=0 forever. That correctly
//     prevents a false arm, but a genuine attack riding such a vhost is likewise
//     invisible to fusion (the live base score still applies), so burn-in
//     would_arm counts UNDERCOUNT that class — factor it in when tuning weights.
//
// Cadence: the pass runs at most once per fusedRunInterval, not every emit tick.
// The signal marks reflect a ~2-min sliding window, so evaluating every ~5s tick
// would fold ~24 autocorrelated near-duplicate samples per window into the ring
// (collapsing MAD toward its floor) and re-log the same verdict; one pass per
// ~window keeps baseline samples ~independent and SumAll() cheap.

var fusedBaseline = newVhostBaseline(vhostBaselineConfig{
	Window:     60,    // last 60 sampling passes (× fusedRunInterval ≈ 2 h of history)
	MinSamples: 8,     // below this the baseline stays silent (robustZ → 0)
	MaxHosts:   20000, // backstop; Prune (below) is the primary bound
})

var (
	fusedRunMu   sync.Mutex
	fusedLastRun time.Time
)

const (
	// fusedRunInterval throttles the whole pass so baseline samples are drawn on a
	// cadence comparable to the marks' own window (see the Cadence note above).
	fusedRunInterval = 2 * time.Minute

	// Δ = fusedWeight · Σ clamp(z,0,fusedZClamp), capped at fusedGroupCap. Burn-in
	// STARTING weights, tuned in-code from would_arm/base data — not config. Sizing:
	// base scores are 0–1 against a 0.70 arm; one saturated signal (z=8) adds 0.16,
	// two add 0.32→cap 0.25, so a corroborated spike can lift a mid-score (~0.5)
	// over the line but not manufacture an arm from nothing.
	fusedWeight   = 0.02
	fusedZClamp   = 8.0
	fusedGroupCap = 0.25

	// Per-feature madFloor: the smallest deviation that is meaningful for that
	// feature's scale (facet = distinct-URL count; cost/dc = percentages; shadow =
	// outlier-IP count), so a flat/quiet baseline doesn't explode robustZ.
	fusedFacetFloor  = 50.0
	fusedPctFloor    = 5.0
	fusedShadowFloor = 1.0

	// fusedBaselineTTL: drop a vhost's baseline after this long with no pass that
	// Observed or Touch()'d it.
	fusedBaselineTTL = 30 * time.Minute
)

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// corroboratingSignals counts how many of the VHOST-LEVEL shapes (facet, cost, dc)
// are non-zero this window. rate_outlier (shadow) is deliberately excluded — see
// the guardrail note; it feeds Δ but not the gate.
func corroboratingSignals(facet, cost, dc int) int {
	return b2i(facet > 0) + b2i(cost > 0) + b2i(dc > 0)
}

// clampPosZ clamps a robust-z into [0, fusedZClamp]: only upward deviations
// contribute, and a single feature can't dominate.
func clampPosZ(z float64) float64 {
	switch {
	case z <= 0:
		return 0
	case z > fusedZClamp:
		return fusedZClamp
	default:
		return z
	}
}

// fusedDelta is the de-correlated, capped group contribution — one capped weight
// over the four partly-correlated signals so we never triple-count the same
// rate/cost shape.
func fusedDelta(zf, zc, zd, zs float64) float64 {
	sum := fusedWeight * (clampPosZ(zf) + clampPosZ(zc) + clampPosZ(zd) + clampPosZ(zs))
	if sum > fusedGroupCap {
		sum = fusedGroupCap
	}
	return sum
}

// fusedVhostVerdict is the PURE fusion decision for one vhost. corrob is the count
// of co-firing vhost-level shapes; fusion applies only when corrob ≥ 2 AND the
// vhost clears the live arm's uniqIP floor. It returns the delta, the fused score,
// and the verdict: "" (nothing to report), "would_arm" (fused crosses `on`, live
// base did not), or "confirm" (both cross — fusion agrees with an arm the live
// score already makes).
func fusedVhostVerdict(base float64, facet, cost, dc, uniqIP, minUniq int, zf, zc, zd, zs, on float64) (corrob int, delta, fused float64, verdict string) {
	corrob = corroboratingSignals(facet, cost, dc)
	fused = clamp01(base)
	if corrob < 2 {
		return corrob, 0, fused, ""
	}
	delta = fusedDelta(zf, zc, zd, zs)
	fused = clamp01(base + delta)
	// Mirror the live arm's non-score gate: an arm needs uniqIP ≥ the floor, so a
	// fused score over the line on a low-uniqIP vhost is not a real catch.
	if fused < on || uniqIP < minUniq {
		return corrob, delta, fused, ""
	}
	if base >= on {
		return corrob, delta, fused, "confirm"
	}
	return corrob, delta, fused, "would_arm"
}

// fuseLearnOrFreeze folds a vhost's current magnitudes into bl ONLY while it is
// uncorroborated (< 2 vhost shapes); a corroborated vhost is FROZEN (not observed)
// so an active flood can't train the baseline to accept itself, but is Touch()'d so
// a sustained flood is not pruned out from under its learned baseline. Returns true
// iff corroborated (the caller then scores it). Split out so the freeze invariant is
// unit-testable without an Engine.
func fuseLearnOrFreeze(bl *vhostBaseline, host string, facet, cost, dc, shadow int, now time.Time) (corroborated bool) {
	if corroboratingSignals(facet, cost, dc) >= 2 {
		bl.Touch(host, now)
		return true
	}
	bl.Observe(host, "facet", float64(facet), now)
	bl.Observe(host, "cost", float64(cost), now)
	bl.Observe(host, "dc", float64(dc), now)
	bl.Observe(host, "shadow", float64(shadow), now)
	return false
}

// emitAbuseShadowFusedScore runs the log-only fusion over every vhost, from the
// per-tick emitIPChallenges shadow block but throttled to once per fusedRunInterval.
// Uncorroborated vhosts fold this pass into their baseline; corroborated ones are
// frozen and scored against it. Only a would-arm / confirm result is logged.
func (e *Engine) emitAbuseShadowFusedScore(now time.Time) {
	if !e.cfg.AbuseShadow || e.longwin == nil {
		return
	}
	fusedRunMu.Lock()
	if !fusedLastRun.IsZero() && now.Sub(fusedLastRun) < fusedRunInterval {
		fusedRunMu.Unlock()
		return
	}
	fusedLastRun = now
	fusedRunMu.Unlock()

	// In the shadow-only burn-in config the live arm is disabled, so FillDefaults
	// leaves ScoreOn / MinUniqIP at 0; fall back to the SAME effective arm defaults
	// so the fused would_arm mirrors a real arm (a fused score over the line on a
	// vhost below the uniqIP floor could never actually fire). Shared constants,
	// no divergent literal.
	on := e.cfg.ChallengeSuspiciousScoreOn
	if on <= 0 {
		on = defaultChallengeSuspiciousScoreOn
	}
	minUniq := e.cfg.ChallengeSuspiciousMinUniqIP
	if minUniq <= 0 {
		minUniq = defaultChallengeSuspiciousMinUniqIP
	}

	sums := e.longwin.SumAll()
	for host := range sums {
		facet := FacetShadowCardinality(host)
		cost := CostShadowPressure(host)
		dc := DCFracShadowPercent(host)
		shadow := AbuseShadowOutliers(host)

		if !fuseLearnOrFreeze(fusedBaseline, host, facet, cost, dc, shadow, now) {
			continue // uncorroborated → learned, nothing to score
		}

		// Corroborated: score against the (frozen) baseline.
		row, ok := e.longwin.OneFromCache(sums, host)
		if !ok {
			continue // no long-window traffic → can't arm
		}
		zf, _ := fusedBaseline.RobustZ(host, "facet", float64(facet), fusedFacetFloor)
		zc, _ := fusedBaseline.RobustZ(host, "cost", float64(cost), fusedPctFloor)
		zd, _ := fusedBaseline.RobustZ(host, "dc", float64(dc), fusedPctFloor)
		zs, _ := fusedBaseline.RobustZ(host, "shadow", float64(shadow), fusedShadowFloor)

		corrob, delta, fused, verdict := fusedVhostVerdict(
			row.Score, facet, cost, dc, row.UniqueIPs, minUniq, zf, zc, zd, zs, on)
		if verdict == "" {
			continue
		}
		if !e.shouldLogVhostSuppress("fusedscore:"+host, now) {
			continue
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=fused_score host=%s base=%.3f fused=%.3f delta=%.3f zf=%.1f zc=%.1f zd=%.1f zs=%.1f corrob=%d uniq=%d verdict=%s",
			host, row.Score, fused, delta, zf, zc, zd, zs, corrob, row.UniqueIPs, verdict,
		)
	}

	fusedBaseline.Prune(now.Add(-fusedBaselineTTL))
}
