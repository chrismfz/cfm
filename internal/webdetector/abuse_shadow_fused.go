package webdetector

import (
	"time"

	"cfm/internal/logging"
)

// abuse_shadow_fused.go — Track-1 score fusion, LOG-ONLY (docs/traffic-classifier.md
// → "Track-1 shadow fusion"). It measures how often the three vhost-level shadow
// signals (facet / cost / dc), fused as weighted contributors on top of the live
// suspicious score, WOULD newly arm a vhost that the live score alone did not —
// WITHOUT touching the live arm. It writes one `signal=fused_score … verdict=…`
// line per corroborated, would-arm vhost per throttle window to the existing
// cfm.abuse_shadow.log; nothing here challenges, blocks, or changes the score.
//
// It rides the existing ABUSE_SHADOW master (no new config knob — the weights and
// baseline geometry are hardcoded constants below, to be tuned in-code from the
// burn-in data, not operator surface). The live arm keeps reading only
// SuspiciousRow.Score = clamp01(raw/6); the fused value is a SEPARATE parallel
// computation, so adding it can never rescale the live 0.70 line (scoring.go's
// /6.0 divisor hazard — see the doc).
//
// Mechanism:
//   fused = clamp01(base_score + Δ)
//   Δ     = fusedWeight · Σ clamp(robustZ_x, 0, zClamp)   (capped at fusedGroupCap)
// where robustZ_x is the modified robust-z (vhost_baseline.go) of signal x's
// current magnitude against THIS vhost's own recent history. Contributions are
// clamped ≥0 (a signal dropping below baseline is not evidence of abuse), so Δ ≥ 0
// and fusion only ever ADDS arms (net-new catches). Lowering an over-armed
// verified-crawler vhost is the verified-crawler fork's job, already shipped —
// not this.
//
// Two guardrails, both from the doc:
//   - Corroboration: Δ is applied only when ≥2 of the four shadow signals co-fire
//     this window. A single signal alone (e.g. planetgym.gr: 402 facet URLs on 1
//     path from ONE IP, no cost/dc) never moves the fused score — that is the
//     "facet alone is benign single-endpoint noise" guard, and it also enforces
//     "datacenter-ASN alone NEVER decides" (dc alone = active 1 = no Δ).
//   - Self-baseline freeze: a vhost is folded into its own baseline only while
//     UNCORROBORATED (active < 2), so an active corroborated flood never trains
//     the baseline to accept itself. A quiet vhost keeps learning (mostly zeros),
//     so its first real corroborated spike reads as a large deviation.
//     KNOWN BLIND SPOT (log-only, acceptable): a vhost corroborated on (nearly)
//     every window — e.g. a legit cloud-hosted app permanently at dc>0 AND cost>0
//     — is frozen from the start, never reaches MinSamples, and so yields z=0 /
//     Δ=0 forever. That correctly prevents a false arm, but a genuine attack
//     riding a permanently-corroborated vhost is likewise invisible to fusion (the
//     live base score still applies). So burn-in would_arm counts UNDERCOUNT that
//     class — factor it in when tuning weights.

var fusedBaseline = newVhostBaseline(vhostBaselineConfig{
	Window:     60,    // ~ the last 60 emit windows of per-vhost history
	MinSamples: 8,     // below this the baseline stays silent (robustZ → 0)
	MaxHosts:   20000, // backstop; Prune (below) is the primary bound
})

const (
	// Δ = fusedWeight · Σ clamp(z,0,fusedZClamp), capped at fusedGroupCap. These
	// are burn-in STARTING weights, tuned in-code from would_arm/base data — not
	// config. Sizing: base scores are 0–1 against a 0.70 arm; one saturated signal
	// (z=8) adds 0.16, two add 0.32→cap 0.25, so a corroborated spike can lift a
	// mid-score (~0.5) over the line but not manufacture an arm from nothing.
	fusedWeight   = 0.02
	fusedZClamp   = 8.0
	fusedGroupCap = 0.25

	// Per-feature madFloor: the smallest deviation that is meaningful for that
	// feature's scale, so a flat/quiet baseline doesn't explode robustZ. facet is a
	// distinct-URL count (hundreds→thousands); cost/dc are percentages (0–100);
	// shadow is an outlier IP count (small integers).
	fusedFacetFloor  = 50.0
	fusedPctFloor    = 5.0
	fusedShadowFloor = 1.0

	// fusedBaselineTTL: drop a vhost's baseline after this long with no window.
	fusedBaselineTTL = 30 * time.Minute
)

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// activeSignals counts how many of the four shadow magnitudes are non-zero this
// window — the corroboration count.
func activeSignals(facet, cost, dc, shadow int) int {
	return b2i(facet > 0) + b2i(cost > 0) + b2i(dc > 0) + b2i(shadow > 0)
}

// fuseObserveOrFreeze folds a vhost's current magnitudes into bl ONLY while it is
// uncorroborated (active < 2); a corroborated vhost is FROZEN (not observed), so
// an active flood can never train the baseline to accept itself. Returns true iff
// it observed (i.e. the vhost was uncorroborated). Split out so this
// security-critical freeze invariant is unit-testable without standing up an
// Engine or touching the package-global baseline.
func fuseObserveOrFreeze(bl *vhostBaseline, host string, facet, cost, dc, shadow int, now time.Time) bool {
	if activeSignals(facet, cost, dc, shadow) >= 2 {
		return false // frozen
	}
	bl.Observe(host, "facet", float64(facet), now)
	bl.Observe(host, "cost", float64(cost), now)
	bl.Observe(host, "dc", float64(dc), now)
	bl.Observe(host, "shadow", float64(shadow), now)
	return true
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

// fusedVhostVerdict is the PURE fusion decision for one vhost: from its live base
// score, the four signal magnitudes, and their robust-z's, it returns the
// corroboration count, the delta, the fused score, and whether the fused score
// would arm (≥ on). Uncorroborated vhosts (active < 2) get Δ = 0 and never arm.
func fusedVhostVerdict(base float64, facet, cost, dc, shadow int, zf, zc, zd, zs, on float64) (active int, delta, fused float64, arm bool) {
	active = activeSignals(facet, cost, dc, shadow)
	if active < 2 {
		return active, 0, clamp01(base), false
	}
	delta = fusedDelta(zf, zc, zd, zs)
	fused = clamp01(base + delta)
	return active, delta, fused, fused >= on
}

// emitAbuseShadowFusedScore runs the log-only fusion over every vhost, from the
// per-tick emitIPChallenges shadow block. Corroborated vhosts (≥2 signals) are
// scored against their frozen baseline; everyone else folds this window into their
// baseline (learning "normal") and is skipped. Only a would-arm result is logged.
func (e *Engine) emitAbuseShadowFusedScore(now time.Time) {
	if !e.cfg.AbuseShadow || e.longwin == nil {
		return
	}
	on := e.cfg.ChallengeSuspiciousScoreOn
	if on <= 0 {
		on = 0.70
	}

	sums := e.longwin.SumAll()
	for host := range sums {
		facet := FacetShadowCardinality(host)
		cost := CostShadowPressure(host)
		dc := DCFracShadowPercent(host)
		shadow := AbuseShadowOutliers(host)

		// Uncorroborated vhosts fold this window into their baseline (learning
		// "normal", mostly zeros) and are skipped; corroborated ones are frozen and
		// scored below.
		if fuseObserveOrFreeze(fusedBaseline, host, facet, cost, dc, shadow, now) {
			continue
		}

		// Corroborated: baseline is frozen (above); score against it.
		row, _ := e.longwin.OneFromCache(sums, host)
		base := row.Score
		zf, _ := fusedBaseline.RobustZ(host, "facet", float64(facet), fusedFacetFloor)
		zc, _ := fusedBaseline.RobustZ(host, "cost", float64(cost), fusedPctFloor)
		zd, _ := fusedBaseline.RobustZ(host, "dc", float64(dc), fusedPctFloor)
		zs, _ := fusedBaseline.RobustZ(host, "shadow", float64(shadow), fusedShadowFloor)

		active, delta, fused, arm := fusedVhostVerdict(base, facet, cost, dc, shadow, zf, zc, zd, zs, on)
		if !arm {
			continue // corroborated but not over the line — nothing to report
		}
		// verdict distinguishes a NET-NEW catch (live score below the line) from
		// fusion merely confirming an arm the live score already made.
		verdict := "would_arm"
		if base >= on {
			verdict = "confirm"
		}
		if !e.shouldLogVhostSuppress("fusedscore:"+host, now) {
			continue
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=fused_score host=%s base=%.3f fused=%.3f delta=%.3f zf=%.1f zc=%.1f zd=%.1f zs=%.1f active=%d verdict=%s",
			host, base, fused, delta, zf, zc, zd, zs, active, verdict,
		)
	}

	fusedBaseline.Prune(now.Add(-fusedBaselineTTL))
}
