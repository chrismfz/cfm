package webdetector

import (
	"fmt"
	"time"
)

// recordChallengeScoreVerdict persists ONE would_deny challenge-score verdict into
// the durable webdetector history store as event_type=challenge_score, so the
// fingerprint-anchored per-IP conviction — which otherwise reaches only
// cfm.abuse_shadow.log (rotated) — becomes queryable via detection_history and can
// be PULLed into the fleet fingerprint-reputation store (cfm-web) as the evidence
// ledger's SECOND source after solver_farm. Mirrors RecordSolverFarmFinding (the
// detector/emit path publishes; this subscribes/persists).
//
// Deliberately LEAN (docs/challenge-score.md § "Durable capture"), because this is a
// per-IP shadow signal, not a rare finding:
//   - only the would_deny (T2) tier is persisted; would_harden stays log-only (grep).
//   - a per-IP hourly throttle (chalScorePersistEvery, applied via persistDue) caps a
//     sustained denier at ≤24 rows/day — the log keeps the fine-grained detail.
//
// The Payload keys are the ingest CONTRACT (docs/fleet-fingerprint-reputation.md §5 →
// cfm-web:docs/fingerprint-reputation.md): keep them stable. `fingerprint` is the
// anchoring TLS fp (the GROUP-BY spine — the convicted solver-farm fp when one drove
// the score, else the fp present on the scored solves, "" when no X-CFM-TLS stamp);
// `fp_convicted` says which of those it is, so the rollup can weight a convicted-fp
// row above a merely-present one. `ip` is the history column (indexed) — the ledger
// counts DISTINCT ips per fingerprint from it.
func (e *Engine) recordChallengeScoreVerdict(r chalScoreRow, verdict string, now time.Time) {
	if e == nil || e.history == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	payload := map[string]interface{}{
		"fingerprint":  r.fp,
		"fp_convicted": r.farmFP > 0,
		"score":        r.score,
		"solves":       r.solves,
		"fast":         r.fast,
		"uaimp":        r.uaImp,
		"farm":         r.farm,
		"farmfp":       r.farmFP,
		"verdict":      verdict,
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  now.Unix(),
		Type:    "challenge_score",
		IP:      r.ip,
		Reason:  challengeScoreReason(r, verdict),
		Score:   r.score,
		Payload: payload,
	})
}

// challengeScoreReason renders a short, human-readable summary for the history row's
// reason column (mirrors solverFarmReason).
func challengeScoreReason(r chalScoreRow, verdict string) string {
	fp := r.fp
	if fp == "" {
		fp = "(none)"
	}
	return fmt.Sprintf("challenge %s — score %.1f from %d solves (fast %d, ua-lie %d, farm %d, fp %d); fp %s",
		verdict, r.score, r.solves, r.fast, r.uaImp, r.farm, r.farmFP, fp)
}
