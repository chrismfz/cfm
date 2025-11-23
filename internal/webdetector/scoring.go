// internal/webdetector/scoring.go
package webdetector

import (
	"math"
	"sort"
)

// Signals is the feature vector we score on.
// This is the bridge to ML later: just dump this to a model.

type Signals struct {
	RPS          float64
	R3xx         float64
	R4xx         float64
	R5xx         float64

	// Fine-grained statuses
	R401         float64
	R403         float64
	R404         float64
	R50x         float64 // 500 + 502 + 503 per second
	R504         float64

	ErrRatio     float64
	Auth401Ratio float64
	UniqueIPs    int
	MedianPerIP  float64
	BytesRPS     float64 // bytes per second
	HotIPs       int

        BotRatio      float64 // 0–1
        PathDiversity float64 // unique_paths / total
        UADiversity   float64 // unique_uas / total
        PostRatio     float64 // POST / total

}




// Result is the scored outcome.
type Result struct {
	Score    float64
	Reasons  []string
	Signals  Signals
	RawScore float64 // pre-normalized, mostly for debug
}

// Scorer is an interface so you can plug ML later.
type Scorer interface {
	Score(Signals) Result
}

// heuristicScorer is the current built-in policy.
// Reference values are deliberately conservative and can be tuned.
type heuristicScorer struct{}

// NewScorer returns a heuristic scorer for now.
func NewScorer() Scorer { return &heuristicScorer{} }

// DefaultScorer is a convenience wrapper.
func DefaultScorer() Scorer { return NewScorer() }

// Tunable "reference" values (rough orders of magnitude)
const (
	refRPSTotal    = 1000
	refRPS3xx      = 200
	refRPS4xx      = 200
	refRPS5xx      = 50

	refRPS401      = 50
	refRPS403      = 50
	refRPS404      = 100
	refRPS50x      = 20
	refRPS504      = 10

	refUniqueIPs   = 300
	refErrRatio    = 0.20
	refAuth401     = 0.10
	refMedianPerIP = 3
	refBytesRPS    = 10 * 1024 * 1024 // 10 MB/s π.χ.
	refHotIPs      = 50
        // Αναμενόμενες τάξεις μεγέθους για τα νέα ratios
        refBotRatio      = 0.50 // πάνω από 50% bot UAs αρχίζει και βρωμάει
        refPathDiversity = 0.20 // scanners συχνά έχουν >20% unique path / req
        refUADiversity   = 0.05 // συνήθως λίγα UAs για πολλά req
        refPostRatio     = 0.30 // πολλά POST → πιθανό login abuse / API abuse
)


func (s *heuristicScorer) Score(sig Signals) Result {
        var (
                score   float64
                reasons []string
        )

        norm := func(v, ref float64) float64 {
            if ref <= 0 {
                return 0
            }
            return clamp01(v / ref)
        }

        // Βασικά norms
        rpsNorm   := norm(sig.RPS, refRPSTotal)
        r3Norm    := norm(sig.R3xx, refRPS3xx)
        r4Norm    := norm(sig.R4xx, refRPS4xx)
        r5Norm    := norm(sig.R5xx, refRPS5xx)
        uniqNorm  := norm(float64(sig.UniqueIPs), refUniqueIPs)
        errNorm   := norm(sig.ErrRatio, refErrRatio)
        authNorm  := norm(sig.Auth401Ratio, refAuth401)
        medNorm   := norm(sig.MedianPerIP, refMedianPerIP)
        bytesNorm := norm(sig.BytesRPS, refBytesRPS)
        hotNorm   := norm(float64(sig.HotIPs), refHotIPs)

        botNorm      := norm(sig.BotRatio, refBotRatio)
        pathDivNorm  := norm(sig.PathDiversity, refPathDiversity)
        uaDivNorm    := norm(sig.UADiversity, refUADiversity)
        postRatioNorm:= norm(sig.PostRatio, refPostRatio)
        // Fine-grained status norms
        r401Norm := norm(sig.R401, refRPS401)
        r403Norm := norm(sig.R403, refRPS403)
        r404Norm := norm(sig.R404, refRPS404)
        r50xNorm := norm(sig.R50x, refRPS50x)
        r504Norm := norm(sig.R504, refRPS504)

        // Raw score aggregation (εύκολα ρυθμίσιμα weights)
        raw := 0.0
        raw += 2.0 * rpsNorm
        raw += 1.5 * uniqNorm
        raw += 1.0 * r3Norm
        raw += 2.0 * r5Norm
        raw += 1.0 * r4Norm
        raw += 1.0 * errNorm
        raw += 0.8 * authNorm
        raw -= 0.5 * medNorm

        // Νέα signals
        raw += 1.2 * r401Norm
        raw += 1.0 * r403Norm
        raw += 1.0 * r404Norm
        raw += 1.5 * r50xNorm
        raw += 1.5 * r504Norm
        // Δίνουμε και στα bytes ένα μικρό βάρος (ενδεικτικά)
        raw += 0.5 * bytesNorm
        raw += 0.8 * hotNorm

        // νέα weights
        raw += 0.8 * botNorm
        raw += 0.8 * pathDivNorm
        raw += 0.5 * uaDivNorm
        raw += 0.7 * postRatioNorm

        // Reasons – short and stable for CLI / logs.
        if sig.RPS > refRPSTotal {
                reasons = append(reasons, "high_rps")
        }
        if sig.R5xx > refRPS5xx {
                reasons = append(reasons, "high_5xx")
        }
        if sig.R4xx > refRPS4xx {
                reasons = append(reasons, "high_4xx")
        }
        if sig.R3xx > refRPS3xx {
                reasons = append(reasons, "high_3xx")
        }
        if sig.ErrRatio > refErrRatio {
                reasons = append(reasons, "high_error_ratio")
        }
        if sig.Auth401Ratio > refAuth401 {
                reasons = append(reasons, "auth401_bruteforce_like")
        }
        if sig.UniqueIPs > int(refUniqueIPs) {
                reasons = append(reasons, "many_unique_ips")
        }
        if sig.MedianPerIP > refMedianPerIP {
                reasons = append(reasons, "few_ips_with_high_rps")
        }
        if sig.HotIPs > int(refHotIPs) {
                reasons = append(reasons, "many_hot_ips")
        }

        if sig.BotRatio > refBotRatio {
                reasons = append(reasons, "many_bot_user_agents")
        }
        if sig.PathDiversity > refPathDiversity && sig.RPS > 1 {
                reasons = append(reasons, "scanner_like_path_diversity")
        }
        if sig.PostRatio > refPostRatio && sig.Auth401Ratio > refAuth401 {
                reasons = append(reasons, "post_heavy_login_abuse_like")
        }

        // Extra reasons από fine-grained status mix
        if sig.R401 > 0 && sig.R401 > sig.R404 {
                reasons = append(reasons, "auth401_bruteforce_like")
        }
        if sig.R404 > refRPS404 {
                reasons = append(reasons, "scanner_404_heavy")
        }
        if sig.R403 > refRPS403 {
                reasons = append(reasons, "waf_403_heavy")
        }
        if sig.R50x > refRPS50x {
                reasons = append(reasons, "backend_5xx_meltdown")
        }
        if sig.R504 > refRPS504 {
                reasons = append(reasons, "gateway_timeout_burst")
        }

        sort.Strings(reasons)

        // Απλό normalization του raw σε [0,1]
        score = clamp01(raw / 6.0) // το 6.0 μπορούμε να το πειράξουμε αργότερα

        return Result{
                Score:    score,
                RawScore: raw,
                Reasons:  reasons,
                Signals:  sig,
        }
}





func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	if math.IsNaN(v) {
		return 0
	}
	return v
}
