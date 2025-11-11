// internal/policy/policy.go
package policy

import (
	"fmt"
	"math"
	"sort"
)

// Signals are detector-agnostic inputs (easy to feed from Metrics or future ML features).
type Signals struct {
	RPS          float64 // total requests/sec
	R3xx         float64
	R4xx         float64
	R5xx         float64
	ErrRatio     float64 // (4xx+5xx+499)/total in window
	Auth401Ratio float64 // optional; 0 if not applicable
	UniqueIPs    int
	MedianPerIP  float64 // optional; 0 if unknown
}

type Result struct {
	Score   float64  // 0..1
	Reasons []string // short human-readable reasons
}

type Config struct {
	MinScore float64 // default 0.60

	// Simple weights; keep stable now, tune later (or replace by ML).
	W_RPS          float64
	W_ErrRatio     float64
	W_R5xx         float64
	W_R4xx         float64
	W_R3xx         float64
	W_Auth401Ratio float64
	W_UniqueIPs    float64
	W_MedianPerIP  float64

	// Soft thresholds used for reason strings & gentle normalization.
	T_RPSHigh       float64
	T_ErrHigh       float64
	T_R5xxHigh      float64
	T_R4xxHigh      float64
	T_R3xxHigh      float64
	T_UniqueIPsHigh int
}

func DefaultConfig() Config {
	return Config{
		MinScore:        0.60,
		W_RPS:           0.20,
		W_ErrRatio:      0.25,
		W_R5xx:          0.15,
		W_R4xx:          0.10,
		W_R3xx:          0.05,
		W_Auth401Ratio:  0.05,
		W_UniqueIPs:     0.15,
		W_MedianPerIP:   0.05,
		T_RPSHigh:       10,      // ~10 rps in the window
		T_ErrHigh:       0.20,    // >20% errors
		T_R5xxHigh:      1.0,     // 1 rps 5xx
		T_R4xxHigh:      2.0,     // 2 rps 4xx
		T_R3xxHigh:      3.0,     // 3 rps 3xx (redirect loops, etc.)
		T_UniqueIPsHigh: 50,      // bursty scatter
	}
}

type Scorer struct{ Cfg Config }

func New(c Config) *Scorer {
	if c.MinScore <= 0 { c.MinScore = 0.60 }
	return &Scorer{Cfg: c}
}

// Score scales inputs by soft-thresholds, applies weights, returns 0..1.
func (s *Scorer) Score(sig Signals) Result {
	c := s.Cfg
	reasons := []string{}

	// Normalize each component roughly to 0..1 by threshold (soft clip).
	norm := func(v, t float64) float64 {
		if t <= 0 { return 0 }
		x := v / t
		if x > 1 { x = 1 + 0.5*(1 - math.Exp(-(x-1))) } // smooth >1
		if x < 0 { x = 0 }
		return x
	}

	nRPS   := norm(sig.RPS, c.T_RPSHigh)
	nErr   := norm(sig.ErrRatio, c.T_ErrHigh)
	nR5xx  := norm(sig.R5xx, c.T_R5xxHigh)
	nR4xx  := norm(sig.R4xx, c.T_R4xxHigh)
	nR3xx  := norm(sig.R3xx, c.T_R3xxHigh)
	n401   := sig.Auth401Ratio // already a ratio
	nUIP   := norm(float64(sig.UniqueIPs), float64(c.T_UniqueIPsHigh))
	nMedIP := norm(sig.MedianPerIP, 1.0) // 1 rps/ip median as "high"

	score := c.W_RPS*nRPS + c.W_ErrRatio*nErr + c.W_R5xx*nR5xx + c.W_R4xx*nR4xx +
		c.W_R3xx*nR3xx + c.W_Auth401Ratio*n401 + c.W_UniqueIPs*nUIP + c.W_MedianPerIP*nMedIP
	if score > 1 { score = 1 }
	if score < 0 { score = 0 }

	// Reasons (kept short for logs/CLI)
	if sig.RPS > c.T_RPSHigh { reasons = append(reasons, fmt.Sprintf("high rps=%.2f", sig.RPS)) }
	if sig.ErrRatio > c.T_ErrHigh { reasons = append(reasons, fmt.Sprintf("high err%%=%.0f", 100*sig.ErrRatio)) }
	if sig.R5xx > c.T_R5xxHigh { reasons = append(reasons, fmt.Sprintf("5xx rps=%.2f", sig.R5xx)) }
	if sig.R4xx > c.T_R4xxHigh { reasons = append(reasons, fmt.Sprintf("4xx rps=%.2f", sig.R4xx)) }
	if sig.R3xx > c.T_R3xxHigh { reasons = append(reasons, fmt.Sprintf("3xx rps=%.2f", sig.R3xx)) }
	if sig.Auth401Ratio > 0.1 { reasons = append(reasons, fmt.Sprintf("auth401%%=%.0f", 100*sig.Auth401Ratio)) }
	if sig.UniqueIPs > c.T_UniqueIPsHigh { reasons = append(reasons, fmt.Sprintf("uniqIPs=%d", sig.UniqueIPs)) }
	if sig.MedianPerIP > 1.0 { reasons = append(reasons, fmt.Sprintf("median/ip=%.2f rps", sig.MedianPerIP)) }

	// Sort reasons for stable output
	sort.Strings(reasons)
	return Result{Score: score, Reasons: reasons}
}
