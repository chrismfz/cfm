// internal/webdetector/longwin.go
package webdetector

import (
	"sort"
	"sync"
	"time"
)

// MiniMetrics is what the short-window engine produces per host.
// We feed this into the long-window ring.
type MiniMetrics struct {
	RPSTotal       float64
	RPS2xx         float64
	RPS3xx         float64
	RPS4xx         float64
	RPS5xx         float64
        RPS50x        float64
        RPS504        float64
	RPS401         float64
	RPS403         float64
	RPS404         float64
	RPS499         float64
	ErrRatio       float64
	Auth401Ratio   float64
	UniqueIPs      int
	MedianPerIPRPS float64
	BytesRPS       float64
	HotIPs         int

        // Νέα short-window derived signals
        BotRatio      float64 // 0–1, αναλογία bot-like UAs
        PathDiversity float64 // unique_paths / total_req
        UADiversity   float64 // unique_uas / total_req
        PostRatio     float64 // POST / total_req
}

// SuspiciousRow is the scored long-window output for CLI / API.
type SuspiciousRow struct {
	Host         string   `json:"host"`
	Score        float64  `json:"score"`
	Reasons      []string `json:"reasons"`
	RPS          float64  `json:"rps"`
	R3xx         float64  `json:"rps_3xx"`
	R4xx         float64  `json:"rps_4xx"`
	R5xx         float64  `json:"rps_5xx"`
	UniqueIPs    int      `json:"unique_ips"`
	ErrRatio     float64  `json:"err_ratio"`
	Auth401Ratio float64  `json:"auth401_ratio"`
	HotIPs       int      `json:"hot_ips"`

        BotRatio      float64 `json:"bot_ratio"`
        PathDiversity float64 `json:"path_diversity"`
        UADiversity   float64 `json:"ua_diversity"`
        PostRatio     float64 `json:"post_ratio"`

	// SolverFarm is true while challenge_solver_farm currently sees a
	// distributed solver farm on this vhost. Stamped by the API handlers, not
	// by the long-window scorer: it is an external verdict, not a scoring
	// input. See solverfarm_marks.go.
	SolverFarm bool `json:"solver_farm"`

	// ShadowOutliers is the live abuse_shadow rate-outlier count for this vhost.
	// Stamped by the API handlers, not the scorer (external verdict). See
	// abuse_shadow_marks.go.
	ShadowOutliers int `json:"shadow_outliers"`

	// QueryCardinality is the live abuse_shadow facet distinct-full-URL count for
	// this vhost (Signal F). Stamped by the API handlers, not the scorer (external
	// verdict). See abuse_shadow_facet_marks.go.
	QueryCardinality int `json:"query_cardinality"`

	// CostPressure is the live abuse_shadow 5xx percent for this vhost (Signal G).
	// Stamped by the API handlers, not the scorer (external verdict). See
	// abuse_shadow_cost_marks.go.
	CostPressure int `json:"cost_pressure"`
}

// LongRow is the raw long-window aggregate without scoring.
type LongRow struct {
	Host         string  `json:"host"`
	RPS          float64 `json:"rps"`
	R3xx         float64 `json:"rps_3xx"`
	R4xx         float64 `json:"rps_4xx"`
	R5xx         float64 `json:"rps_5xx"`
	UniqueIPs    int     `json:"unique_ips"`
	ErrRatio     float64 `json:"err_ratio"`
	Auth401Ratio float64 `json:"auth401_ratio"`
	HotIPs       int     `json:"hot_ips"`

       BotRatio      float64 `json:"bot_ratio"`
       PathDiversity float64 `json:"path_diversity"`
       UADiversity   float64 `json:"ua_diversity"`
       PostRatio     float64 `json:"post_ratio"`
}

type bucket struct {
	Tot         int
	C3, C4, C5  int
        C50x, C504  int
	C401, C403  int
	C404        int
	C499        int
	Uniq        int
	ErrRatio    float64
	Auth401     float64
	MedPerIP    float64
	BytesRPSMax float64 // π.χ. κρατάμε max BytesRPS στα slots
	HotIPsMax   int
        // Max values από τα νέα signals στο horizon
        BotRatioMax      float64
        PathDivMax       float64
        UADivMax         float64
        PostRatioMax     float64
}


// LongWindow is a per-engine ring buffer horizon of web activity.
type LongWindow struct {
	mu         sync.RWMutex
	slots      []map[string]*bucket
	idx        int
	every      time.Duration
	lastRotate time.Time
	scorer     Scorer
}


// Hard thresholds για να μην βαφτίζουμε "ύποπτα" vhosts με ελάχιστη κίνηση.
const (
    minSuspiciousRPS       = 0.5  // ελάχιστο μέσο RPS στο long window
    minSuspiciousUniqueIPs = 3    // ελάχιστες μοναδικές IPs
    minSuspiciousTotReq    = 30   // ελάχιστα συνολικά requests στο horizon
)

// NewLongWindow creates a long-window over the given horizon with bucket step `every`.
func NewLongWindow(horizon, every time.Duration, scorer Scorer) *LongWindow {
	if horizon <= 0 {
		horizon = 10 * time.Minute
	}
	if every <= 0 {
		every = 60 * time.Second
	}
	nSlots := int(horizon / every)
	if nSlots < 2 {
		nSlots = 2
	}
	slots := make([]map[string]*bucket, nSlots)
	for i := range slots {
		slots[i] = make(map[string]*bucket)
	}
	if scorer == nil {
		scorer = DefaultScorer()
	}
	return &LongWindow{
		slots:      slots,
		every:      every,
		lastRotate: time.Now().Truncate(every),
		scorer:     scorer,
	}
}

// Tick ingests the current short-window snapshot into the long window.
func (lw *LongWindow) Tick(now time.Time, snap map[string]MiniMetrics) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	if lw.lastRotate.IsZero() {
		lw.lastRotate = now.Truncate(lw.every)
	}

	for now.Sub(lw.lastRotate) >= lw.every {
		lw.idx = (lw.idx + 1) % len(lw.slots)
		lw.slots[lw.idx] = make(map[string]*bucket)
		lw.lastRotate = lw.lastRotate.Add(lw.every)
	}

	slot := lw.slots[lw.idx]
	sec := lw.every.Seconds()
	if sec <= 0 {
		sec = 1
	}


for host, m := range snap {
    b := slot[host]
    if b == nil {
        b = &bucket{}
        slot[host] = b
    }
    b.Tot  += int(m.RPSTotal * sec)
    b.C3   += int(m.RPS3xx * sec)
    b.C4   += int(m.RPS4xx * sec)
    b.C5   += int(m.RPS5xx * sec)
    b.C50x += int(m.RPS50x * sec)
    b.C504 += int(m.RPS504 * sec)
    b.C401 += int(m.RPS401 * sec)
    b.C403 += int(m.RPS403 * sec)
    b.C404 += int(m.RPS404 * sec)
    b.C499 += int(m.RPS499 * sec)

    if m.UniqueIPs > b.Uniq {
        b.Uniq = m.UniqueIPs
    }
    if m.ErrRatio > 0 {
        b.ErrRatio = m.ErrRatio
    }
    if m.Auth401Ratio > 0 {
        b.Auth401 = m.Auth401Ratio
    }
    if m.MedianPerIPRPS > 0 {
        b.MedPerIP = m.MedianPerIPRPS
    }
    if m.BytesRPS > b.BytesRPSMax {
        b.BytesRPSMax = m.BytesRPS
    }
    if m.HotIPs > b.HotIPsMax {
        b.HotIPsMax = m.HotIPs
    }
    if m.BotRatio > b.BotRatioMax {
        b.BotRatioMax = m.BotRatio
    }
    if m.PathDiversity > b.PathDivMax {
        b.PathDivMax = m.PathDiversity
    }
    if m.UADiversity > b.UADivMax {
        b.UADivMax = m.UADiversity
    }
    if m.PostRatio > b.PostRatioMax {
        b.PostRatioMax = m.PostRatio
    }

}



}

func (lw *LongWindow) horizonSec() float64 {
	if lw == nil || lw.every <= 0 {
		return 1
	}
	return float64(len(lw.slots)) * lw.every.Seconds()
}

func (lw *LongWindow) SumAll() map[string]bucket {
	lw.mu.RLock()
	defer lw.mu.RUnlock()

	out := make(map[string]bucket)
	for _, slot := range lw.slots {
		for h, b := range slot {
			agg := out[h]
			agg.Tot += b.Tot
			agg.C3  += b.C3
			agg.C4  += b.C4
			agg.C5  += b.C5
                        agg.C50x += b.C50x
                        agg.C504 += b.C504
			agg.C401+= b.C401
			agg.C403  += b.C403
			agg.C404  += b.C404
			agg.C499+= b.C499
			if b.Uniq > agg.Uniq {
				agg.Uniq = b.Uniq
			}
			if b.ErrRatio > 0 {
				agg.ErrRatio = b.ErrRatio
			}
			if b.Auth401 > 0 {
				agg.Auth401 = b.Auth401
			}
			if b.MedPerIP > 0 {
				agg.MedPerIP = b.MedPerIP
			}
			if b.BytesRPSMax > agg.BytesRPSMax {
			    agg.BytesRPSMax = b.BytesRPSMax
			}
                        if b.HotIPsMax > agg.HotIPsMax {
                                agg.HotIPsMax = b.HotIPsMax
                        }
                        if b.BotRatioMax > agg.BotRatioMax {
                                agg.BotRatioMax = b.BotRatioMax
                        }
                        if b.PathDivMax > agg.PathDivMax {
                                agg.PathDivMax = b.PathDivMax
                        }
                        if b.UADivMax > agg.UADivMax {
                                agg.UADivMax = b.UADivMax
                        }
                        if b.PostRatioMax > agg.PostRatioMax {
                                agg.PostRatioMax = b.PostRatioMax
                        }
			out[h] = agg
		}
	}
	return out
}

// SuspiciousTop returns top suspicious hosts over the long window.
func (lw *LongWindow) SuspiciousTop(limit int, minScore float64) []SuspiciousRow {
	if lw == nil || lw.scorer == nil {
		return nil
	}

	sums := lw.SumAll()
	hor := lw.horizonSec()
	if hor <= 0 {
		hor = 1
	}

        rows := make([]SuspiciousRow, 0, len(sums))
        for h, b := range sums {
                if b.Tot <= 0 {
                        continue
                }
                rps := float64(b.Tot) / hor
		r3  := float64(b.C3)  / hor
		r4  := float64(b.C4)  / hor
                r5  := float64(b.C5)   / hor
                r401 := float64(b.C401) / hor
                r403 := float64(b.C403) / hor
                r404 := float64(b.C404) / hor
                r50x := float64(b.C50x) / hor
                r504 := float64(b.C504) / hor

		errR := b.ErrRatio
		if errR == 0 {
			errR = (float64(b.C4) + float64(b.C5) + float64(b.C499)) / maxf(float64(b.Tot), 1)
		}

                // --- Noise filters: κόβουμε πολύ χαμηλής έντασης vhosts ---
                // 1) Πολύ χαμηλό μέσο RPS στο long window → σκουπίδια / τυχαία probes.
                if rps < minSuspiciousRPS {
                        continue
                }
                // 2) Λίγες μοναδικές IPs στο horizon → μεμονωμένο bot / scan.
                if b.Uniq < minSuspiciousUniqueIPs {
                        continue
                }
                // 3) Πολύ λίγα συνολικά requests → δεν έχει στατιστικό βάρος.
                if b.Tot < minSuspiciousTotReq {
                        continue
                }

sig := 	Signals{
    RPS:          rps,
    R3xx:         r3,
    R4xx:         r4,
    R5xx:         r5,
    R401:         r401,
    R403:         r403,
    R404:         r404,
    R50x:         r50x,  // π.χ. aggregated 500+502+503
    R504:         r504,
    ErrRatio:     errR,
    Auth401Ratio: b.Auth401,
    UniqueIPs:    b.Uniq,
    MedianPerIP:  b.MedPerIP,
    BytesRPS:     b.BytesRPSMax,
    HotIPs:       b.HotIPsMax,
    BotRatio:     b.BotRatioMax,
    PathDiversity: b.PathDivMax,
    UADiversity:   b.UADivMax,
    PostRatio:     b.PostRatioMax,
}
		res := lw.scorer.Score(sig)
		if res.Score >= minScore {
			rows = append(rows, SuspiciousRow{
				Host:         h,
				Score:        res.Score,
				Reasons:      res.Reasons,
				RPS:          rps,
				R3xx:         r3,
				R4xx:         r4,
				R5xx:         r5,
				UniqueIPs:    b.Uniq,
				ErrRatio:     errR,
				Auth401Ratio: b.Auth401,
				HotIPs:       b.HotIPsMax,
                                BotRatio:     b.BotRatioMax,
                                PathDiversity: b.PathDivMax,
                                UADiversity:   b.UADivMax,
                                PostRatio:     b.PostRatioMax,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			return rows[i].RPS > rows[j].RPS
		}
		return rows[i].Score > rows[j].Score
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// All returns raw long-window rows (no scoring), sorted by RPS desc.
func (lw *LongWindow) All() []LongRow {
	if lw == nil {
		return nil
	}
	sums := lw.SumAll()
	hor := lw.horizonSec()
	if hor <= 0 {
		hor = 1
	}
	out := make([]LongRow, 0, len(sums))
	for h, b := range sums {
		if b.Tot <= 0 {
			continue
		}
		rps := float64(b.Tot) / hor
		r3  := float64(b.C3)  / hor
		r4  := float64(b.C4)  / hor
		r5  := float64(b.C5)  / hor

		errR := b.ErrRatio
		if errR == 0 {
			errR = (float64(b.C4) + float64(b.C5) + float64(b.C499)) / maxf(float64(b.Tot), 1)
		}

		out = append(out, LongRow{
			Host:         h,
			RPS:          rps,
			R3xx:         r3,
			R4xx:         r4,
			R5xx:         r5,
			UniqueIPs:    b.Uniq,
			ErrRatio:     errR,
			Auth401Ratio: b.Auth401,
			HotIPs:       b.HotIPsMax,
                        BotRatio:     b.BotRatioMax,
                        PathDiversity: b.PathDivMax,
                        UADiversity:   b.UADivMax,
                        PostRatio:     b.PostRatioMax,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RPS == out[j].RPS {
			return out[i].Host < out[j].Host
		}
		return out[i].RPS > out[j].RPS
	})
	return out
}

// One returns scored long-window metrics for a single host (no minScore).
func (lw *LongWindow) One(host string) (SuspiciousRow, bool) {
	if lw == nil || lw.scorer == nil {
		return SuspiciousRow{}, false
	}
	sums := lw.SumAll()
	b, ok := sums[host]
	if !ok || b.Tot <= 0 {
		return SuspiciousRow{}, false
	}
	hor := lw.horizonSec()
	if hor <= 0 {
		hor = 1
	}
	rps := float64(b.Tot) / hor
	r3  := float64(b.C3)  / hor
	r4  := float64(b.C4)  / hor
        r5  := float64(b.C5)   / hor
        r401 := float64(b.C401) / hor
        r403 := float64(b.C403) / hor
        r404 := float64(b.C404) / hor
        r50x := float64(b.C50x) / hor
        r504 := float64(b.C504) / hor

	errR := b.ErrRatio
	if errR == 0 {
		errR = (float64(b.C4) + float64(b.C5) + float64(b.C499)) / maxf(float64(b.Tot), 1)
	}

sig := Signals{
    RPS:          rps,
    R3xx:         r3,
    R4xx:         r4,
    R5xx:         r5,
    R401:         r401,
    R403:         r403,
    R404:         r404,
    R50x:         r50x,
    R504:         r504,
    ErrRatio:     errR,
    Auth401Ratio: b.Auth401,
    UniqueIPs:    b.Uniq,
    MedianPerIP:  b.MedPerIP,
    BytesRPS:     b.BytesRPSMax,
    HotIPs:       b.HotIPsMax,
    BotRatio:     b.BotRatioMax,
    PathDiversity: b.PathDivMax,
    UADiversity:   b.UADivMax,
    PostRatio:     b.PostRatioMax,
}

	res := lw.scorer.Score(sig)
	row := SuspiciousRow{
		Host:         host,
		Score:        res.Score,
		Reasons:      res.Reasons,
		RPS:          rps,
		R3xx:         r3,
		R4xx:         r4,
		R5xx:         r5,
		UniqueIPs:    b.Uniq,
		ErrRatio:     errR,
		Auth401Ratio: b.Auth401,
		HotIPs:       b.HotIPsMax,
                BotRatio:     b.BotRatioMax,
                PathDiversity: b.PathDivMax,
                UADiversity:   b.UADivMax,
                PostRatio:     b.PostRatioMax,
	}
	return row, true
}


// OneFromCache is like One but uses a pre-computed SumAll result.
// Call SumAll() once before a loop, then use this per-host to avoid
// O(N * slots * hosts) cost.
func (lw *LongWindow) OneFromCache(sums map[string]bucket, host string) (SuspiciousRow, bool) {
	if lw == nil || lw.scorer == nil {
		return SuspiciousRow{}, false
	}
	b, ok := sums[host]
	if !ok || b.Tot <= 0 {
		return SuspiciousRow{}, false
	}
	hor := lw.horizonSec()
	if hor <= 0 {
		hor = 1
	}
	rps  := float64(b.Tot) / hor
	r3   := float64(b.C3)  / hor
	r4   := float64(b.C4)  / hor
	r5   := float64(b.C5)  / hor
	r401 := float64(b.C401) / hor
	r403 := float64(b.C403) / hor
	r404 := float64(b.C404) / hor
	r50x := float64(b.C50x) / hor
	r504 := float64(b.C504) / hor
	errR := b.ErrRatio
	if errR == 0 {
		errR = (float64(b.C4) + float64(b.C5) + float64(b.C499)) / maxf(float64(b.Tot), 1)
	}
	sig := Signals{
		RPS: rps, R3xx: r3, R4xx: r4, R5xx: r5,
		R401: r401, R403: r403, R404: r404, R50x: r50x, R504: r504,
		ErrRatio: errR, Auth401Ratio: b.Auth401, UniqueIPs: b.Uniq,
		MedianPerIP: b.MedPerIP, BytesRPS: b.BytesRPSMax, HotIPs: b.HotIPsMax,
		BotRatio: b.BotRatioMax, PathDiversity: b.PathDivMax,
		UADiversity: b.UADivMax, PostRatio: b.PostRatioMax,
	}
	res := lw.scorer.Score(sig)
	return SuspiciousRow{
		Host: host, Score: res.Score, Reasons: res.Reasons,
		RPS: rps, R3xx: r3, R4xx: r4, R5xx: r5,
		UniqueIPs: b.Uniq, ErrRatio: errR, Auth401Ratio: b.Auth401,
		HotIPs: b.HotIPsMax, BotRatio: b.BotRatioMax,
		PathDiversity: b.PathDivMax, UADiversity: b.UADivMax, PostRatio: b.PostRatioMax,
	}, true
}



func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
