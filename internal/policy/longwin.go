// internal/policy/longwin.go
package policy

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// MiniMetrics is detector-agnostic: the detector feeds this each time it rotates its short window.
type MiniMetrics struct {
	RPSTotal     float64
	R3xx, R4xx, R5xx float64
	R401, R499   float64
	ErrRatio     float64
	Auth401Ratio float64
	UniqueIPs    int
	MedianPerIPRPS float64
	ProcAvgSec   float64
}

// bucket is per-host, per-bucket integer-ish counts plus sums. We keep ints for requests, float for rt.
type bucket struct {
	Tot, C3, C4, C5, C401, C499 int
	Uniq                        int
	RtSum                       float64
	// keep some ratios (they don't sum; we re-estimate later)
	ErrRatio, Auth401Ratio, MedPerIP float64
}

// ring holds a long horizon as buckets of host->bucket.
type ring struct {
	mu     sync.RWMutex
	slots  []map[string]bucket
	idx    int
	every  time.Duration // must match detector.Every
	factor int           // length = factor * detectorBuckets
	inited bool
}

func newRing(every time.Duration, buckets int) *ring {
	if buckets <= 0 { buckets = 10 } // fallback
	r := &ring{
		slots: make([]map[string]bucket, buckets),
		every: every,
	}
	for i := range r.slots { r.slots[i] = make(map[string]bucket) }
	return r
}

func (r *ring) advanceAndApply(snap map[string]bucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.idx = (r.idx + 1) % len(r.slots)
	// reset current slot and write fresh snapshot
	r.slots[r.idx] = make(map[string]bucket, len(snap))
	for h, b := range snap { r.slots[r.idx][h] = b }
}

// sum over all buckets (the whole long horizon)
func (r *ring) sumAll() map[string]bucket {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]bucket, 256)
	for i := range r.slots {
		for h, b := range r.slots[i] {
			acc := out[h]
			acc.Tot  += b.Tot
			acc.C3   += b.C3
			acc.C4   += b.C4
			acc.C5   += b.C5
			acc.C401 += b.C401
			acc.C499 += b.C499
			// For uniques across buckets we conservatively take max (not sum) to avoid wild overcount.
			if b.Uniq > acc.Uniq { acc.Uniq = b.Uniq }
			acc.RtSum += b.RtSum
			// Keep last observed ratios as rough signal
			if b.ErrRatio != 0 { acc.ErrRatio = b.ErrRatio }
			if b.Auth401Ratio != 0 { acc.Auth401Ratio = b.Auth401Ratio }
			if b.MedPerIP != 0 { acc.MedPerIP = b.MedPerIP }
			out[h] = acc
		}
	}
	return out
}

// ----------------- Global manager -----------------

type manager struct {
	mu     sync.RWMutex
	rings  map[string]*ring // key: "httpd" | "nginx"
	scorer *Scorer
	// config
	factor int
	every  time.Duration
}

var gMgr *manager
var once sync.Once

// Init or reconfigure (idempotent). If already initialized, only updates factor/every for new rings.
func InitLongWindow(every time.Duration, factor int, scorerCfg Config) {
	if factor <= 0 { factor = 10 }
	once.Do(func() {
		gMgr = &manager{
			rings:  make(map[string]*ring),
			factor: factor,
			every:  every,
			scorer: New(scorerCfg),
		}
	})
	// allow subsequent calls to adjust defaults for new rings
	gMgr.mu.Lock()
	gMgr.factor = factor
	if every > 0 { gMgr.every = every }
	if scorerCfg.MinScore > 0 { gMgr.scorer = New(scorerCfg) }
	gMgr.mu.Unlock()
}

// Ensure ring exists for a kind ("httpd"/"nginx") with B buckets.
// B is computed as longHorizon / every. We’ll approximate as 10× of 60s => 10 buckets if every==60s, etc.
func ensure(kind string, every time.Duration, buckets int) *ring {
	InitLongWindow(every, 10, DefaultConfig())
	gMgr.mu.Lock()
	defer gMgr.mu.Unlock()
	r := gMgr.rings[kind]
	if r == nil || len(r.slots) != buckets || r.every != every {
		r = newRing(every, buckets)
		gMgr.rings[kind] = r
	}
	return r
}

// IngestWindowSnapshot is called by the detector when it completes its short window.
// winSec is the detector window seconds (e.g., 60).
// snap maps host -> MiniMetrics (per-window averages); we scale back to counts.
func IngestWindowSnapshot(kind string, every time.Duration, longFactor int, winSec float64, snap map[string]MiniMetrics) {
	if longFactor <= 0 { longFactor = 10 }
	// We store longFactor buckets for each 1× detector window.
	// Example: detector window = 60s, longFactor=10 -> 10 buckets ≈ 10 minutes.
	buckets := longFactor
	r := ensure(strings.ToLower(kind), every, buckets)

	// Convert averages to approximate counts for this window (integers)
	conv := make(map[string]bucket, len(snap))
	for h, m := range snap {
		// Requests ≈ rps * winSec
		tot := int(m.RPSTotal * winSec + 0.5)
		c3  := int(m.R3xx     * winSec + 0.5)
		c4  := int(m.R4xx     * winSec + 0.5)
		c5  := int(m.R5xx     * winSec + 0.5)
		c401:= int(m.R401     * winSec + 0.5)
		c499:= int(m.R499     * winSec + 0.5)

		conv[h] = bucket{
			Tot: tot, C3: c3, C4: c4, C5: c5, C401: c401, C499: c499,
			Uniq:   m.UniqueIPs,
			RtSum:  m.ProcAvgSec * float64(max1(tot)), // approx
			ErrRatio:     m.ErrRatio,
			Auth401Ratio: m.Auth401Ratio,
			MedPerIP:     m.MedianPerIPRPS,
		}
	}
	r.advanceAndApply(conv)
}

// SuspiciousRow is the long-window version used by CLI/HTTP endpoints.
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
}

// SuspiciousTop over the long window (≈ factor × detector window).
func SuspiciousTop(kind string, minScore float64, limit int) []SuspiciousRow {
	InitLongWindow(0, 10, DefaultConfig()) // ensure gMgr exists
	gMgr.mu.RLock()
	r := gMgr.rings[strings.ToLower(kind)]
	sc := gMgr.scorer
	gMgr.mu.RUnlock()
	if r == nil || sc == nil { return nil }

	sums := r.sumAll()
	// Estimate rps over the long horizon: total counts / horizon seconds.
	horizonSec := float64(len(r.slots)) * r.every.Seconds()
	if horizonSec <= 0 { horizonSec = 1 }

	rows := make([]SuspiciousRow, 0, len(sums))
	for h, b := range sums {
		if b.Tot <= 0 { continue }
		rps   := float64(b.Tot) / horizonSec
		r3    := float64(b.C3)  / horizonSec
		r4    := float64(b.C4)  / horizonSec
		r5    := float64(b.C5)  / horizonSec
		// Use kept ratios for auth/errors; if missing, approximate
		errR  := b.ErrRatio
		if errR == 0 {
			errR = (float64(b.C5)+float64(b.C499)) / maxf(float64(b.Tot), 1)
		}
		sig := Signals{
			RPS:          rps,
			R3xx:         r3,
			R4xx:         r4,
			R5xx:         r5,
			ErrRatio:     errR,
			Auth401Ratio: b.Auth401Ratio,
			UniqueIPs:    b.Uniq,
			MedianPerIP:  b.MedPerIP,
		}
		res := sc.Score(sig)
		if res.Score >= maxf(minScore, 0.0001) {
			rows = append(rows, SuspiciousRow{
				Host: h, Score: res.Score, Reasons: res.Reasons,
				RPS: rps, R3xx: r3, R4xx: r4, R5xx: r5,
				UniqueIPs: b.Uniq, ErrRatio: errR, Auth401Ratio: b.Auth401Ratio,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score { return rows[i].RPS > rows[j].RPS }
		return rows[i].Score > rows[j].Score
	})
	if limit > 0 && len(rows) > limit { rows = rows[:limit] }
	return rows
}

func max1(x int) int { if x < 1 { return 1 }; return x }
func maxf(x, y float64) float64 { if x > y { return x }; return y }
