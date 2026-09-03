package webdetector

import (
	"math"
	"sort"
	"sync"
	"time"
)

// vhost_baseline.go — a rolling ROBUST baseline for scalar per-(vhost, feature)
// values, and the modified robust-z of a value against it.
//
// This is the Track-1 fusion substrate (docs/traffic-classifier.md → "Track-1
// shadow fusion"). The Class-2 abuse we chase is DISTRIBUTIONAL: a vhost's own
// feature (facet cardinality, 5xx fraction, unverified-datacenter fraction, …)
// suddenly departs from ITS OWN recent history. So we score each feature by how
// far the current value sits from the vhost's own baseline, using a robust
// estimator — median + MAD — because the very spike we want to detect is the
// outlier, and a robust estimator (unlike mean/σ) is not dragged by it: a
// minority of spike samples barely moves the median or the MAD.
//
// Design notes:
//   - The "baseline" is literally a fixed-size recency window (a ring) of the
//     last Window observations per (host, feature). Old data ages out by
//     eviction — no decay math, no half-life (contrast fpBaseline, which is an
//     EWMA categorical histogram and is NOT reused here; see the doc correction).
//   - Feature-agnostic: the caller names features (strings) and passes a
//     per-feature madFloor at query time, so one primitive serves values on
//     wildly different scales (dc% 0–100, frac5xx 0–1, cardinality 0–10000).
//   - PURE and UNWIRED: this file adds no behaviour. The caller (Track-1 PR-2)
//     decides WHEN to Observe — e.g. it should NOT Observe while a vhost is
//     armed/under-attack, so an active attack never folds into its own baseline.
//   - RobustZ never includes the queried value in the window it deviates
//     against; Observe is a separate call. Typical per-tick use is:
//     z := b.RobustZ(host, feat, cur, floor); if !armed { b.Observe(host, feat, cur, now) }.
//
// Thread-safe: one mutex guards the whole store. The store is meant to live as a
// package-level singleton like the abuse_shadow mark stores; median/MAD over a
// ~60-sample window is a couple of tiny sorts, negligible under the mutex.

// robustZScale is the 0.6745 constant (Φ⁻¹(0.75)) of the modified z-score, which
// makes MAD a consistent estimator of the standard deviation for normal data.
const robustZScale = 0.6745

// vhostBaselineConfig tunes the store. Non-positive fields fall back to defaults
// in newVhostBaseline.
type vhostBaselineConfig struct {
	Window     int // ring size per (host,feature); effective time span = Window × caller tick
	MinSamples int // below this many stored samples, RobustZ returns 0 (cold start)
	MaxHosts   int // hard cap on tracked hosts (least-recently-seen evicted); 0 = unlimited (rely on Prune)
}

// featureRing is a fixed-size recency window of scalar samples for one
// (host, feature) — the vhost's own history a current value deviates against.
type featureRing struct {
	buf  []float64
	head int
	n    int // number of valid samples (≤ len(buf))
}

func (r *featureRing) push(v float64) {
	r.buf[r.head] = v
	r.head = (r.head + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
}

// appendSamples appends the valid samples to dst (order irrelevant — callers
// sort). While the ring is unfilled the valid entries are buf[0:n] (head has not
// wrapped); once filled n == len(buf) and every slot is valid.
func (r *featureRing) appendSamples(dst []float64) []float64 {
	for i := 0; i < r.n; i++ {
		dst = append(dst, r.buf[i])
	}
	return dst
}

type hostBaseline struct {
	// feats grows one entry per distinct feature name and is NOT capped (MaxHosts
	// bounds hosts, not features-per-host). Safe only because feature names are a
	// fixed, small, INTERNAL set (facet/cost/dc/uniqIP …); never key a feature name
	// on request- or attacker-controlled data or this becomes unbounded.
	feats    map[string]*featureRing
	lastSeen time.Time
}

type vhostBaseline struct {
	mu       sync.Mutex
	cfg      vhostBaselineConfig
	hosts    map[string]*hostBaseline
	scratch  []float64 // reused sample buffer (guarded by mu)
	scratch2 []float64 // reused deviation buffer (guarded by mu)
}

func newVhostBaseline(cfg vhostBaselineConfig) *vhostBaseline {
	if cfg.Window <= 0 {
		cfg.Window = 60
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = 8
	}
	if cfg.MinSamples > cfg.Window {
		cfg.MinSamples = cfg.Window
	}
	if cfg.MaxHosts < 0 {
		cfg.MaxHosts = 0
	}
	return &vhostBaseline{cfg: cfg, hosts: make(map[string]*hostBaseline)}
}

// Observe folds one sample of feature for host into its rolling window and marks
// the host seen at now. The caller decides when NOT to call this (e.g. while the
// vhost is armed) so an attack does not poison its own baseline.
func (b *vhostBaseline) Observe(host, feature string, v float64, now time.Time) {
	// Never store a non-finite sample: a caller computing e.g. a 5xx fraction as
	// 0/0 on a zero-request tick would otherwise poison median/MAD with NaN for a
	// whole window (NaN ≤ 0 is false, so it would slip past RobustZ's scale guard).
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	hb := b.hosts[host]
	if hb == nil {
		if b.cfg.MaxHosts > 0 && len(b.hosts) >= b.cfg.MaxHosts {
			b.evictLRULocked()
		}
		hb = &hostBaseline{feats: make(map[string]*featureRing)}
		b.hosts[host] = hb
	}
	hb.lastSeen = now
	r := hb.feats[feature]
	if r == nil {
		r = &featureRing{buf: make([]float64, b.cfg.Window)}
		hb.feats[feature] = r
	}
	r.push(v)
}

// RobustZ returns the modified robust-z of x against host's own stored window for
// feature — 0.6745·(x − median)/max(MAD, madFloor) — and the sample count n it
// was computed over. It returns (0, n) when the window is below MinSamples
// (cold start) and (0, 0) when the (host,feature) is unknown. The sign is kept
// (negative = below baseline); callers that only care about upward spikes clamp
// at 0. madFloor is the caller's per-feature minimum scale: it both prevents a
// divide-by-zero on a flat/quiet baseline (MAD = 0) and bounds how large z can
// grow, so it must be set to the smallest deviation that is meaningful for that
// feature.
func (b *vhostBaseline) RobustZ(host, feature string, x, madFloor float64) (z float64, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	hb := b.hosts[host]
	if hb == nil {
		return 0, 0
	}
	r := hb.feats[feature]
	if r == nil {
		return 0, 0
	}
	if r.n < b.cfg.MinSamples {
		return 0, r.n
	}
	// Stored samples are always finite (Observe drops non-finite), so only x can
	// carry a NaN/Inf in here — guard it so we never hand a non-finite z upward.
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 0, r.n
	}

	b.scratch = r.appendSamples(b.scratch[:0])
	s := b.scratch
	sort.Float64s(s)
	med := medianSorted(s)

	b.scratch2 = b.scratch2[:0]
	for _, v := range s {
		b.scratch2 = append(b.scratch2, math.Abs(v-med))
	}
	sort.Float64s(b.scratch2)
	mad := medianSorted(b.scratch2)

	scale := math.Max(mad, madFloor)
	if scale <= 0 {
		return 0, r.n
	}
	return robustZScale * (x - med) / scale, r.n
}

// Prune drops every host not Observed since `before` and returns how many were
// removed. The caller runs it periodically (the store has no timer of its own).
func (b *vhostBaseline) Prune(before time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	removed := 0
	for h, hb := range b.hosts {
		if hb.lastSeen.Before(before) {
			delete(b.hosts, h)
			removed++
		}
	}
	return removed
}

// evictLRULocked removes the least-recently-seen host. Caller holds b.mu. Runs
// only when MaxHosts is exceeded, so the O(hosts) scan is rare.
func (b *vhostBaseline) evictLRULocked() {
	var oldestHost string
	var oldest time.Time
	first := true
	for h, hb := range b.hosts {
		if first || hb.lastSeen.Before(oldest) {
			oldest, oldestHost, first = hb.lastSeen, h, false
		}
	}
	if !first {
		delete(b.hosts, oldestHost)
	}
}

// hostCount reports how many hosts are tracked (for metrics/tests).
func (b *vhostBaseline) hostCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.hosts)
}

// medianSorted returns the median of an already-sorted slice (0 for empty).
func medianSorted(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return 0.5 * (sorted[n/2-1] + sorted[n/2])
}
