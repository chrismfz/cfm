package webdetector

import (
	"time"

	"cfm/internal/logging"
)

// abuse_shadow_cost.go — Signal G: LOG-ONLY vhost-level origin cost pressure
// (docs/traffic-classifier.md, Phase 1). Where facet (Signal F) sees the
// request-shape CAUSE of a flood, Signal G sees its SYMPTOM: the origin buckling.
// The malicious flood's damage is the 256k×500 origin collapse — a vhost whose
// backend starts returning 5xx under load. This flags a vhost whose 5xx fraction
// is high under real request volume AND whose absolute 5xx rate clears a floor
// (so a tiny idle vhost with one 500 does not read as "under pressure").
//
// It reuses the per-bucket 5xx counters (c5xx/c500…/sumRT) the engine already
// maintains for every request, so there is NO ingest cost — only a cheap per-tick
// aggregation. Like the other shadow signals it NEVER challenges or blocks: it
// stamps a per-vhost `cost_pressure` badge (5xx percent) and writes one structured
// line per flagged vhost to the shared cfm.abuse_shadow.log. rtAvg is logged as a
// second cost dimension (a collapsing origin also slows down) but is not a gate.

// costShadowCfg is the resolved Signal-G threshold set (defaults applied).
type costShadowCfg struct {
	MinFrac float64 // 5xx/total must be ≥ this
	MinReq  int     // …with ≥ this many requests (kills tiny samples)
	MinRPS  float64 // …and ≥ this absolute 5xx rps (guards low-volume 5xx blips)
}

func (e *Engine) costShadowCfg() costShadowCfg {
	c := costShadowCfg{
		MinFrac: e.cfg.AbuseShadowCostMinFrac,
		MinReq:  e.cfg.AbuseShadowCostMinReq,
		MinRPS:  e.cfg.AbuseShadowCostMinRPS,
	}
	if c.MinFrac <= 0 {
		// 15% of responses being 5xx under load is real trouble, not noise; a
		// healthy origin sits near 0.
		c.MinFrac = 0.15
	}
	if c.MinReq <= 0 {
		c.MinReq = 50
	}
	if c.MinRPS <= 0 {
		c.MinRPS = 1.0
	}
	return c
}

// costOutlier is the Signal-G verdict for one vhost: enough requests, a high
// enough 5xx fraction, AND an absolute 5xx rate above the floor. Pure, so the
// floors can be unit-tested without an Engine.
func costOutlier(total, c5xx int, rps5xx float64, c costShadowCfg) bool {
	if total < c.MinReq || c5xx <= 0 {
		return false
	}
	if float64(c5xx)/float64(total) < c.MinFrac {
		return false
	}
	return rps5xx >= c.MinRPS
}

// emitAbuseShadowCostPressure runs Signal G in log-only mode over every vhost.
// Called from the per-tick emitIPChallenges after the facet pass. Snapshots the
// per-vhost 5xx aggregates under the read lock, then flags + badges after unlock.
func (e *Engine) emitAbuseShadowCostPressure(now time.Time) {
	if !e.cfg.AbuseShadow || !e.cfg.AbuseShadowCost {
		return
	}
	winSec := e.cfg.Window.Seconds()
	if winSec <= 0 {
		winSec = 60
	}
	cfg := e.costShadowCfg()

	type costAgg struct {
		total int
		c5xx  int
		sumRT float64
	}

	snap := make(map[string]*costAgg)
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		var a costAgg
		for i := range hs.buckets {
			b := &hs.buckets[i]
			a.total += b.total
			a.c5xx += b.c5xx
			a.sumRT += b.sumRT
		}
		if a.total > 0 && a.c5xx > 0 {
			cp := a
			snap[host] = &cp
		}
	}
	e.mu.RUnlock()

	if len(snap) == 0 {
		return
	}

	marks := make(map[string]int)
	for host, a := range snap {
		rps5xx := float64(a.c5xx) / winSec
		if !costOutlier(a.total, a.c5xx, rps5xx, cfg) {
			continue
		}
		// frac is 5xx over the vhost's WHOLE response mix — edge-served static/
		// cached 200s and 3xx/4xx included, matching the engine's existing ErrRatio
		// convention. It is well-defined (c5xx ≤ total, so frac ∈ [0,1]), but on a
		// cache-heavy vhost where the edge serves most requests and only a slice
		// reaches the origin, a FULL origin collapse can still sit under MinFrac and
		// not flag. That dilution is in the SAFE (false-negative) direction for a
		// log-only signal, but it means operators tuning MIN_FRAC from fleet logs
		// will see systematically low fractions on cached vhosts — and it must be
		// revisited (a dynamic-only denominator, at the cost of a per-bucket counter)
		// before this signal ever feeds enforcement. The absolute rps5xx floor is the
		// partial backstop: high raw 5xx volume still clears even when diluted.
		frac := float64(a.c5xx) / float64(a.total)
		// Badge value is the 5xx percent (1–100), never 0 for a flagged vhost
		// (MinFrac > 0), so 0 unambiguously means "not flagged" like the other
		// shadow badges. Round to nearest; floor at 1 so a sub-1% rounding can't
		// erase a genuine flag.
		pct := int(frac*100 + 0.5)
		if pct < 1 {
			pct = 1
		}
		marks[host] = pct

		// rt_avg is over ALL requests, not 5xx-only — like frac it is diluted by fast
		// static 200s, so treat it as a coarse whole-vhost latency hint, not an
		// origin-slowness proxy. Logged for correlation, never a gate.
		rtAvg := a.sumRT / float64(a.total)
		if !e.shouldLogVhostSuppress("abuseshadowcost:"+host, now) {
			continue
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=cost_pressure host=%s rps5xx=%.3f frac5xx=%.3f rt_avg=%.3f reqs=%d fails=%d verdict=would_shadow",
			host, rps5xx, frac, rtAvg, a.total, a.c5xx,
		)
	}

	if len(marks) > 0 {
		ttl := 3 * e.cfg.Window
		if ttl < 90*time.Second {
			ttl = 90 * time.Second
		}
		MarkCostShadowBulk(marks, ttl)
	}
}
