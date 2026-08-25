package webdetector

import (
	"time"

	"cfm/internal/logging"
)

// abuse_shadow_facet.go — Signal F: LOG-ONLY vhost-level facet / query-cardinality
// expansion (docs/traffic-classifier.md, Phase 1). It exists to make visible the
// one shape PathDiversity is structurally blind to.
//
// PathDiversity = distinct BASE paths / total_req. The ingest strips the query
// string before counting paths, so a faceted-URL flood — few base paths, an
// enormous distinct-query fan-out (the e-athlos shape: ~805k `?filter_category=…`
// URLs riding on 2 base paths) — collapses to unique_paths≈2 and reads as the
// most benign vhost on the board. Signal F counts distinct FULL URLs (path+query,
// via bucket.fullURIs) and flags a vhost whose distinct-URL count is large AND
// dwarfs its distinct base-path count. That ratio (facet expansion) is the
// discriminator: a normal busy shop grows distinct URLs and distinct paths
// together (each product is its own path → expansion ≈ 1–3), while a facet flood
// pins base paths near-constant and sprays queries (expansion in the hundreds→
// thousands).
//
// Like Signal C this NEVER challenges or blocks. It stamps a per-vhost badge
// (abuse_shadow_facet_marks.go) for webtop/API/CLI visibility and writes one
// structured line per flagged vhost per throttle window to the existing
// cfm.abuse_shadow.log (no new log file → no logrotate change), so the thresholds
// can be tuned from real fleet data before any promotion to enforcement.

// facetURICapDefault bounds the per-bucket distinct-full-URL set when
// ABUSE_SHADOW_FACET_CAP is unset. A facet flood only needs to prove "very many
// distinct URLs on very few paths"; once the set is this large per bucket the
// signal is already unambiguous, so capping here bounds memory without weakening
// the verdict (the union across buckets can still exceed it).
const facetURICapDefault = 3000

// facetShadowCfg is the resolved Signal-F threshold set (defaults applied).
type facetShadowCfg struct {
	MinURLs      int     // distinct full URLs must be ≥ this (guards small/idle vhosts)
	MinExpansion float64 // …and distinctURLs / distinctPaths must be ≥ this
}

func (e *Engine) facetShadowCfg() facetShadowCfg {
	c := facetShadowCfg{
		MinURLs:      e.cfg.AbuseShadowFacetMinURLs,
		MinExpansion: e.cfg.AbuseShadowFacetMinExpansion,
	}
	if c.MinURLs <= 0 {
		// ~an order of magnitude above a busy legit page's dynamic-URL spread in
		// one window; a real facet crawl clears this in seconds.
		c.MinURLs = 300
	}
	if c.MinExpansion <= 0 {
		// A legit shop's distinct URLs track its distinct paths (expansion ≈ 1–3);
		// 20× separates "many varied pages" from "few pages, exploding queries".
		c.MinExpansion = 20
	}
	return c
}

// facetOutlier is the Signal-F verdict for one vhost: enough distinct full URLs
// AND a distinct-URL/distinct-path ratio (facet expansion) high enough that the
// query dimension — invisible to PathDiversity — dominates. Pure, so the floors
// can be unit-tested without standing up an Engine.
func facetOutlier(distinctURLs, distinctPaths int, c facetShadowCfg) bool {
	if distinctURLs < c.MinURLs || distinctPaths <= 0 {
		return false
	}
	return float64(distinctURLs)/float64(distinctPaths) >= c.MinExpansion
}

// emitAbuseShadowFacetOutliers runs Signal F in log-only mode over every vhost.
// Called from the per-tick emitIPChallenges after the rate-outlier pass. It
// snapshots per-vhost distinct full URLs (union of bucket.fullURIs), distinct
// base paths (union of bucket.paths keys) and totals under the read lock, then
// flags and badges any vhost that clears both floors.
func (e *Engine) emitAbuseShadowFacetOutliers(now time.Time) {
	if !e.cfg.AbuseShadow || !e.cfg.AbuseShadowFacet {
		return
	}
	cfg := e.facetShadowCfg()

	type facetAgg struct {
		urls  map[uint64]struct{}
		paths map[string]struct{}
		total int
	}

	// Snapshot under the read lock; do the (lock-free) verdict + logging after.
	snap := make(map[string]*facetAgg)
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		var seenFacet bool
		for i := range hs.buckets {
			if len(hs.buckets[i].fullURIs) > 0 {
				seenFacet = true
				break
			}
		}
		if !seenFacet {
			continue // vhost carries no facet data this window — skip allocation
		}
		a := &facetAgg{urls: make(map[uint64]struct{}), paths: make(map[string]struct{})}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			a.total += b.total
			for h := range b.fullURIs {
				a.urls[h] = struct{}{}
			}
			for p := range b.paths {
				a.paths[p] = struct{}{}
			}
		}
		snap[host] = a
	}
	e.mu.RUnlock()

	if len(snap) == 0 {
		return
	}

	marks := make(map[string]int)
	for host, a := range snap {
		distinctURLs := len(a.urls)
		distinctPaths := len(a.paths)
		if !facetOutlier(distinctURLs, distinctPaths, cfg) {
			continue
		}
		expansion := float64(distinctURLs) / float64(distinctPaths)
		// A vhost-level signal has nothing per-IP to bypass here (per-IP leniency /
		// good-bot exemption is Signal C's job); record the cardinality for the badge.
		marks[host] = distinctURLs

		// urlRepeatRatio ≈ 1.0 means each distinct URL was hit ~once (enumeration /
		// crawl), which is the facet-flood shape; a cache/refresh workload re-serves
		// URLs and sits well above 1. Logged as corroboration, not a gate.
		repeat := 0.0
		if distinctURLs > 0 {
			repeat = float64(a.total) / float64(distinctURLs)
		}
		if !e.shouldLogVhostSuppress("abuseshadowfacet:"+host, now) {
			continue
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=facet_expansion host=%s urls=%d paths=%d expansion=%.1f repeat=%.2f reqs=%d verdict=would_shadow",
			host, distinctURLs, distinctPaths, expansion, repeat, a.total,
		)
	}

	// Stamp the per-vhost distinct-URL count for the badge / API field in one batch
	// (single prune pass). TTL mirrors the rate-outlier mark: a small multiple of
	// the window, floored at 90s, so it survives eval jitter and clears on its own
	// within one TTL once the flood stops (no un-mark path to get wrong).
	if len(marks) > 0 {
		ttl := 3 * e.cfg.Window
		if ttl < 90*time.Second {
			ttl = 90 * time.Second
		}
		MarkFacetShadowBulk(marks, ttl)
	}
}
