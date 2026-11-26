package sslcollector

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"time"
)

type Stats struct {
	Version       string
	ExactHosts    int
	WildcardZones int

	UniquePairs int            // unique (certPath+keyPath) pairs
	BySource    map[Source]int // counts unique pairs by source

	KnownFiles int
	CachedTLS  int

	GeneratedAt time.Time
}

// statsCache is the part of Stats computed from exact and wildSuffix, and
// the two maps it was computed from (held, so neither can be freed and its
// address reused while the cache names it; a scan drops the cache when it
// replaces them, forgetStats, so the old index is not kept alive).
type statsCache struct {
	exact, wild map[string]*Entry
	exactN      int
	wildN       int
	ver         string
	pairs       int
	bySrc       map[Source]int
}

// fresh reports whether the cache was computed from these maps.
func (sc *statsCache) fresh(exact, wild map[string]*Entry) bool {
	return sc.exact != nil && sameMap(sc.exact, exact) && sameMap(sc.wild, wild) &&
		sc.exactN == len(exact) && sc.wildN == len(wild)
}

func sameMap(a, b map[string]*Entry) bool {
	return reflect.ValueOf(a).UnsafePointer() == reflect.ValueOf(b).UnsafePointer()
}

// forgetStats drops the cached version and the maps it holds.
func (c *Collector) forgetStats() {
	c.statsMu.Lock()
	c.statsCache = statsCache{}
	c.statsMu.Unlock()
}

// Stats reports the collector's sizes and its version. The edge polls it
// (/stats) to see a renewal, and the version hashes every host and pair: on
// a node with thousands of certificates that hash, per poll, was ~10 % of
// the daemon's CPU (earth, virgo, 2026-11-25). It is computed once per scan
// now (a scan replaces the maps) and reused until the next.
func (c *Collector) Stats() Stats {
	c.mu.RLock()
	exact, wild := c.exact, c.wildSuffix
	c.mu.RUnlock()

	c.statsMu.Lock()
	if !c.statsCache.fresh(exact, wild) {
		c.mu.RLock()
		c.statsCache = c.computeStats()
		c.mu.RUnlock()
	}
	sc := c.statsCache
	c.statsMu.Unlock()

	bySrc := make(map[Source]int, len(sc.bySrc))
	for k, v := range sc.bySrc {
		bySrc[k] = v
	}

	c.filesMu.RLock()
	filesN := len(c.knownFiles)
	c.filesMu.RUnlock()

	c.cacheMu.Lock()
	cacheN := len(c.certCache)
	c.cacheMu.Unlock()

	return Stats{
		Version:       sc.ver,
		ExactHosts:    sc.exactN,
		WildcardZones: sc.wildN,
		UniquePairs:   sc.pairs,
		BySource:      bySrc,
		KnownFiles:    filesN,
		CachedTLS:     cacheN,
		GeneratedAt:   time.Now(),
	}
}

// computeStats hashes exact and wildSuffix (c.mu held for reading).
func (c *Collector) computeStats() statsCache {
	exactN := len(c.exact)
	wildN := len(c.wildSuffix)
	// Collect unique Entry pointers (avoid double counting per-host), and
	// which entry serves each name: betterEntry ranks by validity at the
	// scan time, so a name can move to another (already known) pair as one
	// expires with no pair changing — the version must move too, or the
	// workers and the snapshot (WriteSnapshot skips an unchanged version)
	// keep the old mapping.
	uniq := map[*Entry]struct{}{}
	names := make([]string, 0, exactN+wildN)
	for h, e := range c.exact {
		uniq[e] = struct{}{}
		names = append(names, "e|"+h+"|"+e.Fingerprint)
	}
	for suf, e := range c.wildSuffix {
		uniq[e] = struct{}{}
		names = append(names, "w|"+suf+"|"+e.Fingerprint)
	}

	bySrc := map[Source]int{}
	for e := range uniq {
		bySrc[e.Source]++
	}

	// Build a deterministic "version" hash over unique entries
	// (fingerprint + mtimes) so OpenResty can detect renewals/changes.
	//
	// ChainMTime is folded in (zero when ChainPath is empty) so a
	// chain-only rotation — eg DA rewrites <domain>.cacert during a
	// Let's Encrypt intermediate transition without touching the leaf
	// or key — produces a new version and wakes the lua workers.
	// Without this, chain-only changes would only be picked up by
	// FORCE_DUMPALL_AFTER (1h), serving the stale chain in between.
	keys := make([]string, 0, len(uniq))
	for e := range uniq {
		keys = append(keys,
			e.Fingerprint+"|"+
				e.CertMTime.UTC().Format(time.RFC3339Nano)+"|"+
				e.KeyMTime.UTC().Format(time.RFC3339Nano)+"|"+
				e.ChainMTime.UTC().Format(time.RFC3339Nano))
	}
	sort.Strings(keys)
	sort.Strings(names)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'\n'})
	}
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{'\n'})
	}
	return statsCache{
		exact: c.exact, wild: c.wildSuffix,
		exactN: exactN, wildN: wildN,
		ver:   hex.EncodeToString(h.Sum(nil)),
		pairs: len(uniq),
		bySrc: bySrc,
	}
}
