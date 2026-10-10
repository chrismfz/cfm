package sslcollector

import (
    "crypto/sha256"
    "encoding/hex"
    "sort"
    "time"
)

type Stats struct {
	Version      string
	ExactHosts    int
	WildcardZones int

	UniquePairs int              // unique (certPath+keyPath) pairs
	BySource    map[Source]int   // counts unique pairs by source

	KnownFiles int
	CachedTLS  int

	GeneratedAt time.Time
}

func (c *Collector) Stats() Stats {
	// Snapshot sizes
	c.mu.RLock()
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
	c.mu.RUnlock()

	bySrc := map[Source]int{}
	for e := range uniq {
		bySrc[e.Source]++
	}

	c.filesMu.RLock()
	filesN := len(c.knownFiles)
	c.filesMu.RUnlock()

	c.cacheMu.Lock()
	cacheN := len(c.certCache)
	c.cacheMu.Unlock()

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
    ver := hex.EncodeToString(h.Sum(nil))

	return Stats{
		Version:      ver,
		ExactHosts:    exactN,
		WildcardZones: wildN,
		UniquePairs:   len(uniq),
		BySource:      bySrc,
		KnownFiles:    filesN,
		CachedTLS:     cacheN,
		GeneratedAt:   time.Now(),
	}
}
