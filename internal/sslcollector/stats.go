package sslcollector

import "time"

type Stats struct {
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
	// Collect unique Entry pointers (avoid double counting per-host)
	uniq := map[*Entry]struct{}{}
	for _, e := range c.exact {
		uniq[e] = struct{}{}
	}
	for _, e := range c.wildSuffix {
		uniq[e] = struct{}{}
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

	return Stats{
		ExactHosts:    exactN,
		WildcardZones: wildN,
		UniquePairs:   len(uniq),
		BySource:      bySrc,
		KnownFiles:    filesN,
		CachedTLS:     cacheN,
		GeneratedAt:   time.Now(),
	}
}
