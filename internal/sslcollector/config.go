package sslcollector

import "time"

type Config struct {
	Enabled        bool
	CacheDir       string

	// Cadence
	StatEvery      time.Duration // cheap stat loop on known files
	DiscoveryEvery time.Duration // full rescan fallback

	NegativeTTL    time.Duration
	MaxCertCache   int
}
