package sslcollector

import "time"

type Config struct {
	Enabled  bool
	CacheDir string

	// Cadence
	StatEvery      time.Duration // cheap stat loop on known files
	DiscoveryEvery time.Duration // full rescan fallback

	NegativeTTL  time.Duration
	MaxCertCache int

	// ReadOnly: a collector that never writes the daemon's on-disk state —
	// Refresh skips WriteSnapshot (dump.json, which the edge workers load)
	// and New does not create CacheDir. The one-shot `cfm ssl` CLI sets it:
	// run as root it used to rewrite the daemon's live snapshot from its own
	// process, outside the daemon's snapshot lock.
	ReadOnly bool
}
