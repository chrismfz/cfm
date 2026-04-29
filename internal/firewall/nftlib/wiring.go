//go:build linux

// Wiring methods wire enrichment, reporting, and logging into the backend.
// All wiring is forwarded to the embedded cli backend so that delegated policy
// methods have access to the same enricher / reporter configuration.
package nftlib

import (
	"strings"

	enrichpkg "cfm/internal/enrich"
	"cfm/internal/reporting"
)

func (b *Backend) SetConfigDir(dir string) {
	b.cfgDir = strings.TrimSpace(dir)
	b.cli.SetConfigDir(dir)
}

// EnableEnrichment initialises the GeoIP/ASN enricher and caches the handle so
// GetEnricher() returns a valid enricher even for methods handled natively.
func (b *Backend) EnableEnrichment(dirs ...string) {
	b.cli.EnableEnrichment(dirs...)
	b.enr = b.cli.GetEnricher()
}

func (b *Backend) GetEnricher() *enrichpkg.Enricher {
	return b.cli.GetEnricher()
}

func (b *Backend) SetReporter(r reporting.Reporter) {
	b.reporter = r
	b.cli.SetReporter(r)
}

func (b *Backend) SetChallengeLogger(f func(format string, args ...any)) {
	b.challengeLogf = f
	b.cli.SetChallengeLogger(f)
}

// ReportBlock delegates to cli which owns the API reporting logic and config
// gates (DetectorsSend, AutoBlockSend, ManualBlockSend).
func (b *Backend) ReportBlock(ip, comment, source, mode string, ttlSeconds int) error {
	return b.cli.ReportBlock(ip, comment, source, mode, ttlSeconds)
}
