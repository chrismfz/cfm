//go:build linux

// Wiring methods wire enrichment, reporting, and logging into the backend.
// All wiring is forwarded to the embedded cli backend so that delegated policy
// methods have access to the same enricher / reporter configuration.
package nftlib

import (
	"os"
	"path/filepath"
	"strings"

	cfgpkg "cfm/internal/config"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/firewall"
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

func (b *Backend) ReportBlock(ip, comment, source, mode string, ttlSeconds int) error {
	if b == nil || b.reporter == nil {
		return nil
	}
	cfg := b.loadConfig()
	if !firewall.ShouldReportBlock(cfg, source) {
		return nil
	}
	return b.reporter.ReportBlock(ip, comment, source, mode, ttlSeconds)
}

func (b *Backend) loadConfig() *cfgpkg.Config {
	dir := strings.TrimSpace(b.cfgDir)
	if dir == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, "cfm.conf")) // #nosec G304
	if err != nil {
		return nil
	}
	defer f.Close()
	cfg, err := cfgpkg.ParseCFMConf(f)
	if err != nil {
		return nil
	}
	return cfg
}
