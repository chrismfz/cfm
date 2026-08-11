//go:build linux

// Wiring methods wire enrichment, reporting, and logging into the backend.
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
}

func (b *Backend) EnableEnrichment(dirs ...string) {
	if b.enr != nil {
		return
	}
	if e, _ := enrichpkg.New(dirs...); e != nil {
		b.enr = e
	}
}

func (b *Backend) GetEnricher() *enrichpkg.Enricher {
	return b.enr
}

func (b *Backend) SetReporter(r reporting.Reporter) {
	b.reporter = r
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

// ReportLenient forwards a lenient (per-server) block record. It honours the
// same global per-source report switches as ReportBlock — a server with API
// reporting disabled stays silent on both paths; the lenient vs blacklist
// choice only affects which list the record lands on once reporting is on.
func (b *Backend) ReportLenient(ip, comment, source, mode string, ttlSeconds int) error {
	if b == nil || b.reporter == nil {
		return nil
	}
	cfg := b.loadConfig()
	if !firewall.ShouldReportBlock(cfg, source) {
		return nil
	}
	return b.reporter.ReportLenient(ip, comment, source, mode, ttlSeconds)
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
