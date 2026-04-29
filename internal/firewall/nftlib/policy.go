//go:build linux

// Policy and diagnostics methods delegate to the embedded nft.Backend.
// These methods generate complex nft rule expressions; native nftlib
// implementations will replace them in a later phase.
package nftlib

import (
	"cfm/internal/config"
)

func (b *Backend) ApplyFloodRules(c *config.Config) error {
	return b.cli.ApplyFloodRules(c)
}

func (b *Backend) ApplyHardeningRules(c *config.Config) error {
	return b.cli.ApplyHardeningRules(c)
}

func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) error {
	return b.cli.ApplyPortsPolicy(cfg)
}

func (b *Backend) ApplyConnlimit(rules []config.ConnlimitRule) error {
	return b.cli.ApplyConnlimit(rules)
}

func (b *Backend) ApplyPortFlood(rules []config.PortFloodRule) error {
	return b.cli.ApplyPortFlood(rules)
}

func (b *Backend) ApplySMTPBlock(cfg *config.SMTPBlockConfig) error {
	return b.cli.ApplySMTPBlock(cfg)
}

func (b *Backend) ApplyOutboundObserve(cfg *config.OutboundConfig) error {
	return b.cli.ApplyOutboundObserve(cfg)
}

func (b *Backend) DumpFloodCounters() {
	b.cli.DumpFloodCounters()
}

func (b *Backend) DumpThrottledIPs() {
	b.cli.DumpThrottledIPs()
}

func (b *Backend) LoadPortScanner() {
	b.cli.LoadPortScanner()
}
