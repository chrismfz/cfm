//go:build linux

package nftlib

import (
	"fmt"
	"strings"

	"cfm/internal/config"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (b *Backend) ApplyFloodRules(c *config.Config) error {
	if err := b.EnsureBase(); err != nil { return err }
	if err := b.flushChain("flood"); err != nil { return err }
	if err := b.ApplyHardeningRules(c); err != nil { return err }
	if err := b.ApplyConnlimit(c.Connlimit.Rules); err != nil { return err }
	if err := b.ApplyPortFlood(c.PortFlood.Rules); err != nil { return err }
	return nil
}

func (b *Backend) ApplyHardeningRules(c *config.Config) error {
	if c == nil { return nil }
	if c.Hardening.BlockBadTCPFlags {
		for range []int{0,1,2,3} {
			if err := b.appendVerdictRule("flood", expr.VerdictDrop); err != nil { return err }
		}
	}
	return nil
}

func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) error {
	if cfg == nil { return nil }
	if err := b.ensureChain("output"); err != nil { return err }
	if err := b.flushChain("input"); err != nil { return err }
	if err := b.flushChain("output"); err != nil { return err }
	for _, pr := range cfg.TCPIn { _ = pr; if err := b.appendVerdictRule("input", expr.VerdictAccept); err != nil { return err } }
	for _, pr := range cfg.UDPIn { _ = pr; if err := b.appendVerdictRule("input", expr.VerdictAccept); err != nil { return err } }
	for _, pr := range cfg.TCPOut { _ = pr; if err := b.appendVerdictRule("output", expr.VerdictAccept); err != nil { return err } }
	for _, pr := range cfg.UDPOut { _ = pr; if err := b.appendVerdictRule("output", expr.VerdictAccept); err != nil { return err } }
	return nil
}

func (b *Backend) ApplyConnlimit(rules []config.ConnlimitRule) error {
	for _, r := range rules {
		if strings.ToLower(r.Proto) != "tcp" && strings.ToLower(r.Proto) != "udp" {
			return fmt.Errorf("unknown proto %q in CONNLIMIT", r.Proto)
		}
		if err := b.appendVerdictRule("flood", expr.VerdictDrop); err != nil { return err }
	}
	return nil
}

func (b *Backend) ApplyPortFlood(rules []config.PortFloodRule) error {
	for range rules {
		if err := b.appendVerdictRule("flood", expr.VerdictDrop); err != nil { return err }
	}
	return nil
}

func (b *Backend) ApplySMTPBlock(cfg *config.SMTPBlockConfig) error {
	if cfg == nil || !cfg.Enabled { return nil }
	if err := b.ensureChain("smtpblock"); err != nil { return err }
	if err := b.flushChain("smtpblock"); err != nil { return err }
	return b.appendVerdictRule("smtpblock", expr.VerdictDrop)
}

func (b *Backend) ApplyOutboundObserve(cfg *config.OutboundConfig) error {
	if cfg == nil || !cfg.Enabled || cfg.NFLOGGroup <= 0 { return nil }
	if err := b.ensureChain("cfm_outbound_observe"); err != nil { return err }
	if err := b.flushChain("cfm_outbound_observe"); err != nil { return err }
	return b.appendVerdictRule("cfm_outbound_observe", expr.VerdictAccept)
}

func (b *Backend) appendVerdictRule(chain string, kind expr.VerdictKind) error {
	ch, err := b.getChain(chain)
	if err != nil { return err }
	b.conn.AddRule(&nftables.Rule{Table: ch.Table, Chain: ch, Exprs: []expr.Any{&expr.Verdict{Kind: kind}}})
	return b.conn.Flush()
}

func (b *Backend) getChain(name string) (*nftables.Chain, error) {
	t := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	chains, err := b.conn.ListChains()
	if err != nil { return nil, err }
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == t.Name && c.Table.Family == t.Family && c.Name == name { return c, nil }
	}
	return nil, fmt.Errorf("chain %s not found", name)
}

func (b *Backend) ensureChain(name string) error {
	t := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.conn.AddChain(&nftables.Chain{Table: t, Name: name})
	if err := b.conn.Flush(); err != nil && !isAlreadyExists(err) { return err }
	return nil
}

func (b *Backend) flushChain(name string) error {
	ch, err := b.getChain(name)
	if err != nil { return err }
	b.conn.FlushChain(ch)
	return b.conn.Flush()
}

func (b *Backend) DumpFloodCounters() { b.cli.DumpFloodCounters() }
func (b *Backend) DumpThrottledIPs() { b.cli.DumpThrottledIPs() }
func (b *Backend) LoadPortScanner() { b.cli.LoadPortScanner() }
