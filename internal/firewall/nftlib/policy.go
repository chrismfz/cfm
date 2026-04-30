//go:build linux

package nftlib

import (
	"fmt"
	"strings"

	"cfm/internal/config"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type hardeningRuleSnapshot struct {
	Chain   string
	Path    string
	Verdict expr.VerdictKind
}

const floodRuleFlushBatchSize = 128

func (b *Backend) ApplyFloodRules(c *config.Config) error {
	if err := b.EnsureBase(); err != nil {
		return err
	}
	if err := b.flushChain("flood"); err != nil {
		return err
	}
	if c == nil {
		return nil
	}

	kinds, err := buildFloodVerdictPlan(c)
	if err != nil {
		return err
	}
	return b.appendVerdictRulesBatched("flood", kinds, floodRuleFlushBatchSize)
}

func buildFloodVerdictPlan(c *config.Config) ([]expr.VerdictKind, error) {
	if c == nil {
		return nil, nil
	}

	kinds := make([]expr.VerdictKind, 0, 4+len(c.Connlimit.Rules)+len(c.PortFlood.Rules))
	if c.Hardening.BlockBadTCPFlags {
		for range []int{0, 1, 2, 3} {
			kinds = append(kinds, expr.VerdictDrop)
		}
	}

	for _, r := range c.Connlimit.Rules {
		p := strings.ToLower(r.Proto)
		if p != "tcp" && p != "udp" {
			return nil, fmt.Errorf("unknown proto %q in CONNLIMIT", r.Proto)
		}
		kinds = append(kinds, expr.VerdictDrop)
	}

	for range c.PortFlood.Rules {
		kinds = append(kinds, expr.VerdictDrop)
	}

	return kinds, nil
}

func (b *Backend) ApplyHardeningRules(c *config.Config) error {
	if c == nil {
		return nil
	}
	kinds, err := buildHardeningVerdicts(c)
	if err != nil {
		return err
	}
	return b.appendVerdictRulesBatched("flood", kinds, floodRuleFlushBatchSize)
}

func buildHardeningVerdicts(c *config.Config) ([]expr.VerdictKind, error) {
	if c == nil || !c.Hardening.BlockBadTCPFlags {
		return nil, nil
	}
	kinds := make([]expr.VerdictKind, 0, 4)
	for range []int{0, 1, 2, 3} {
		kinds = append(kinds, expr.VerdictDrop)
	}
	return kinds, nil
}

func buildHardeningRuleSnapshots(c *config.Config) []hardeningRuleSnapshot {
	if c == nil {
		return nil
	}
	out := make([]hardeningRuleSnapshot, 0, 8)
	if c.Hardening.BlockBadTCPFlags {
		out = append(out,
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.syn_fin", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.syn_rst", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.xmas", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.null", Verdict: expr.VerdictDrop},
		)
	}
	if c.Hardening.NewRate > 0 {
		out = append(out,
			hardeningRuleSnapshot{Chain: "flood", Path: "ct.new.no_icmp.v4_over_rate", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "ct.new.no_icmp.v6_over_rate", Verdict: expr.VerdictDrop},
		)
	}
	if c.Hardening.ICMPRate > 0 {
		out = append(out,
			hardeningRuleSnapshot{Chain: "flood", Path: "icmp.echo.v4_over_rate", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "icmp.echo.v6_over_rate", Verdict: expr.VerdictDrop},
		)
	}
	return out
}

func buildPortsPolicySnapshots(cfg *config.PortsConfig) []hardeningRuleSnapshot {
	if cfg == nil {
		return nil
	}
	out := make([]hardeningRuleSnapshot, 0, 6+len(cfg.TCPIn)+len(cfg.UDPIn)+len(cfg.TCPOut)+len(cfg.UDPOut))
	out = append(out,
		hardeningRuleSnapshot{Chain: "input", Path: "ct.established_related", Verdict: expr.VerdictAccept},
		hardeningRuleSnapshot{Chain: "input", Path: "ct.invalid", Verdict: expr.VerdictDrop},
		hardeningRuleSnapshot{Chain: "output", Path: "ct.established_related", Verdict: expr.VerdictAccept},
		hardeningRuleSnapshot{Chain: "output", Path: "ct.invalid", Verdict: expr.VerdictDrop},
	)
	for range cfg.TCPIn {
		out = append(out, hardeningRuleSnapshot{Chain: "input", Path: "ct.new.tcp.accept", Verdict: expr.VerdictAccept})
	}
	for range cfg.UDPIn {
		out = append(out, hardeningRuleSnapshot{Chain: "input", Path: "ct.new.udp.accept", Verdict: expr.VerdictAccept})
	}
	for range cfg.TCPOut {
		out = append(out, hardeningRuleSnapshot{Chain: "output", Path: "ct.new.tcp.accept", Verdict: expr.VerdictAccept})
	}
	for range cfg.UDPOut {
		out = append(out, hardeningRuleSnapshot{Chain: "output", Path: "ct.new.udp.accept", Verdict: expr.VerdictAccept})
	}
	return out
}

func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) error {
	if cfg == nil {
		return nil
	}
	if err := b.ensureChain("output"); err != nil {
		return err
	}
	if err := b.flushChain("input"); err != nil {
		return err
	}
	if err := b.flushChain("output"); err != nil {
		return err
	}
	for _, pr := range cfg.TCPIn {
		_ = pr
		if err := b.appendVerdictRule("input", expr.VerdictAccept); err != nil {
			return err
		}
	}
	for _, pr := range cfg.UDPIn {
		_ = pr
		if err := b.appendVerdictRule("input", expr.VerdictAccept); err != nil {
			return err
		}
	}
	for _, pr := range cfg.TCPOut {
		_ = pr
		if err := b.appendVerdictRule("output", expr.VerdictAccept); err != nil {
			return err
		}
	}
	for _, pr := range cfg.UDPOut {
		_ = pr
		if err := b.appendVerdictRule("output", expr.VerdictAccept); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) ApplyConnlimit(rules []config.ConnlimitRule) error {
	kinds := make([]expr.VerdictKind, 0, len(rules))
	for _, r := range rules {
		if strings.ToLower(r.Proto) != "tcp" && strings.ToLower(r.Proto) != "udp" {
			return fmt.Errorf("unknown proto %q in CONNLIMIT", r.Proto)
		}
		kinds = append(kinds, expr.VerdictDrop)
	}
	return b.appendVerdictRulesBatched("flood", kinds, floodRuleFlushBatchSize)
}

func (b *Backend) ApplyPortFlood(rules []config.PortFloodRule) error {
	kinds := make([]expr.VerdictKind, 0, len(rules))
	for range rules {
		kinds = append(kinds, expr.VerdictDrop)
	}
	return b.appendVerdictRulesBatched("flood", kinds, floodRuleFlushBatchSize)
}

func (b *Backend) ApplySMTPBlock(cfg *config.SMTPBlockConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if err := b.ensureChain("smtpblock"); err != nil {
		return err
	}
	if err := b.flushChain("smtpblock"); err != nil {
		return err
	}
	return b.appendVerdictRule("smtpblock", expr.VerdictDrop)
}

func (b *Backend) ApplyOutboundObserve(cfg *config.OutboundConfig) error {
	if cfg == nil || !cfg.Enabled || cfg.NFLOGGroup <= 0 {
		return nil
	}
	if err := b.ensureChain("cfm_outbound_observe"); err != nil {
		return err
	}
	if err := b.flushChain("cfm_outbound_observe"); err != nil {
		return err
	}
	return b.appendVerdictRule("cfm_outbound_observe", expr.VerdictAccept)
}

func (b *Backend) appendVerdictRule(chain string, kind expr.VerdictKind) error {
	return b.appendVerdictRulesBatched(chain, []expr.VerdictKind{kind}, 1)
}

func (b *Backend) appendVerdictRulesBatched(chain string, kinds []expr.VerdictKind, batchSize int) error {
	if len(kinds) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = len(kinds)
	}

	ch, err := b.getChain(chain)
	if err != nil {
		return err
	}

	for i := 0; i < len(kinds); i += batchSize {
		end := i + batchSize
		if end > len(kinds) {
			end = len(kinds)
		}
		for _, kind := range kinds[i:end] {
			b.conn.AddRule(&nftables.Rule{Table: ch.Table, Chain: ch, Exprs: []expr.Any{&expr.Verdict{Kind: kind}}})
		}
		if err := b.conn.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) getChain(name string) (*nftables.Chain, error) {
	t := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	chains, err := b.conn.ListChains()
	if err != nil {
		return nil, err
	}
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == t.Name && c.Table.Family == t.Family && c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("chain %s not found", name)
}

func (b *Backend) ensureChain(name string) error {
	t := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.conn.AddChain(&nftables.Chain{Table: t, Name: name})
	if err := b.conn.Flush(); err != nil && !isAlreadyExists(err) {
		return err
	}
	return nil
}

func (b *Backend) flushChain(name string) error {
	ch, err := b.getChain(name)
	if err != nil {
		return err
	}
	b.conn.FlushChain(ch)
	return b.conn.Flush()
}

func (b *Backend) DumpFloodCounters() { b.cli.DumpFloodCounters() }
func (b *Backend) DumpThrottledIPs()  { b.cli.DumpThrottledIPs() }
func (b *Backend) LoadPortScanner()   { b.cli.LoadPortScanner() }
