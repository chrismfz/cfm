//go:build linux

package nftlib

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"

	"cfm/internal/config"
	"cfm/internal/logging"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ── port-set names ───────────────────────────────────────────────────────────

const (
	setTCPIn  = "tcp_in_ports"
	setUDPIn  = "udp_in_ports"
	setTCPOut = "tcp_out_ports"
	setUDPOut = "udp_out_ports"
)

// portRange mirrors config.PortRange for local use.
type portRange struct{ From, To int }

// normalizePortRanges merges overlapping/adjacent port ranges.
func normalizePortRanges(prs []portRange) []portRange {
	if len(prs) == 0 {
		return prs
	}
	for _, r := range prs {
		if r.From == 0 && r.To == 65535 {
			return []portRange{{0, 65535}}
		}
	}
	rs := make([]portRange, len(prs))
	copy(rs, prs)
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].From == rs[j].From {
			return rs[i].To < rs[j].To
		}
		return rs[i].From < rs[j].From
	})
	out := []portRange{rs[0]}
	for _, r := range rs[1:] {
		cur := &out[len(out)-1]
		if r.From <= cur.To+1 {
			if r.To > cur.To {
				cur.To = r.To
			}
		} else {
			out = append(out, r)
		}
	}
	return out
}

type portsPolicyRule struct {
	Chain         string
	Protocol      string
	PortFrom      int
	PortTo        int
	Verdict       expr.VerdictKind
	MatchExprs    []string
	ExpectedMatch bool
}

// hardeningRuleSnapshot is a compatibility snapshot used by parity tests to
// validate logical rule intent without relying on nft expression internals.
type hardeningRuleSnapshot struct {
	Chain   string
	Path    string
	Verdict expr.VerdictKind
}

func cfgPortRanges(prs []config.PortRange) []portRange {
	out := make([]portRange, len(prs))
	for i, p := range prs {
		out[i] = portRange{p.From, p.To}
	}
	return out
}

// ── flood rebuild hash ────────────────────────────────────────────────────────

func floodCfgHash(c *config.Config) uint64 {
	if c == nil {
		return 0
	}
	h := nftlibFnv64(0,
		uint64(c.PacketRate.Rate), uint64(c.PacketRate.Burst),
		nftlibHashStr(c.PacketRate.Mode),
		nftlibBoolU64(c.Hardening.BlockBadTCPFlags),
		uint64(c.Hardening.NewRate), uint64(c.Hardening.ICMPRate),
		uint64(len(c.Connlimit.Rules)), uint64(len(c.PortFlood.Rules)),
		uint64(c.NFT.InputPriority),
	)
	for _, r := range c.Connlimit.Rules {
		h = nftlibFnv64(h, uint64(r.Port), uint64(r.Limit), nftlibHashStr(r.Proto))
	}
	for _, r := range c.PortFlood.Rules {
		h = nftlibFnv64(h, uint64(r.Port), uint64(r.Packets), uint64(r.WindowSec), nftlibHashStr(r.Proto))
	}
	return h
}

func nftlibFnv64(h uint64, vals ...uint64) uint64 {
	const prime = 1099511628211
	if h == 0 {
		h = 14695981039346656037
	}
	for _, v := range vals {
		h ^= v
		h *= prime
	}
	return h
}

func nftlibHashStr(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func nftlibBoolU64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// ── ApplyFloodRules ───────────────────────────────────────────────────────────

const meterRefreshInterval = 15 * time.Minute

var throttleSetEnsureCmds = []string{
	"add set inet cfm th_syn_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_syn_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm th_pps_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_pps_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm th_pf_tcp_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_pf_tcp_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm th_pf_udp_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_pf_udp_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm throttled_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm throttled_v6 { type ipv6_addr; flags timeout; }",
}

func (b *Backend) ApplyFloodRules(c *config.Config) (err error) {
	start := time.Now()
	connRules := 0
	pfRules := 0
	if c != nil {
		connRules = len(c.Connlimit.Rules)
		pfRules = len(c.PortFlood.Rules)
	}
	b.logPhase("ApplyFloodRules", "start", 0, nil, fmt.Sprintf("connlimit_rules=%d portflood_rules=%d", connRules, pfRules))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyFloodRules", st, time.Since(start), err, fmt.Sprintf("connlimit_rules=%d portflood_rules=%d", connRules, pfRules))
	}()
	b.cfg = c

	h := floodCfgHash(c)
	if h != 0 && h == b.lastFloodHash {
		b.mu.Lock()
		_, tableErr := b.lookupTable()
		b.mu.Unlock()
		if tableErr == nil && !b.lastFloodRebuild.IsZero() &&
			time.Since(b.lastFloodRebuild) < meterRefreshInterval {
			return nil
		}
	}
	b.lastFloodHash = h

	b.mu.Lock()
	_, tableErr := b.lookupTable()
	b.mu.Unlock()
	if tableErr != nil {
		if err = b.EnsureBase(); err != nil {
			return err
		}
	}

	_ = b.nftExec("flush chain inet cfm flood")
	_ = b.nftExec("add rule inet cfm flood ip saddr @self_v4 return")
	_ = b.nftExec("add rule inet cfm flood ip6 saddr @self_v6 return")

	b.ensureThrottleSetsCLI()

	if c == nil {
		return nil
	}
	if err = b.ApplyHardeningRules(c); err != nil {
		return err
	}
	if c.PacketRate.Rate > 0 {
		burst := c.PacketRate.Burst
		if burst <= 0 {
			burst = c.PacketRate.Rate * 2
		}
		if err = b.applyPerIPRateLimitCLI(c.PacketRate.Rate, burst, c.PacketRate.Mode); err != nil {
			return err
		}
	}
	if err = b.ApplyConnlimit(c.Connlimit.Rules); err != nil {
		return err
	}
	if err = b.ApplyPortFlood(c.PortFlood.Rules); err != nil {
		return err
	}
	b.lastFloodRebuild = time.Now()
	return nil
}

func (b *Backend) ensureThrottleSetsCLI() {
	for _, s := range throttleSetEnsureCmds {
		_ = b.nftExec(s)
	}
}

func perIPRateLimitCmds(rate, burst, ttl int, mode string) []string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "all":
		return []string{
			fmt.Sprintf(
				"add rule inet cfm flood meter pps_v4 { ip saddr limit rate over %d/second burst %d packets } "+
					"add @th_pps_v4 { ip saddr timeout %ds } "+
					"add @throttled_v4 { ip saddr timeout %ds } "+
					"counter name ppsrate_v4 drop comment \"per-ip pps rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
			fmt.Sprintf(
				"add rule inet cfm flood meter pps_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
					"add @th_pps_v6 { ip6 saddr timeout %ds } "+
					"add @throttled_v6 { ip6 saddr timeout %ds } "+
					"counter name ppsrate_v6 drop comment \"per-ip pps rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
		}
	default:
		return []string{
			fmt.Sprintf(
				"add rule inet cfm flood tcp flags syn meter syn_v4 { ip saddr limit rate over %d/second burst %d packets } "+
					"add @th_syn_v4 { ip saddr timeout %ds } "+
					"add @throttled_v4 { ip saddr timeout %ds } "+
					"counter name synrate_v4 drop comment \"per-ip syn rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
			fmt.Sprintf(
				"add rule inet cfm flood tcp flags syn meter syn_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
					"add @th_syn_v6 { ip6 saddr timeout %ds } "+
					"add @throttled_v6 { ip6 saddr timeout %ds } "+
					"counter name synrate_v6 drop comment \"per-ip syn rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
		}
	}
}

// ── Test-consumed package-private helpers (compatibility surface) ────────────
//
// NOTE: These helpers are intentionally package-private and consumed by parity
// tests. Keep names/signatures stable; if internals need to change, preserve
// these entry points as wrappers first and migrate tests separately.

// buildFloodVerdictPlan returns the planned verdict kind for each flood-path
// rule in order.
func buildFloodVerdictPlan(c *config.Config) ([]expr.VerdictKind, error) {
	if c == nil {
		return nil, nil
	}
	snaps := buildHardeningRuleSnapshots(c)
	out := make([]expr.VerdictKind, 0, len(snaps)+len(c.Connlimit.Rules)+len(c.PortFlood.Rules))
	for _, s := range snaps {
		out = append(out, s.Verdict)
	}
	for _, r := range c.Connlimit.Rules {
		proto := strings.ToLower(strings.TrimSpace(r.Proto))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("unknown proto %q", r.Proto)
		}
		out = append(out, expr.VerdictDrop)
	}
	for range c.PortFlood.Rules {
		out = append(out, expr.VerdictDrop)
	}
	return out, nil
}

// buildHardeningRuleSnapshots snapshots hardening rule intent for parity tests.
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

// buildPortsPolicySnapshots snapshots ports policy rule intent for parity tests.
func buildPortsPolicySnapshots(cfg *config.PortsConfig) []hardeningRuleSnapshot {
	rules := buildPortsAllowlistRules(cfg)
	out := []hardeningRuleSnapshot{
		{Chain: "input", Path: "ct.established_related", Verdict: expr.VerdictAccept},
		{Chain: "input", Path: "ct.invalid", Verdict: expr.VerdictDrop},
		{Chain: "output", Path: "ct.established_related", Verdict: expr.VerdictAccept},
		{Chain: "output", Path: "ct.invalid", Verdict: expr.VerdictDrop},
	}
	for _, r := range rules {
		out = append(out, hardeningRuleSnapshot{
			Chain:   r.Chain,
			Path:    fmt.Sprintf("ct.new.%s.accept", r.Protocol),
			Verdict: r.Verdict,
		})
	}
	return out
}

// ── ApplyHardeningRules ───────────────────────────────────────────────────────

func (b *Backend) ApplyHardeningRules(c *config.Config) (err error) {
	start := time.Now()
	b.logPhase("ApplyHardeningRules", "start", 0, nil, "")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyHardeningRules", st, time.Since(start), err, "")
	}()
	if c == nil {
		return nil
	}

	if c.Hardening.BlockBadTCPFlags {
		b.ensureCounterCLI("badflags_drop")
		for _, r := range []string{
			`add rule inet cfm flood tcp flags & (syn|fin) == (syn|fin) counter name "badflags_drop" drop comment "SYN+FIN"`,
			`add rule inet cfm flood tcp flags & (syn|rst) == (syn|rst) counter name "badflags_drop" drop comment "SYN+RST"`,
			`add rule inet cfm flood tcp flags & (fin|psh|urg) == (fin|psh|urg) counter name "badflags_drop" drop comment "XMAS"`,
			`add rule inet cfm flood tcp flags & (fin|psh|urg|rst|syn|ack) == 0 counter name "badflags_drop" drop comment "NULL"`,
		} {
			if err := b.nftExec(r); err != nil {
				return err
			}
		}
	}

	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}

	if c.Hardening.NewRate > 0 {
		b.ensureCounterCLI("newrate_v4")
		b.ensureCounterCLI("newrate_v6")
		_ = b.nftExec("add set inet cfm th_new_v4 { type ipv4_addr; flags timeout; }")
		_ = b.nftExec("add set inet cfm th_new_v6 { type ipv6_addr; flags timeout; }")

		burstNew := c.Hardening.NewBurst
		if burstNew <= 0 {
			burstNew = c.Hardening.NewRate
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ct state new ip protocol != icmp `+
				`meter new_v4 { ip saddr limit rate over %d/second burst %d packets } `+
				`add @th_new_v4 { ip saddr timeout %ds } `+
				`add @throttled_v4 { ip saddr timeout %ds } `+
				`counter name "newrate_v4" drop comment "global-new-v4(no-icmp)"`,
			c.Hardening.NewRate, burstNew, ttl, ttl,
		)); err != nil {
			return err
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ct state new ip6 nexthdr != ipv6-icmp `+
				`meter new_v6 { ip6 saddr limit rate over %d/second burst %d packets } `+
				`add @th_new_v6 { ip6 saddr timeout %ds } `+
				`add @throttled_v6 { ip6 saddr timeout %ds } `+
				`counter name "newrate_v6" drop comment "global-new-v6(no-icmp6)"`,
			c.Hardening.NewRate, burstNew, ttl, ttl,
		)); err != nil {
			return err
		}
	}

	if c.Hardening.ICMPRate > 0 {
		b.ensureCounterCLI("icmp_v4")
		b.ensureCounterCLI("icmp_v6")
		_ = b.nftExec("add set inet cfm th_icmp_v4 { type ipv4_addr; flags timeout; }")
		_ = b.nftExec("add set inet cfm th_icmp_v6 { type ipv6_addr; flags timeout; }")

		burstICMP := c.Hardening.ICMPBurst
		if burstICMP <= 0 {
			burstICMP = c.Hardening.ICMPRate * 2
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ip protocol icmp icmp type echo-request `+
				`meter icmp4 { ip saddr limit rate over %d/second burst %d packets } `+
				`add @th_icmp_v4 { ip saddr timeout %ds } `+
				`counter name "icmp_v4" drop comment "icmp-echo-limit"`,
			c.Hardening.ICMPRate, burstICMP, ttl,
		)); err != nil {
			return err
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ip6 nexthdr ipv6-icmp icmpv6 type echo-request `+
				`meter icmp6 { ip6 saddr limit rate over %d/second burst %d packets } `+
				`add @th_icmp_v6 { ip6 saddr timeout %ds } `+
				`counter name "icmp_v6" drop comment "icmp6-echo-limit"`,
			c.Hardening.ICMPRate, burstICMP, ttl,
		)); err != nil {
			return err
		}
	}

	return nil
}

// ── applyPerIPRateLimitCLI ────────────────────────────────────────────────────

func (b *Backend) applyPerIPRateLimitCLI(rate, burst int, mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}
	switch mode {
	case "all":
		b.ensureCounterCLI("ppsrate_v4")
		cmds := perIPRateLimitCmds(rate, burst, ttl, mode)
		if err := b.nftExec(cmds[0]); err != nil {
			return err
		}
		b.ensureCounterCLI("ppsrate_v6")
		if err := b.nftExec(cmds[1]); err != nil {
			return err
		}
	default: // "syn"
		b.ensureCounterCLI("synrate_v4")
		cmds := perIPRateLimitCmds(rate, burst, ttl, mode)
		if err := b.nftExec(cmds[0]); err != nil {
			return err
		}
		b.ensureCounterCLI("synrate_v6")
		if err := b.nftExec(cmds[1]); err != nil {
			return err
		}
	}
	return nil
}

func buildPortsAllowlistRules(cfg *config.PortsConfig) []portsPolicyRule {
	if cfg == nil {
		return nil
	}
	tcpIn := normalizePortRanges(cfgPortRanges(cfg.TCPIn))
	udpIn := normalizePortRanges(cfgPortRanges(cfg.UDPIn))
	tcpOut := normalizePortRanges(cfgPortRanges(cfg.TCPOut))
	udpOut := normalizePortRanges(cfgPortRanges(cfg.UDPOut))

	rules := make([]portsPolicyRule, 0, len(tcpIn)+len(udpIn)+len(tcpOut)+len(udpOut))
	for _, pr := range tcpIn {
		rules = append(rules, portsPolicyRule{Chain: "input", Protocol: "tcp", PortFrom: pr.From, PortTo: pr.To, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", fmt.Sprintf("tcp dport %d-%d", pr.From, pr.To)}, ExpectedMatch: true})
	}
	for _, pr := range udpIn {
		rules = append(rules, portsPolicyRule{Chain: "input", Protocol: "udp", PortFrom: pr.From, PortTo: pr.To, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", fmt.Sprintf("udp dport %d-%d", pr.From, pr.To)}, ExpectedMatch: true})
	}
	for _, pr := range tcpOut {
		rules = append(rules, portsPolicyRule{Chain: "output", Protocol: "tcp", PortFrom: pr.From, PortTo: pr.To, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", fmt.Sprintf("tcp dport %d-%d", pr.From, pr.To)}, ExpectedMatch: true})
	}
	for _, pr := range udpOut {
		rules = append(rules, portsPolicyRule{Chain: "output", Protocol: "udp", PortFrom: pr.From, PortTo: pr.To, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", fmt.Sprintf("udp dport %d-%d", pr.From, pr.To)}, ExpectedMatch: true})
	}
	return rules
}

func validateRuleBeforeCommit(r portsPolicyRule) error {
	if r.ExpectedMatch && len(r.MatchExprs) == 0 {
		return fmt.Errorf("rule validation failed: chain=%s proto=%s expected match expressions before verdict", r.Chain, r.Protocol)
	}
	if r.ExpectedMatch && r.Verdict == expr.VerdictAccept && len(r.MatchExprs) == 0 {
		return fmt.Errorf("rule validation failed: verdict accept without required match expressions")
	}
	return nil
}

func debugLogRuleBatch(category string, rules []portsPolicyRule, sample int) {
	if sample <= 0 {
		sample = 3
	}
	log.Printf("[nftlib] rule batch category=%s count=%d", category, len(rules))
	for i := 0; i < len(rules) && i < sample; i++ {
		log.Printf("[nftlib] rule batch category=%s sample[%d]=%s", category, i, renderPortsPolicyRule(rules[i]))
	}
}

func renderPortsPolicyRule(r portsPolicyRule) string {
	parts := append([]string{}, r.MatchExprs...)
	verdict := "unknown"
	if r.Verdict == expr.VerdictAccept {
		verdict = "accept"
	} else if r.Verdict == expr.VerdictDrop {
		verdict = "drop"
	}
	parts = append(parts, fmt.Sprintf("verdict=%s", verdict))
	return strings.Join(parts, " ")
}

func (b *Backend) flushChainsAndAppendVerdictsAtomically(chains []string, rules []portsPolicyRule) error {
	seen := make(map[string]struct{}, len(chains))
	orderedChains := make([]string, 0, len(chains))
	for _, name := range chains {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		orderedChains = append(orderedChains, name)
	}

	rulesByChain := make(map[string][]portsPolicyRule, len(orderedChains))
	for _, r := range rules {
		if err := validateRuleBeforeCommit(r); err != nil {
			return err
		}
		if _, ok := seen[r.Chain]; !ok {
			return fmt.Errorf("rule validation failed: unexpected chain %q", r.Chain)
		}
		rulesByChain[r.Chain] = append(rulesByChain[r.Chain], r)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	for _, name := range orderedChains {
		ch, err := b.getChain(name)
		if err != nil {
			return err
		}
		b.conn.FlushChain(ch)
	}
	for _, name := range orderedChains {
		ch, err := b.getChain(name)
		if err != nil {
			return err
		}
		for _, r := range rulesByChain[name] {
			b.conn.AddRule(&nftables.Rule{Table: ch.Table, Chain: ch, Exprs: []expr.Any{&expr.Verdict{Kind: r.Verdict}}})
		}
	}
	debugLogRuleBatch("ports_policy", rules, 5)
	return b.conn.Flush()
}

// ── ApplyConnlimit ────────────────────────────────────────────────────────────

func (b *Backend) ApplyConnlimit(rules []config.ConnlimitRule) (err error) {
	start := time.Now()
	b.logPhase("ApplyConnlimit", "start", 0, nil, fmt.Sprintf("rules=%d", len(rules)))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyConnlimit", st, time.Since(start), err, fmt.Sprintf("rules=%d", len(rules)))
	}()
	const meterSize = 65535
	for _, r := range rules {
		proto := strings.ToLower(r.Proto)
		cname := fmt.Sprintf("connlimit_%d_%s", r.Port, proto)
		b.ensureCounterCLI(cname)
		switch proto {
		case "tcp":
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood ip protocol tcp ct state new tcp dport %d "+
					"meter cl_%d_tcp_v4 size %d { ip saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\"",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)); err != nil {
				return fmt.Errorf("connlimit tcp v4: %w", err)
			}
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr tcp ct state new tcp dport %d "+
					"meter cl_%d_tcp_v6 size %d { ip6 saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\"",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)); err != nil {
				return fmt.Errorf("connlimit tcp v6: %w", err)
			}
		case "udp":
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood ip protocol udp ct state new udp dport %d "+
					"meter cl_%d_udp_v4 size %d { ip saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\"",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)); err != nil {
				return fmt.Errorf("connlimit udp v4: %w", err)
			}
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr udp ct state new udp dport %d "+
					"meter cl_%d_udp_v6 size %d { ip6 saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\"",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)); err != nil {
				return fmt.Errorf("connlimit udp v6: %w", err)
			}
		default:
			return fmt.Errorf("unknown proto %q in CONNLIMIT", r.Proto)
		}
	}
	return nil
}

// ── ApplyPortFlood ────────────────────────────────────────────────────────────

func nftlibMapRate(max, intervalSec int) (int, string) {
	if intervalSec <= 0 {
		intervalSec = 60
	}
	for _, u := range []struct {
		name string
		sec  int
	}{{"day", 86400}, {"hour", 3600}, {"minute", 60}, {"second", 1}} {
		if intervalSec%u.sec == 0 {
			n := int(math.Ceil(float64(max) / float64(intervalSec/u.sec)))
			if n < 1 {
				n = 1
			}
			return n, u.name
		}
	}
	return max, "second"
}

func (b *Backend) ApplyPortFlood(rules []config.PortFloodRule) (err error) {
	start := time.Now()
	b.logPhase("ApplyPortFlood", "start", 0, nil, fmt.Sprintf("rules=%d", len(rules)))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyPortFlood", st, time.Since(start), err, fmt.Sprintf("rules=%d", len(rules)))
	}()
	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}
	for _, r := range rules {
		proto := strings.ToLower(r.Proto)
		cname := fmt.Sprintf("portflood_%d_%s", r.Port, proto)
		b.ensureCounterCLI(cname)

		setV4 := fmt.Sprintf("th_pf_%d_%s_v4", r.Port, proto)
		setV6 := fmt.Sprintf("th_pf_%d_%s_v6", r.Port, proto)
		_ = b.nftExec(fmt.Sprintf("add set inet cfm %s { type ipv4_addr; flags timeout; }", setV4))
		_ = b.nftExec(fmt.Sprintf("add set inet cfm %s { type ipv6_addr; flags timeout; }", setV6))

		num, unit := nftlibMapRate(r.Packets, r.WindowSec)
		switch proto {
		case "tcp":
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV4, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood tcp v4: %w", err)
			}
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV6, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood tcp v6: %w", err)
			}
		case "udp":
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV4, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood udp v4: %w", err)
			}
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV6, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood udp v6: %w", err)
			}
		default:
			return fmt.Errorf("unknown proto %q in PORTFLOOD", r.Proto)
		}
	}
	return nil
}

// ── ApplySMTPBlock ────────────────────────────────────────────────────────────

func (b *Backend) ApplySMTPBlock(cfg *config.SMTPBlockConfig) (err error) {
	start := time.Now()
	enabled := cfg != nil && cfg.Enabled
	b.logPhase("ApplySMTPBlock", "start", 0, nil, fmt.Sprintf("enabled=%t", enabled))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplySMTPBlock", st, time.Since(start), err, fmt.Sprintf("enabled=%t", enabled))
	}()
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if !b.chainExistsCLI("smtpblock") {
		if err := b.nftExec(
			"add chain inet cfm smtpblock { type filter hook output priority -100; policy accept; }",
		); err != nil {
			return err
		}
	}
	_ = b.nftExec("flush chain inet cfm smtpblock")
	return b.nftExec("add rule inet cfm smtpblock drop")
}

// ── ApplyPortsPolicy ─────────────────────────────────────────────────────────

func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) (err error) {
	start := time.Now()
	b.logPhase("ApplyPortsPolicy", "start", 0, nil, fmt.Sprintf("tcp_in=%d udp_in=%d tcp_out=%d udp_out=%d", len(cfg.TCPIn), len(cfg.UDPIn), len(cfg.TCPOut), len(cfg.UDPOut)))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyPortsPolicy", st, time.Since(start), err, fmt.Sprintf("tcp_in=%d udp_in=%d tcp_out=%d udp_out=%d", len(cfg.TCPIn), len(cfg.UDPIn), len(cfg.TCPOut), len(cfg.UDPOut)))
	}()
	if cfg == nil {
		return nil
	}
	logging.Logf("[ports] applying policy: tcp_in=%d ranges, udp_in=%d, tcp_out=%d, udp_out=%d",
		len(cfg.TCPIn), len(cfg.UDPIn), len(cfg.TCPOut), len(cfg.UDPOut))

	// Ensure output chain.
	if !b.chainExistsCLI("output") {
		if err := b.nftExec(
			"add chain inet cfm output { type filter hook output priority 0; policy accept; }",
		); err != nil {
			return err
		}
	}

	// Ensure port sets and load ranges.
	for _, name := range []string{setTCPIn, setUDPIn, setTCPOut, setUDPOut} {
		if err := b.ensurePortSetCLI(name); err != nil {
			return err
		}
	}

	dbgPort := 0
	if b.cfg != nil && b.cfg.Debug.Port > 0 && b.cfg.Debug.Port <= 65535 {
		dbgPort = b.cfg.Debug.Port
	}

	filteredTCPIn := cfgPortRanges(cfg.TCPIn)
	if dbgPort > 0 {
		filteredTCPIn = subtractPortRange(filteredTCPIn, dbgPort)
	}

	if err := b.replacePortSetCLI(setTCPIn, filteredTCPIn); err != nil {
		return err
	}
	if err := b.replacePortSetCLI(setUDPIn, cfgPortRanges(cfg.UDPIn)); err != nil {
		return err
	}
	if err := b.replacePortSetCLI(setTCPOut, cfgPortRanges(cfg.TCPOut)); err != nil {
		return err
	}
	if err := b.replacePortSetCLI(setUDPOut, cfgPortRanges(cfg.UDPOut)); err != nil {
		return err
	}

	addRule := func(chain, expr string) error {
		if !b.ruleExistsCLI(chain, expr) {
			return b.nftExec("add rule inet cfm " + chain + " " + expr)
		}
		return nil
	}

	// Portscan tracking sets (netlink-native, already ensured by telemetry on LoadPortScanner).
	b.ensurePortscanSetsNative()

	hasSvcFilter := false
	if b.cfg != nil && b.cfg.Portscan.Enabled {
		ps := b.cfg.Portscan
		pairTTL := ps.Interval
		if pairTTL <= 0 {
			pairTTL = 60
		}

		svc := make([]portRange, 0, len(ps.OnlyPorts)+len(ps.Ports))
		for _, r := range ps.OnlyPorts {
			svc = append(svc, portRange{r.From, r.To})
		}
		for _, p := range ps.Ports {
			if p < 0 {
				p = 0
			}
			if p > 65535 {
				p = 65535
			}
			svc = append(svc, portRange{p, p})
		}
		hasSvcFilter = len(svc) > 0

		logging.Logf("[ports] portscan: enabled=%v interval=%ds track_tcp=%v track_udp=%v only_ranges=%d focus_ports=%d",
			ps.Enabled, ps.Interval, ps.TrackTCP, ps.TrackUDP, len(ps.OnlyPorts), len(ps.Ports))

		if hasSvcFilter {
			const trackTCP = "ps_track_tcp_ports"
			const trackUDP = "ps_track_udp_ports"
			if err := b.ensurePortSetCLI(trackTCP); err != nil {
				return err
			}
			if err := b.replacePortSetCLI(trackTCP, svc); err != nil {
				return err
			}
			if ps.TrackUDP {
				if err := b.ensurePortSetCLI(trackUDP); err != nil {
					return err
				}
				if err := b.replacePortSetCLI(trackUDP, svc); err != nil {
					return err
				}
			}
			logging.Logf("[ports] ps_track_tcp_ports loaded (%d entries)", len(svc))

			if ps.TrackTCP {
				if err := addRule("input", fmt.Sprintf(
					"tcp dport @%s add @%s { ip saddr . tcp dport timeout %ds }",
					trackTCP, psPairsV4, pairTTL)); err != nil {
					return err
				}
				if err := addRule("input", fmt.Sprintf(
					"ip6 nexthdr tcp tcp dport @%s add @%s { ip6 saddr . tcp dport timeout %ds }",
					trackTCP, psPairsV6, pairTTL)); err != nil {
					return err
				}
			}
			if ps.TrackUDP {
				if err := addRule("input", fmt.Sprintf(
					"udp dport @%s add @%s { ip saddr . udp dport timeout %ds }",
					trackUDP, psPairsUDPV4, pairTTL)); err != nil {
					return err
				}
				if err := addRule("input", fmt.Sprintf(
					"ip6 nexthdr udp udp dport @%s add @%s { ip6 saddr . udp dport timeout %ds }",
					trackUDP, psPairsUDPV6, pairTTL)); err != nil {
					return err
				}
			}
		}
	}

	_ = addRule("input", "ct state established,related accept")

	// Remove old bare-range rules then add ct-state-qualified ones.
	delRuleCLI("input", "tcp dport @"+setTCPIn+" accept")
	delRuleCLI("input", "udp dport @"+setUDPIn+" accept")

	if err := addRule("input", "ct state new tcp dport @"+setTCPIn+" accept"); err != nil {
		return err
	}
	if err := addRule("input", "ct state new udp dport @"+setUDPIn+" accept"); err != nil {
		return err
	}

	// Debug port: restrict to self + API sets only.
	if dbgPort > 0 {
		_ = b.nftExec("add set inet cfm debug_api_v4 { type ipv4_addr; }")
		_ = b.nftExec("add set inet cfm debug_api_v6 { type ipv6_addr; }")
		if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip saddr @self_v4 accept", dbgPort)); err != nil {
			return err
		}
		if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip6 saddr @self_v6 accept", dbgPort)); err != nil {
			return err
		}
		if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip saddr @debug_api_v4 accept", dbgPort)); err != nil {
			return err
		}
		if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip6 saddr @debug_api_v6 accept", dbgPort)); err != nil {
			return err
		}
	}

	// Portscan tracking (non-filter mode: track anything NOT in accepted ports).
	if b.cfg != nil && b.cfg.Portscan.Enabled && !hasSvcFilter {
		ps := b.cfg.Portscan
		pairTTL := ps.Interval
		if pairTTL <= 0 {
			pairTTL = 60
		}
		if ps.TrackTCP {
			if err := addRule("input", fmt.Sprintf(
				"tcp dport != @%s add @%s { ip saddr . tcp dport timeout %ds }",
				setTCPIn, psPairsV4, pairTTL)); err != nil {
				return err
			}
			if err := addRule("input", fmt.Sprintf(
				"ip6 nexthdr tcp tcp dport != @%s add @%s { ip6 saddr . tcp dport timeout %ds }",
				setTCPIn, psPairsV6, pairTTL)); err != nil {
				return err
			}
		}
		if ps.TrackUDP {
			if err := addRule("input", fmt.Sprintf(
				"udp dport != @%s add @%s { ip saddr . udp dport timeout %ds }",
				setUDPIn, psPairsUDPV4, pairTTL)); err != nil {
				return err
			}
			if err := addRule("input", fmt.Sprintf(
				"ip6 nexthdr udp udp dport != @%s add @%s { ip6 saddr . udp dport timeout %ds }",
				setUDPIn, psPairsUDPV6, pairTTL)); err != nil {
				return err
			}
		}
	}

	// Default drops (INPUT).
	delRuleCLI("input", "tcp dport 0-65535 drop")
	delRuleCLI("input", "udp dport 0-65535 drop")
	if err := addRule("input", "ct state new tcp dport 0-65535 drop"); err != nil {
		return err
	}
	if err := addRule("input", "ct state new udp dport 0-65535 drop"); err != nil {
		return err
	}
	if err := addRule("input", "ct state invalid drop"); err != nil {
		return err
	}

	// OUTPUT policy.
	_ = addRule("output", "ct state established,related accept")
	_ = addRule("output", "ct state invalid drop")
	delRuleCLI("output", "tcp dport 0-65535 drop")
	delRuleCLI("output", "udp dport 0-65535 drop")
	if err := addRule("output", "ct state new tcp dport @"+setTCPOut+" accept"); err != nil {
		return err
	}
	if err := addRule("output", "ct state new udp dport @"+setUDPOut+" accept"); err != nil {
		return err
	}
	if err := addRule("output", "ct state new tcp dport 0-65535 drop"); err != nil {
		return err
	}
	if err := addRule("output", "ct state new udp dport 0-65535 drop"); err != nil {
		return err
	}

	return nil
}

// subtractPortRange removes a single port from a slice of portRange.
func subtractPortRange(prs []portRange, p int) []portRange {
	if p <= 0 || p > 65535 {
		return prs
	}
	out := make([]portRange, 0, len(prs)+1)
	for _, r := range prs {
		if p < r.From || p > r.To {
			out = append(out, r)
			continue
		}
		if r.From < p {
			out = append(out, portRange{r.From, p - 1})
		}
		if p < r.To {
			out = append(out, portRange{p + 1, r.To})
		}
	}
	return out
}
