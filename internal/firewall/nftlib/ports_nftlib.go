//go:build linux

package nftlib

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"cfm/internal/config"
	"cfm/internal/logging"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

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

func cfgPortRanges(prs []config.PortRange) []portRange {
	out := make([]portRange, len(prs))
	for i, p := range prs {
		out[i] = portRange{p.From, p.To}
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

	dbgPorts := []int{}
	if b.cfg != nil {
		if b.cfg.Debug.Port > 0 && b.cfg.Debug.Port <= 65535 {
			dbgPorts = append(dbgPorts, b.cfg.Debug.Port)
		}
		if b.cfg.Debug.TLSPort > 0 && b.cfg.Debug.TLSPort <= 65535 {
			dbgPorts = append(dbgPorts, b.cfg.Debug.TLSPort)
		}
	}

	filteredTCPIn := cfgPortRanges(cfg.TCPIn)
	for _, p := range dbgPorts {
		filteredTCPIn = subtractPortRange(filteredTCPIn, p)
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

	// Debug ports (plaintext + TLS): restrict to self + API sets only.
	if len(dbgPorts) > 0 {
		_ = b.nftExec("add set inet cfm debug_api_v4 { type ipv4_addr; }")
		_ = b.nftExec("add set inet cfm debug_api_v6 { type ipv6_addr; }")
		for _, p := range dbgPorts {
			if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip saddr @self_v4 accept", p)); err != nil {
				return err
			}
			if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip6 saddr @self_v6 accept", p)); err != nil {
				return err
			}
			if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip saddr @debug_api_v4 accept", p)); err != nil {
				return err
			}
			if err := addRule("input", fmt.Sprintf("ct state new tcp dport %d ip6 saddr @debug_api_v6 accept", p)); err != nil {
				return err
			}
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
