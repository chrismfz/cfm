//go:build linux

package nftlib

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"cfm/internal/config"
	"cfm/internal/firewall"
	"cfm/internal/logging"
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

// ApplyPortsPolicy writes the TCP_IN/UDP_IN/TCP_OUT/UDP_OUT policy, the
// debug-port accepts and the portscan tracking rules as ONE nft transaction
// (firewall.PortsPolicyScript, shared with the nft engine): no packet sees a
// half-applied policy, and a failed apply leaves the previous one in place.
// Like every input-chain write it is nft text: nftlib must never read inet cfm
// input over netlink (the DNAT accepts' `ct original` match breaks the dump).
func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) (err error) {
	if cfg == nil {
		return nil
	}
	start := time.Now()
	summary := fmt.Sprintf("tcp_in=%d udp_in=%d tcp_out=%d udp_out=%d", len(cfg.TCPIn), len(cfg.UDPIn), len(cfg.TCPOut), len(cfg.UDPOut))
	b.logPhase("ApplyPortsPolicy", "start", 0, nil, summary)
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyPortsPolicy", st, time.Since(start), err, summary)
	}()
	logging.Logf("[ports] applying policy: tcp_in=%d ranges, udp_in=%d, tcp_out=%d, udp_out=%d",
		len(cfg.TCPIn), len(cfg.UDPIn), len(cfg.TCPOut), len(cfg.UDPOut))

	p := firewall.PortsPolicy{Family: "inet", Table: cfmTableName, TCPIn: cfg.TCPIn, UDPIn: cfg.UDPIn, TCPOut: cfg.TCPOut, UDPOut: cfg.UDPOut}

	// Debug ports: out of the generic tcp_in set, accepted only from self and
	// the debug_api_* sets.
	if b.cfg != nil {
		for _, port := range []int{b.cfg.Debug.Port, b.cfg.Debug.TLSPort} {
			if port > 0 && port <= 65535 {
				p.DebugPorts = append(p.DebugPorts, port)
				p.TCPIn = firewall.SubtractPort(p.TCPIn, port)
			}
		}
	}
	if len(p.DebugPorts) > 0 {
		_ = b.nftExec("add set inet cfm debug_api_v4 { type ipv4_addr; }")
		_ = b.nftExec("add set inet cfm debug_api_v6 { type ipv6_addr; }")
	}

	// Portscan tracking sets (netlink-native, already ensured by telemetry on LoadPortScanner).
	b.ensurePortscanSetsNative()
	if b.cfg != nil && b.cfg.Portscan.Enabled {
		ps := b.cfg.Portscan
		svc := append([]config.PortRange{}, ps.OnlyPorts...)
		for _, port := range ps.Ports {
			port = min(max(port, 0), 65535)
			svc = append(svc, config.PortRange{From: port, To: port})
		}
		p.Portscan = &firewall.PortscanTracking{TrackTCP: ps.TrackTCP, TrackUDP: ps.TrackUDP, Interval: ps.Interval, Service: svc}
		logging.Logf("[ports] portscan: enabled=%v interval=%ds track_tcp=%v track_udp=%v only_ranges=%d focus_ports=%d",
			ps.Enabled, ps.Interval, ps.TrackTCP, ps.TrackUDP, len(ps.OnlyPorts), len(ps.Ports))
	}

	return firewall.ApplyPortsPolicyScript(p,
		func(chain string) (string, bool, error) {
			text, err := b.chainTextCLI(chain)
			if err != nil && firewall.IsNFTNoSuchObject(err.Error()) {
				return "", false, nil
			}
			return text, err == nil, err
		},
		b.nftExec)
}
