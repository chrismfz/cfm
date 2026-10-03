package nft

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cfm/internal/config"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

// port-scan tracking sets (also read by the portscan harvester)
const (
	psPairsV4    = "ps_pairs_v4"
	psPairsV6    = "ps_pairs_v6"
	psPairsUDPV4 = "ps_pairs_udp_v4"
	psPairsUDPV6 = "ps_pairs_udp_v6"
)

// ApplyPortsPolicy writes the TCP_IN/UDP_IN/TCP_OUT/UDP_OUT policy, the
// debug-port accepts and the portscan tracking rules as ONE nft transaction
// (firewall.PortsPolicyScript): no packet sees a half-applied policy, and a
// failed apply leaves the previous one in place.
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

	p := firewall.PortsPolicy{Family: family, Table: tableName, TCPIn: cfg.TCPIn, UDPIn: cfg.UDPIn, TCPOut: cfg.TCPOut, UDPOut: cfg.UDPOut}

	// Debug ports: out of the generic tcp_in set, accepted only from self and
	// the resolved API addresses.
	if b.cfg != nil {
		for _, port := range []int{b.cfg.Debug.Port, b.cfg.Debug.TLSPort} {
			if port > 0 && port <= 65535 {
				p.DebugPorts = append(p.DebugPorts, port)
				p.TCPIn = firewall.SubtractPort(p.TCPIn, port)
			}
		}
	}
	if len(p.DebugPorts) > 0 {
		if err := b.ensureSet(debugAPIV4, "ipv4_addr"); err != nil {
			return err
		}
		if err := b.ensureSet(debugAPIV6, "ipv6_addr"); err != nil {
			return err
		}
		b.refreshAPISets()
	}

	if b.cfg != nil && b.cfg.Portscan.Enabled {
		ps := b.cfg.Portscan
		b.ensurePortscanSets()
		p.Portscan = portscanTracking(ps)
		logging.Logf("[ports] portscan: enabled=%v interval=%ds track_tcp=%v track_udp=%v only_ranges=%d focus_ports=%d",
			ps.Enabled, ps.Interval, ps.TrackTCP, ps.TrackUDP, len(ps.OnlyPorts), len(ps.Ports))
	}

	return firewall.ApplyPortsPolicyScript(p, b.listChainForPorts, b.nftCmd)
}

// portscanTracking is the PS_* config as the ports policy writes it: the
// service filter is PS_ONLY_PORTS plus PS_PORTS (clamped to 0-65535).
func portscanTracking(ps config.PortscanConfig) *firewall.PortscanTracking {
	svc := append([]config.PortRange{}, ps.OnlyPorts...)
	for _, port := range ps.Ports {
		port = min(max(port, 0), 65535)
		svc = append(svc, config.PortRange{From: port, To: port})
	}
	return &firewall.PortscanTracking{TrackTCP: ps.TrackTCP, TrackUDP: ps.TrackUDP, Interval: ps.Interval, Service: svc}
}

// listChainForPorts is firewall.ListChainFunc for this engine.
func (b *Backend) listChainForPorts(chain string) (string, bool, error) {
	res, err := runNFTCommand(context.Background(), "-a", "list", "chain", family, tableName, chain)
	if err != nil {
		if firewall.IsNFTNoSuchObject(res.Stderr) {
			return "", false, nil
		}
		return "", true, fmt.Errorf("nft -a list chain %s %s %s: %w: %s", family, tableName, chain, err, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, true, nil
}
