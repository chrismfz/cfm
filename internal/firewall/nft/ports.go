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

// port-scan tracking sets (also read by the portscan harvester); one copy of
// each name, in package firewall
const (
	psPairsV4    = firewall.SetPSPairsV4
	psPairsV6    = firewall.SetPSPairsV6
	psPairsUDPV4 = firewall.SetPSPairsUDPV4
	psPairsUDPV6 = firewall.SetPSPairsUDPV6
)

// ApplyPortsPolicy writes the TCP_IN/UDP_IN/TCP_OUT/UDP_OUT policy, the
// debug-port accepts and the portscan tracking rules as ONE nft transaction
// (firewall.PortsPolicyScript, shared with nftlib): no packet sees a
// half-applied policy, and a failed apply leaves the previous one in place.
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

	p := firewall.NewPortsPolicy(family, tableName, cfg, b.cfg)
	if len(p.DebugPorts) > 0 {
		if err := b.ensureSet(debugAPIV4, "ipv4_addr"); err != nil {
			return err
		}
		if err := b.ensureSet(debugAPIV6, "ipv6_addr"); err != nil {
			return err
		}
		b.refreshAPISets()
	}
	if p.Portscan != nil {
		ps := b.cfg.Portscan
		b.ensurePortscanSets()
		logging.Logf("[ports] portscan: enabled=%v interval=%ds track_tcp=%v track_udp=%v only_ranges=%d focus_ports=%d",
			ps.Enabled, ps.Interval, ps.TrackTCP, ps.TrackUDP, len(ps.OnlyPorts), len(ps.Ports))
	}

	return firewall.ApplyPortsPolicyScript(p, nftRead, b.nftCmd)
}

// nftRead is firewall.NFTRead for this engine.
func nftRead(args ...string) (string, error) {
	res, err := runNFTCommand(context.Background(), args...)
	if err != nil {
		return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}
