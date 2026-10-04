//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/config"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

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

	p := firewall.NewPortsPolicy("inet", cfmTableName, cfg, b.cfg)
	if len(p.DebugPorts) > 0 {
		_ = b.nftExec("add set inet cfm " + firewall.SetDebugAPIV4 + " { type ipv4_addr; }")
		_ = b.nftExec("add set inet cfm " + firewall.SetDebugAPIV6 + " { type ipv6_addr; }")
	}
	// Portscan tracking sets (netlink-native, already ensured by telemetry on LoadPortScanner).
	b.ensurePortscanSetsNative()
	if p.Portscan != nil {
		ps := b.cfg.Portscan
		logging.Logf("[ports] portscan: enabled=%v interval=%ds track_tcp=%v track_udp=%v only_ranges=%d focus_ports=%d",
			ps.Enabled, ps.Interval, ps.TrackTCP, ps.TrackUDP, len(ps.OnlyPorts), len(ps.Ports))
	}

	return firewall.ApplyPortsPolicyScript(p, nftReadCLI, b.nftExec)
}
