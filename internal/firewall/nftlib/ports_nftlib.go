//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/config"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"github.com/google/nftables"
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

	return firewall.ApplyPortsPolicyScript(p, firewall.PortsPolicyReads{Read: nftReadPorts, Chains: b.cfmChainNames}, b.nftExecPortsPolicy)
}

// nftReadPorts is firewall.NFTRead for this engine: the chain reads stay nft
// text (google/nftables can't decode the input chain's DNAT accepts), zero
// is the CLI default deadline.
func nftReadPorts(timeout time.Duration, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = nftlibCLITimeout
	}
	return nftReadCLITimeout(timeout, args...)
}

// nftExecPortsPolicy runs the ports-policy transaction under
// firewall.PortsPolicyChainReadTimeout, as the nft engine does.
func (b *Backend) nftExecPortsPolicy(script string) error {
	return b.nftExecTimeout(script, firewall.PortsPolicyChainReadTimeout)
}

// cfmChainNames names inet cfm's chains over netlink (a chain listing, never
// a rule dump), for firewall.PortsPolicyReads.Chains; ok is false when the
// listing fails, and the output chain is then read anyway.
func (b *Backend) cfmChainNames() (map[string]bool, bool) {
	b.mu.Lock()
	chains, err := b.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	b.mu.Unlock()
	if err != nil {
		return nil, false
	}
	names := map[string]bool{}
	for _, ch := range chains {
		if ch != nil && ch.Table != nil && ch.Table.Name == cfmTableName {
			names[ch.Name] = true
		}
	}
	return names, true
}
