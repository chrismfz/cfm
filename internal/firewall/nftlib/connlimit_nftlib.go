//go:build linux

package nftlib

import (
	"fmt"
	"strings"
	"time"

	"cfm/internal/config"
)

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
