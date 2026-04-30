package nft

import (
	cfgpkg "cfm/internal/config"
	"fmt"
	"strings"
)

func (b *Backend) ApplyConnlimit(rules []cfgpkg.ConnlimitRule) error {
	const meterSize = 65535
	for _, r := range rules {
		cname := fmt.Sprintf("connlimit_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)
		switch strings.ToLower(r.Proto) {
		case "tcp":
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood ip protocol tcp ct state new tcp dport %d "+
					"meter cl_%d_tcp_v4 size %d { ip saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("connlimit per-ip v4 tcp rule failed: %w", err)
			}
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr tcp ct state new tcp dport %d "+
					"meter cl_%d_tcp_v6 size %d { ip6 saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("connlimit per-ip v6 tcp rule failed: %w", err)
			}
		case "udp":
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood ip protocol udp ct state new udp dport %d "+
					"meter cl_%d_udp_v4 size %d { ip saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("connlimit per-ip v4 udp rule failed: %w", err)
			}
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr udp ct state new udp dport %d "+
					"meter cl_%d_udp_v6 size %d { ip6 saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("connlimit per-ip v6 udp rule failed: %w", err)
			}
		default:
			return fmt.Errorf("unknown proto %q in CONNLIMIT", r.Proto)
		}
	}
	return nil
}

func (b *Backend) listSetsWithPrefix(prefix string) []string {
	var out []string
	switch prefix {
	case "th_pf_":
		out = append(out, b.pfSets...)
	case "cl_":
		out = append(out, b.clSets...)
	}
	return out
}
