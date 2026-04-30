//go:build linux

package nftlib

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"cfm/internal/config"
)

func (b *Backend) ApplyOutboundObserve(cfg *config.OutboundConfig) error {
	if cfg == nil || !cfg.Enabled || cfg.NFLOGGroup <= 0 {
		_ = b.nftExec("delete chain inet cfm cfm_outbound_observe")
		return nil
	}

	_ = b.nftExec("add table inet cfm")
	if !b.chainExistsCLI("cfm_outbound_observe") {
		if err := b.nftExec(
			"add chain inet cfm cfm_outbound_observe { type filter hook output priority 10; policy accept; }",
		); err != nil {
			return err
		}
	}
	_ = b.nftExec("flush chain inet cfm cfm_outbound_observe")

	for _, rule := range nftlibOutboundObserveSelectionRules(cfg) {
		_ = b.nftExec(rule)
	}
	for _, ports := range nftlibOutboundObservePortGroups(cfg) {
		_ = b.nftExec(nftlibOutboundObservePortGroupRule(cfg.NFLOGGroup, ports))
	}
	return nil
}

func nftlibOutboundObserveSelectionRules(cfg *config.OutboundConfig) []string {
	rules := []string{"add rule inet cfm cfm_outbound_observe meta skuid 0 return"}
	if uids := nftlibSortedU32(cfg.AllowUIDs); len(uids) > 0 {
		rules = append(rules, fmt.Sprintf(
			"add rule inet cfm cfm_outbound_observe meta skuid { %s } return",
			strings.Join(uids, ", "),
		))
	}
	if gids := nftlibSortedU32(cfg.AllowGIDs); len(gids) > 0 {
		rules = append(rules, fmt.Sprintf(
			"add rule inet cfm cfm_outbound_observe meta skgid { %s } return",
			strings.Join(gids, ", "),
		))
	}
	return rules
}

func nftlibOutboundObservePortGroups(cfg *config.OutboundConfig) []string {
	groups := make([]string, 0, 3)
	for _, ports := range []string{
		nftlibJoinPorts(cfg.SMTPPorts, []uint16{25, 465, 587}),
		nftlibJoinPorts(cfg.ScanPorts, []uint16{22, 23, 3389}),
		nftlibJoinPorts(cfg.HTTPPorts, []uint16{80, 443, 8080, 8443}),
	} {
		if ports != "" {
			groups = append(groups, ports)
		}
	}
	return groups
}

func nftlibOutboundObservePortGroupRule(group int, ports string) string {
	return fmt.Sprintf(
		`add rule inet cfm cfm_outbound_observe ct state new tcp dport { %s } log prefix "CFM_OUT: " group %d snaplen 96`,
		ports, group,
	)
}

func nftlibJoinPorts(ports, defaults []uint16) string {
	use := ports
	if len(use) == 0 {
		use = defaults
	}
	if len(use) == 0 {
		return ""
	}
	use = append([]uint16(nil), use...)
	sort.Slice(use, func(i, j int) bool { return use[i] < use[j] })
	out := make([]string, 0, len(use))
	for _, p := range use {
		if p != 0 {
			out = append(out, strconv.FormatUint(uint64(p), 10))
		}
	}
	return strings.Join(out, ", ")
}
func nftlibSortedU32(ids []uint32) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	uniq := make([]uint32, 0, len(seen))
	for id := range seen {
		uniq = append(uniq, id)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i] < uniq[j] })
	s := make([]string, len(uniq))
	for i, v := range uniq {
		s[i] = strconv.FormatUint(uint64(v), 10)
	}
	return s
}
