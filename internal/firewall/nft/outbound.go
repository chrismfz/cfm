// internal/firewall/nft/outbound.go
package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	cfgpkg "cfm/internal/config"
)

// ApplyOutboundObserve installs (or removes) the cfm_outbound_observe chain.
//
// Phase-1 contract: this chain is OBSERVE-ONLY — it never drops or rejects.
// It NFLOGs new outbound connections in three port groups (SMTP / SCAN / HTTP)
// so the user-space outbound collector can classify traffic per uid. Root
// traffic is excluded at the kernel level so
// cfm itself, system services, and exim's own outbound delivery don't dominate
// the signal.
//
// Why a separate chain (not a rule appended to an existing one):
//   - Idempotent rebuild on config reload (flush + repopulate this chain).
//   - Keeps observe rules visibly grouped for operators (`nft list chain
//     inet cfm cfm_outbound_observe`).
//   - Phase 2 will add a sibling cfm_outbound_enforce chain for throttle/drop;
//     this name reservation matters now.
func (b *Backend) ApplyOutboundObserve(cfg *cfgpkg.OutboundConfig) error {
	if cfg == nil || !cfg.Enabled || cfg.NFLOGGroup <= 0 {
		// Best-effort cleanup if previously installed.
		_ = b.nftExpr(`delete chain inet cfm cfm_outbound_observe`)
		return nil
	}

	_ = b.nftExpr(`add table inet cfm`)

	if !b.chainExists("cfm_outbound_observe") {
		// priority 10 sits AFTER smtpblock (-100) so an SMTP-blocked packet
		// gets denied first and we never NFLOG something that's already being
		// rejected. policy accept — this chain never makes a decision.
		if err := b.nftCmd(`add chain inet cfm cfm_outbound_observe { type filter hook output priority 10; policy accept; }`); err != nil {
			return err
		}
	}
	_ = b.nftExpr(`flush chain inet cfm cfm_outbound_observe`)

	group := cfg.NFLOGGroup
	logSuffix := fmt.Sprintf(`log prefix "CFM_OUT: " group %d snaplen 96`, group)

	// Skip root + explicit allow lists at the kernel boundary so we don't
	// burn netlink bandwidth on traffic the analyzer would discard anyway.
	_ = b.nftExpr(`add rule inet cfm cfm_outbound_observe meta skuid 0 return`)
	if uids := sortedU32(cfg.AllowUIDs); len(uids) > 0 {
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm cfm_outbound_observe meta skuid { %s } return`, strings.Join(uids, ", ")))
	}
	if gids := sortedU32(cfg.AllowGIDs); len(gids) > 0 {
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm cfm_outbound_observe meta skgid { %s } return`, strings.Join(gids, ", ")))
	}

	// SMTP / SCAN / HTTP: TCP, only ct state new (connection establishment).
	smtp := joinPorts(cfg.SMTPPorts, []uint16{25, 465, 587})
	scan := joinPorts(cfg.ScanPorts, []uint16{22, 23, 3389})
	http := joinPorts(cfg.HTTPPorts, []uint16{80, 443, 8080, 8443})

	if smtp != "" {
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm cfm_outbound_observe ct state new tcp dport { %s } %s`, smtp, logSuffix))
	}
	if scan != "" {
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm cfm_outbound_observe ct state new tcp dport { %s } %s`, scan, logSuffix))
	}
	if http != "" {
		_ = b.nftExpr(fmt.Sprintf(`add rule inet cfm cfm_outbound_observe ct state new tcp dport { %s } %s`, http, logSuffix))
	}

	return nil
}

// joinPorts returns "p1, p2, ..." for nft anonymous set syntax. Falls back to
// `defaults` if `ports` is empty/nil. Returns "" only if both are empty.
func joinPorts(ports, defaults []uint16) string {
	use := ports
	if len(use) == 0 {
		use = defaults
	}
	if len(use) == 0 {
		return ""
	}
	sort.Slice(use, func(i, j int) bool { return use[i] < use[j] })
	out := make([]string, 0, len(use))
	for _, p := range use {
		if p == 0 {
			continue
		}
		out = append(out, strconv.FormatUint(uint64(p), 10))
	}
	return strings.Join(out, ", ")
}

// sortedU32 returns ids as a deduplicated, sorted slice of decimal strings.
func sortedU32(ids []uint32) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	out := make([]uint32, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	s := make([]string, len(out))
	for i, v := range out {
		s[i] = strconv.FormatUint(uint64(v), 10)
	}
	return s
}
