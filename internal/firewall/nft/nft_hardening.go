package nft

import (
	"fmt"

	cfgpkg "cfm/internal/config"
)

// ApplyHardeningRules installs global hardening rules into the 'flood' chain.
// It is called early from ApplyFloodRules(), after throttle sets exist.
// The rules below are config-driven (Config.Hardening).
func (b *Backend) ApplyHardeningRules(c *cfgpkg.Config) error {
	// --- Counters & sets (created only if needed). We ignore errors on add to keep idempotency. ---

	// Bad TCP flags counter
	if c.Hardening.BlockBadTCPFlags {
		_ = b.nftExpr(`add counter inet cfm badflags_drop`)
	}

	// NEW-rate: counters + per-source tracking sets (for logging / autoblock)
	if c.Hardening.NewRate > 0 {
		_ = b.nftExpr(`add counter inet cfm newrate_v4`)
		_ = b.nftExpr(`add counter inet cfm newrate_v6`)
		_ = b.nftExpr(`add set inet cfm th_new_v4 { type ipv4_addr; flags timeout; }`)
		_ = b.nftExpr(`add set inet cfm th_new_v6 { type ipv6_addr; flags timeout; }`)
	}

	// ICMP echo: counters + per-source tracking sets (for logging / autoblock)
	if c.Hardening.ICMPRate > 0 {
		_ = b.nftExpr(`add counter inet cfm icmp_v4`)
		_ = b.nftExpr(`add counter inet cfm icmp_v6`)
		_ = b.nftExpr(`add set inet cfm th_icmp_v4 { type ipv4_addr; flags timeout; }`)
		_ = b.nftExpr(`add set inet cfm th_icmp_v6 { type ipv6_addr; flags timeout; }`)
	}

	// --- 1) Bad TCP flags (placed early in 'flood') ---
	if c.Hardening.BlockBadTCPFlags {
		badflags := []string{
			// NEW without SYN: drop ACK in ct state NEW (prevents some scan tricks)
			`add rule inet cfm flood ct state new tcp flags & ack == ack counter name "badflags_drop" drop comment "new-without-SYN"`,
			// SYN+FIN (illegal)
			`add rule inet cfm flood tcp flags & (syn|fin) == (syn|fin) counter name "badflags_drop" drop comment "SYN+FIN"`,
			// SYN+RST (illegal)
			`add rule inet cfm flood tcp flags & (syn|rst) == (syn|rst) counter name "badflags_drop" drop comment "SYN+RST"`,
			// XMAS: FIN+PSH+URG
			`add rule inet cfm flood tcp flags & (fin|psh|urg) == (fin|psh|urg) counter name "badflags_drop" drop comment "XMAS"`,
			// NULL: no flags set at all
			`add rule inet cfm flood tcp flags & (fin|psh|urg|rst|syn|ack) == 0 counter name "badflags_drop" drop comment "NULL"`,
		}
		for _, r := range badflags {
			if err := b.nftExpr(r); err != nil { return err }
		}
	}

	// --- Tuning helpers ---
	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}
	burstNew := c.Hardening.NewBurst
	if burstNew <= 0 {
		burstNew = c.Hardening.NewRate // small, sane default burst = rate
	}
	burstICMP := c.Hardening.ICMPBurst
	if burstICMP <= 0 {
		burstICMP = c.Hardening.ICMPRate * 2
	}

	// --- 2) Global per-IP NEW-rate (meters) ---
	// If a source exceeds NEW_RATE (with burst), drop + mark in th_new_* and throttled_*
	if c.Hardening.NewRate > 0 {
		expr4 := fmt.Sprintf(
			`add rule inet cfm flood ct state new `+
				`meter new_v4 { ip saddr limit rate over %d/second burst %d packets } `+
				`add @th_new_v4 { ip saddr timeout %ds } `+
				`add @throttled_v4 { ip saddr timeout %ds } `+
				`counter name "newrate_v4" drop comment "global-new-v4"`,
			c.Hardening.NewRate, burstNew, ttl, ttl,
		)
		if err := b.nftExpr(expr4); err != nil { return err }

		expr6 := fmt.Sprintf(
			`add rule inet cfm flood ct state new `+
				`meter new_v6 { ip6 saddr limit rate over %d/second burst %d packets } `+
				`add @th_new_v6 { ip6 saddr timeout %ds } `+
				`add @throttled_v6 { ip6 saddr timeout %ds } `+
				`counter name "newrate_v6" drop comment "global-new-v6"`,
			c.Hardening.NewRate, burstNew, ttl, ttl,
		)
		if err := b.nftExpr(expr6); err != nil { return err }
	}

	// --- 3) ICMP/ICMPv6 echo-request per-IP (meters) ---
	// If a source exceeds ICMP_RATE_LIMIT (with burst), drop + mark in th_icmp_*
	if c.Hardening.ICMPRate > 0 {
		exprI4 := fmt.Sprintf(
			`add rule inet cfm flood ip protocol icmp icmp type echo-request `+
				`meter icmp4 { ip saddr limit rate over %d/second burst %d packets } `+
				`add @th_icmp_v4 { ip saddr timeout %ds } `+
				`counter name "icmp_v4" drop comment "icmp-echo-limit"`,
			c.Hardening.ICMPRate, burstICMP, ttl,
		)
		if err := b.nftExpr(exprI4); err != nil { return err }

		// nftables syntax for IPv6 next header is 'ipv6-icmp'
		exprI6 := fmt.Sprintf(
			`add rule inet cfm flood ip6 nexthdr ipv6-icmp icmpv6 type echo-request `+
				`meter icmp6 { ip6 saddr limit rate over %d/second burst %d packets } `+
				`add @th_icmp_v6 { ip6 saddr timeout %ds } `+
				`counter name "icmp_v6" drop comment "icmp6-echo-limit"`,
			c.Hardening.ICMPRate, burstICMP, ttl,
		)
		if err := b.nftExpr(exprI6); err != nil { return err }
	}

	return nil
}
