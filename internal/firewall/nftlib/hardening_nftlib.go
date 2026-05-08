//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/config"
	"github.com/google/nftables/expr"
)

// hardeningRuleSnapshot is a compatibility snapshot used by parity tests to
// validate logical rule intent without relying on nft expression internals.
type hardeningRuleSnapshot struct {
	Chain   string
	Path    string
	Verdict expr.VerdictKind
}

func (b *Backend) ApplyHardeningRules(c *config.Config) (err error) {
	start := time.Now()
	b.logPhase("ApplyHardeningRules", "start", 0, nil, "")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyHardeningRules", st, time.Since(start), err, "")
	}()
	if c == nil {
		return nil
	}

	if c.Hardening.BlockBadTCPFlags {
		b.ensureCounterCLI("badflags_drop")
		for _, r := range []string{
			`add rule inet cfm flood tcp flags & (syn|fin) == (syn|fin) counter name "badflags_drop" drop comment "SYN+FIN"`,
			`add rule inet cfm flood tcp flags & (syn|rst) == (syn|rst) counter name "badflags_drop" drop comment "SYN+RST"`,
			`add rule inet cfm flood tcp flags & (fin|psh|urg) == (fin|psh|urg) counter name "badflags_drop" drop comment "XMAS"`,
			`add rule inet cfm flood tcp flags & (fin|psh|urg|rst|syn|ack) == 0 counter name "badflags_drop" drop comment "NULL"`,
		} {
			if err := b.nftExec(r); err != nil {
				return err
			}
		}
	}

	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}

	if c.Hardening.NewRate > 0 {
		b.ensureCounterCLI("newrate_v4")
		b.ensureCounterCLI("newrate_v6")
		_ = b.nftExec("add set inet cfm th_new_v4 { type ipv4_addr; flags timeout; }")
		_ = b.nftExec("add set inet cfm th_new_v6 { type ipv6_addr; flags timeout; }")

		burstNew := c.Hardening.NewBurst
		if burstNew <= 0 {
			burstNew = c.Hardening.NewRate
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ct state new ip protocol != icmp `+
				`meter new_v4 { ip saddr limit rate over %d/second burst %d packets } `+
				`add @th_new_v4 { ip saddr timeout %ds } `+
				`add @throttled_v4 { ip saddr timeout %ds } `+
				`counter name "newrate_v4" drop comment "global-new-v4(no-icmp)"`,
			c.Hardening.NewRate, burstNew, ttl, ttl,
		)); err != nil {
			return err
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ct state new ip6 nexthdr != ipv6-icmp `+
				`meter new_v6 { ip6 saddr limit rate over %d/second burst %d packets } `+
				`add @th_new_v6 { ip6 saddr timeout %ds } `+
				`add @throttled_v6 { ip6 saddr timeout %ds } `+
				`counter name "newrate_v6" drop comment "global-new-v6(no-icmp6)"`,
			c.Hardening.NewRate, burstNew, ttl, ttl,
		)); err != nil {
			return err
		}
	}

	if c.Hardening.ICMPRate > 0 {
		b.ensureCounterCLI("icmp_v4")
		b.ensureCounterCLI("icmp_v6")
		_ = b.nftExec("add set inet cfm th_icmp_v4 { type ipv4_addr; flags timeout; }")
		_ = b.nftExec("add set inet cfm th_icmp_v6 { type ipv6_addr; flags timeout; }")

		burstICMP := c.Hardening.ICMPBurst
		if burstICMP <= 0 {
			burstICMP = c.Hardening.ICMPRate * 2
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ip protocol icmp icmp type echo-request `+
				`meter icmp4 { ip saddr limit rate over %d/second burst %d packets } `+
				`add @th_icmp_v4 { ip saddr timeout %ds } `+
				`counter name "icmp_v4" drop comment "icmp-echo-limit"`,
			c.Hardening.ICMPRate, burstICMP, ttl,
		)); err != nil {
			return err
		}
		if err := b.nftExec(fmt.Sprintf(
			`add rule inet cfm flood ip6 nexthdr ipv6-icmp icmpv6 type echo-request `+
				`meter icmp6 { ip6 saddr limit rate over %d/second burst %d packets } `+
				`add @th_icmp_v6 { ip6 saddr timeout %ds } `+
				`counter name "icmp_v6" drop comment "icmp6-echo-limit"`,
			c.Hardening.ICMPRate, burstICMP, ttl,
		)); err != nil {
			return err
		}
	}

	return nil
}

// buildHardeningRuleSnapshots snapshots hardening rule intent for parity tests.
func buildHardeningRuleSnapshots(c *config.Config) []hardeningRuleSnapshot {
	if c == nil {
		return nil
	}
	out := make([]hardeningRuleSnapshot, 0, 8)
	if c.Hardening.BlockBadTCPFlags {
		out = append(out,
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.syn_fin", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.syn_rst", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.xmas", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "tcp.flags.null", Verdict: expr.VerdictDrop},
		)
	}
	if c.Hardening.NewRate > 0 {
		out = append(out,
			hardeningRuleSnapshot{Chain: "flood", Path: "ct.new.no_icmp.v4_over_rate", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "ct.new.no_icmp.v6_over_rate", Verdict: expr.VerdictDrop},
		)
	}
	if c.Hardening.ICMPRate > 0 {
		out = append(out,
			hardeningRuleSnapshot{Chain: "flood", Path: "icmp.echo.v4_over_rate", Verdict: expr.VerdictDrop},
			hardeningRuleSnapshot{Chain: "flood", Path: "icmp.echo.v6_over_rate", Verdict: expr.VerdictDrop},
		)
	}
	return out
}
