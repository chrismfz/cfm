//go:build linux

package nftlib

import (
	"fmt"
	"strings"
	"time"

	"cfm/internal/config"
	"github.com/google/nftables/expr"
)

const meterRefreshInterval = 15 * time.Minute

var throttleSetEnsureCmds = []string{
	"add set inet cfm th_syn_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_syn_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm th_pps_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_pps_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm th_pf_tcp_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_pf_tcp_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm th_pf_udp_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm th_pf_udp_v6 { type ipv6_addr; flags timeout; }",
	"add set inet cfm throttled_v4 { type ipv4_addr; flags timeout; }",
	"add set inet cfm throttled_v6 { type ipv6_addr; flags timeout; }",
}

func floodCfgHash(c *config.Config) uint64 {
	if c == nil {
		return 0
	}
	h := nftlibFnv64(0,
		uint64(c.PacketRate.Rate), uint64(c.PacketRate.Burst),
		nftlibHashStr(c.PacketRate.Mode),
		nftlibBoolU64(c.Hardening.BlockBadTCPFlags),
		uint64(c.Hardening.NewRate), uint64(c.Hardening.ICMPRate),
		uint64(len(c.Connlimit.Rules)), uint64(len(c.PortFlood.Rules)),
		uint64(c.NFT.InputPriority),
	)
	for _, r := range c.Connlimit.Rules {
		h = nftlibFnv64(h, uint64(r.Port), uint64(r.Limit), nftlibHashStr(r.Proto))
	}
	for _, r := range c.PortFlood.Rules {
		h = nftlibFnv64(h, uint64(r.Port), uint64(r.Packets), uint64(r.WindowSec), nftlibHashStr(r.Proto))
	}
	return h
}

func nftlibFnv64(h uint64, vals ...uint64) uint64 {
	const prime = 1099511628211
	if h == 0 {
		h = 14695981039346656037
	}
	for _, v := range vals {
		h ^= v
		h *= prime
	}
	return h
}

func nftlibHashStr(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func nftlibBoolU64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (b *Backend) ApplyFloodRules(c *config.Config) (err error) {
	start := time.Now()
	connRules := 0
	pfRules := 0
	if c != nil {
		connRules = len(c.Connlimit.Rules)
		pfRules = len(c.PortFlood.Rules)
	}
	b.logPhase("ApplyFloodRules", "start", 0, nil, fmt.Sprintf("connlimit_rules=%d portflood_rules=%d", connRules, pfRules))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyFloodRules", st, time.Since(start), err, fmt.Sprintf("connlimit_rules=%d portflood_rules=%d", connRules, pfRules))
	}()
	b.cfg = c

	h := floodCfgHash(c)
	if h != 0 && h == b.lastFloodHash {
		b.mu.Lock()
		_, tableErr := b.lookupTable()
		b.mu.Unlock()
		floodChainPresent := b.chainExistsCLI("flood")
		if shouldSkipFloodRebuild(tableErr == nil, floodChainPresent, b.lastFloodRebuild, time.Now()) {
			return nil
		}
	}
	b.lastFloodHash = h

	b.mu.Lock()
	_, tableErr := b.lookupTable()
	b.mu.Unlock()
	if tableErr != nil {
		if err = b.EnsureBase(); err != nil {
			return err
		}
	}

	_ = b.nftExec("flush chain inet cfm flood")
	_ = b.nftExec("add rule inet cfm flood ip saddr @self_v4 return")
	_ = b.nftExec("add rule inet cfm flood ip6 saddr @self_v6 return")

	b.ensureThrottleSetsCLI()

	if c == nil {
		return nil
	}
	if err = b.ApplyHardeningRules(c); err != nil {
		return err
	}
	if c.PacketRate.Rate > 0 {
		burst := c.PacketRate.Burst
		if burst <= 0 {
			burst = c.PacketRate.Rate * 2
		}
		if err = b.applyPerIPRateLimitCLI(c.PacketRate.Rate, burst, c.PacketRate.Mode); err != nil {
			return err
		}
	}
	if err = b.ApplyConnlimit(c.Connlimit.Rules); err != nil {
		return err
	}
	if err = b.ApplyPortFlood(c.PortFlood.Rules); err != nil {
		return err
	}
	b.lastFloodRebuild = time.Now()
	return nil
}

func shouldSkipFloodRebuild(tablePresent, floodChainPresent bool, lastRebuild, now time.Time) bool {
	if !tablePresent || !floodChainPresent || lastRebuild.IsZero() {
		return false
	}
	return now.Sub(lastRebuild) < meterRefreshInterval
}

func (b *Backend) ensureThrottleSetsCLI() {
	for _, s := range throttleSetEnsureCmds {
		_ = b.nftExec(s)
	}
}

func perIPRateLimitCmds(rate, burst, ttl int, mode string) []string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "all":
		return []string{
			fmt.Sprintf(
				"add rule inet cfm flood meter pps_v4 { ip saddr limit rate over %d/second burst %d packets } "+
					"add @th_pps_v4 { ip saddr timeout %ds } "+
					"add @throttled_v4 { ip saddr timeout %ds } "+
					"counter name ppsrate_v4 drop comment \"per-ip pps rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
			fmt.Sprintf(
				"add rule inet cfm flood meter pps_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
					"add @th_pps_v6 { ip6 saddr timeout %ds } "+
					"add @throttled_v6 { ip6 saddr timeout %ds } "+
					"counter name ppsrate_v6 drop comment \"per-ip pps rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
		}
	default:
		return []string{
			fmt.Sprintf(
				"add rule inet cfm flood tcp flags syn meter syn_v4 { ip saddr limit rate over %d/second burst %d packets } "+
					"add @th_syn_v4 { ip saddr timeout %ds } "+
					"add @throttled_v4 { ip saddr timeout %ds } "+
					"counter name synrate_v4 drop comment \"per-ip syn rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
			fmt.Sprintf(
				"add rule inet cfm flood tcp flags syn meter syn_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
					"add @th_syn_v6 { ip6 saddr timeout %ds } "+
					"add @throttled_v6 { ip6 saddr timeout %ds } "+
					"counter name synrate_v6 drop comment \"per-ip syn rate %d/%d\"",
				rate, burst, ttl, ttl, rate, burst,
			),
		}
	}
}

func (b *Backend) applyPerIPRateLimitCLI(rate, burst int, mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}
	switch mode {
	case "all":
		b.ensureCounterCLI("ppsrate_v4")
		cmds := perIPRateLimitCmds(rate, burst, ttl, mode)
		if err := b.nftExec(cmds[0]); err != nil {
			return err
		}
		b.ensureCounterCLI("ppsrate_v6")
		if err := b.nftExec(cmds[1]); err != nil {
			return err
		}
	default: // "syn"
		b.ensureCounterCLI("synrate_v4")
		cmds := perIPRateLimitCmds(rate, burst, ttl, mode)
		if err := b.nftExec(cmds[0]); err != nil {
			return err
		}
		b.ensureCounterCLI("synrate_v6")
		if err := b.nftExec(cmds[1]); err != nil {
			return err
		}
	}
	return nil
}

// buildFloodVerdictPlan returns the planned verdict kind for each flood-path
// rule in order. Consumed by parity tests.
func buildFloodVerdictPlan(c *config.Config) ([]expr.VerdictKind, error) {
	if c == nil {
		return nil, nil
	}
	snaps := buildHardeningRuleSnapshots(c)
	out := make([]expr.VerdictKind, 0, len(snaps)+len(c.Connlimit.Rules)+len(c.PortFlood.Rules))
	for _, s := range snaps {
		out = append(out, s.Verdict)
	}
	for _, r := range c.Connlimit.Rules {
		proto := strings.ToLower(strings.TrimSpace(r.Proto))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("unknown proto %q", r.Proto)
		}
		out = append(out, expr.VerdictDrop)
	}
	for range c.PortFlood.Rules {
		out = append(out, expr.VerdictDrop)
	}
	return out, nil
}
