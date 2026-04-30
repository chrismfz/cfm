package nft

import (
	cfgpkg "cfm/internal/config"
	"time"
)

// floodCfgHash returns a cheap hash of all flood-relevant config fields.
// If the hash is identical to the previous tick we skip the full rebuild.
func floodCfgHash(c *cfgpkg.Config) uint64 {
	if c == nil {
		return 0
	}
	h := fnv64(0,
		uint64(c.PacketRate.Rate),
		uint64(c.PacketRate.Burst),
		hashStr(c.PacketRate.Mode),
		boolU64(c.Hardening.BlockBadTCPFlags),
		uint64(c.Hardening.NewRate),
		uint64(c.Hardening.ICMPRate),
		uint64(len(c.Connlimit.Rules)),
		uint64(len(c.PortFlood.Rules)),
		uint64(c.NFT.InputPriority),
	)
	for _, r := range c.Connlimit.Rules {
		h = fnv64(h, uint64(r.Port), uint64(r.Limit), hashStr(r.Proto))
	}
	for _, r := range c.PortFlood.Rules {
		h = fnv64(h, uint64(r.Port), uint64(r.Packets), uint64(r.WindowSec), hashStr(r.Proto))
	}
	return h
}

func fnv64(h uint64, vals ...uint64) uint64 {
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

func hashStr(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func boolU64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (b *Backend) ApplyFloodRules(c *cfgpkg.Config) error {
	b.cfg = c
	const meterRefreshInterval = 15 * time.Minute
	h := floodCfgHash(c)
	if h != 0 && h == b.lastFloodHash && b.tableExists() {
		if !b.lastFloodRebuild.IsZero() && time.Since(b.lastFloodRebuild) < meterRefreshInterval {
			return nil
		}
	}
	b.lastFloodHash = h
	if !b.tableExists() {
		if err := b.EnsureBase(); err != nil {
			return err
		}
	}
	_ = b.nftExpr("flush chain inet cfm flood;")
	_ = b.nftExpr(`add rule inet cfm flood ip saddr @self_v4 return`)
	_ = b.nftExpr(`add rule inet cfm flood ip6 saddr @self_v6 return`)
	b.ensureThrottleSets()
	if err := b.ApplyHardeningRules(c); err != nil {
		return err
	}
	if c.PacketRate.Rate > 0 {
		burst := c.PacketRate.Burst
		if burst <= 0 {
			burst = c.PacketRate.Rate * 2
		}
		if err := b.applyPerIPRateLimit(c.PacketRate.Rate, burst, c.PacketRate.Mode); err != nil {
			return err
		}
	}
	if err := b.ApplyConnlimit(c.Connlimit.Rules); err != nil {
		return err
	}
	if err := b.ApplyPortFlood(c.PortFlood.Rules); err != nil {
		return err
	}
	b.lastFloodRebuild = time.Now()
	return nil
}

func (b *Backend) ensureThrottleSets() {
	_ = b.nftExpr("add set inet cfm th_syn_v4 { type ipv4_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_syn_v6 { type ipv6_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_pps_v4 { type ipv4_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_pps_v6 { type ipv6_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_pf_tcp_v4 { type ipv4_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_pf_tcp_v6 { type ipv6_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_pf_udp_v4 { type ipv4_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm th_pf_udp_v6 { type ipv6_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm throttled_v4 { type ipv4_addr; flags timeout; }")
	_ = b.nftExpr("add set inet cfm throttled_v6 { type ipv6_addr; flags timeout; }")
}
