package nft

import (
	cfgpkg "cfm/internal/config"
	"fmt"
	"math"
	"strings"
	"time"
)

func mapRate(packets, windowSec int) (int, string) {
	if windowSec <= 0 {
		windowSec = 1
	}
	if windowSec < 60 {
		ratePerSecond := int(math.Ceil(float64(packets) / float64(windowSec)))
		if ratePerSecond < 1 {
			ratePerSecond = 1
		}
		return ratePerSecond, "second"
	}
	ratePerMinute := int(math.Ceil(float64(packets) / float64(windowSec) * 60.0))
	if ratePerMinute < 1 {
		ratePerMinute = 1
	}
	return ratePerMinute, "minute"
}

// floodCfgHash returns a cheap hash of all flood-relevant config fields.
// If the hash is identical to the previous tick we skip the full rebuild.
// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
// listSetsWithPrefix lists set names in table 'inet cfm' that start with the given prefix.

// listSetsWithPrefix: φτιάχνει τα ονόματα από το in-memory registry· κανένα nft call.
func (b *Backend) ApplyPortFlood(rules []cfgpkg.PortFloodRule) (err error) {
	start := time.Now()
	b.logPhase("ApplyPortFlood", "start", 0, nil, fmt.Sprintf("rules=%d", len(rules)))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyPortFlood", st, time.Since(start), err, fmt.Sprintf("rules=%d", len(rules)))
	}()
	for _, r := range rules {
		proto := strings.ToLower(r.Proto)
		cname := fmt.Sprintf("portflood_%d_%s", r.Port, proto)
		b.ensureCounter(cname)

		// Per-port dynamic sets so we can see the port in [throttle] logs
		setV4 := fmt.Sprintf("th_pf_%d_%s_v4", r.Port, proto)
		setV6 := fmt.Sprintf("th_pf_%d_%s_v6", r.Port, proto)
		_ = b.nftExpr(fmt.Sprintf("add set inet cfm %s { type ipv4_addr; flags timeout; }", setV4))
		_ = b.nftExpr(fmt.Sprintf("add set inet cfm %s { type ipv6_addr; flags timeout; }", setV6))

		num, unit := mapRate(r.Packets, r.WindowSec)
		ttl := b.cfg.Throttle.SetTTL

		b.registerPfSet(setV4)
		b.registerPfSet(setV6)

		switch proto {
		case "tcp":
			// IPv4
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Packets, setV4, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("portflood v4 tcp failed: %w", err)
			}
			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Packets, setV6, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("portflood v6 tcp failed: %w", err)
			}

		case "udp":
			// IPv4
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Packets, setV4, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("portflood v4 udp failed: %w", err)
			}
			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Packets, setV6, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("portflood v6 udp failed: %w", err)
			}

		default:
			return fmt.Errorf("unknown proto %q in PORTFLOOD", r.Proto)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Debug/telemetry
// -----------------------------------------------------------------------------
// DumpFloodCounters logs flood-related counters with delta since last tick.
