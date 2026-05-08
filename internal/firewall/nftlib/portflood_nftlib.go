//go:build linux

package nftlib

import (
	"fmt"
	"math"
	"strings"
	"time"

	"cfm/internal/config"
)

func nftlibMapRate(max, intervalSec int) (int, string) {
	if intervalSec <= 0 {
		intervalSec = 60
	}
	for _, u := range []struct {
		name string
		sec  int
	}{{"day", 86400}, {"hour", 3600}, {"minute", 60}, {"second", 1}} {
		if intervalSec%u.sec == 0 {
			n := int(math.Ceil(float64(max) / float64(intervalSec/u.sec)))
			if n < 1 {
				n = 1
			}
			return n, u.name
		}
	}
	return max, "second"
}

func (b *Backend) ApplyPortFlood(rules []config.PortFloodRule) (err error) {
	start := time.Now()
	b.logPhase("ApplyPortFlood", "start", 0, nil, fmt.Sprintf("rules=%d", len(rules)))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("ApplyPortFlood", st, time.Since(start), err, fmt.Sprintf("rules=%d", len(rules)))
	}()
	ttl := 60
	if b.cfg != nil && b.cfg.Throttle.SetTTL > 0 {
		ttl = b.cfg.Throttle.SetTTL
	}
	for _, r := range rules {
		proto := strings.ToLower(r.Proto)
		cname := fmt.Sprintf("portflood_%d_%s", r.Port, proto)
		b.ensureCounterCLI(cname)

		setV4 := fmt.Sprintf("th_pf_%d_%s_v4", r.Port, proto)
		setV6 := fmt.Sprintf("th_pf_%d_%s_v6", r.Port, proto)
		_ = b.nftExec(fmt.Sprintf("add set inet cfm %s { type ipv4_addr; flags timeout; }", setV4))
		_ = b.nftExec(fmt.Sprintf("add set inet cfm %s { type ipv6_addr; flags timeout; }", setV6))

		num, unit := nftlibMapRate(r.Packets, r.WindowSec)
		switch proto {
		case "tcp":
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV4, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood tcp v4: %w", err)
			}
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV6, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood tcp v6: %w", err)
			}
		case "udp":
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV4, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood udp v4: %w", err)
			}
			if err := b.nftExec(fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\"",
				r.Port, r.Port, num, unit, r.Packets, setV6, ttl, cname, r.Port, r.WindowSec, r.Packets,
			)); err != nil {
				return fmt.Errorf("portflood udp v6: %w", err)
			}
		default:
			return fmt.Errorf("unknown proto %q in PORTFLOOD", r.Proto)
		}
	}
	return nil
}
