// Package autoblock provides the sliding-window hit counter that drives
// automatic IP blocking decisions. It is engine-neutral: both the nft (cli)
// and nftlib (netlink) backends instantiate an Evaluator and supply their own
// BlockAction callback for the actual kernel write.
package autoblock

import (
	"strings"
	"time"

	cfgpkg "cfm/internal/config"
)

// BlockAction is called when an IP crosses the auto-block threshold.
// ip is the source address, fam is "v4" or "v6", reason is the
// throttle/portscan reason string. The implementation handles the kernel
// write, logging, debouncing, and reporting.
type BlockAction func(ip, fam, reason string, tc cfgpkg.ThrottleConfig) error

// Evaluator tracks per-IP hit counts within a sliding window and fires a
// BlockAction when an IP exceeds the configured threshold.
//
// NOT goroutine-safe. Callers serialise access with their own overlap guards
// (the same mutex that prevents concurrent DumpFloodCounters / LoadPortScanner
// goroutines from running simultaneously).
type Evaluator struct {
	thV4Hits  map[string][]time.Time
	thV6Hits  map[string][]time.Time
	evalCount int

	// Reasons maps ip → the most-recent throttle/portscan reason string.
	// Callers write it before Eval; the BlockAction receives it as a parameter.
	Reasons map[string]string
}

// New returns a ready Evaluator.
func New() *Evaluator {
	return &Evaluator{
		thV4Hits: make(map[string][]time.Time),
		thV6Hits: make(map[string][]time.Time),
		Reasons:  make(map[string]string),
	}
}

// Eval updates the sliding window for each IP in v4/v6 and calls action for
// every IP that reaches tc.Hits within tc.WindowSec. Hit maps are pruned
// every 500 calls to prevent unbounded growth on busy servers.
func (e *Evaluator) Eval(v4, v6 []string, tc cfgpkg.ThrottleConfig, action BlockAction) {
	e.evalCount++
	if e.evalCount%500 == 0 {
		e.pruneHitMaps(time.Duration(tc.WindowSec) * time.Second)
	}

	now := time.Now()
	window := time.Duration(tc.WindowSec) * time.Second

	for _, ip := range v4 {
		e.thV4Hits[ip] = append(e.thV4Hits[ip], now)
		e.thV4Hits[ip] = pruneOld(e.thV4Hits[ip], now.Add(-window))
		if len(e.thV4Hits[ip]) >= tc.Hits {
			_ = action(ip, "v4", e.Reasons[ip], tc)
			delete(e.thV4Hits, ip)
		}
	}
	for _, ip := range v6 {
		e.thV6Hits[ip] = append(e.thV6Hits[ip], now)
		e.thV6Hits[ip] = pruneOld(e.thV6Hits[ip], now.Add(-window))
		if len(e.thV6Hits[ip]) >= tc.Hits {
			_ = action(ip, "v6", e.Reasons[ip], tc)
			delete(e.thV6Hits, ip)
		}
	}
}

// pruneHitMaps removes stale entries from the hit maps and the Reasons cache.
func (e *Evaluator) pruneHitMaps(window time.Duration) {
	cutoff := time.Now().Add(-window)
	for ip, ts := range e.thV4Hits {
		pruned := pruneOld(ts, cutoff)
		if len(pruned) == 0 {
			delete(e.thV4Hits, ip)
		} else {
			e.thV4Hits[ip] = pruned
		}
	}
	for ip, ts := range e.thV6Hits {
		pruned := pruneOld(ts, cutoff)
		if len(pruned) == 0 {
			delete(e.thV6Hits, ip)
		} else {
			e.thV6Hits[ip] = pruned
		}
	}
	for ip := range e.Reasons {
		_, in4 := e.thV4Hits[ip]
		_, in6 := e.thV6Hits[ip]
		if !in4 && !in6 {
			delete(e.Reasons, ip)
		}
	}
}

func pruneOld(ts []time.Time, cutoff time.Time) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// ParseIPFam returns 4 or 6 based on the IP string format, or 0 if neither.
func ParseIPFam(ip string) int {
	if strings.Contains(ip, ":") {
		return 6
	}
	if strings.Count(ip, ".") == 3 {
		return 4
	}
	return 0
}

// ReasonForName maps a counter or throttle-set name to a human-readable label.
func ReasonForName(name string) string {
	switch {
	case strings.HasPrefix(name, "synrate"):
		return "SYN flood"
	case strings.HasPrefix(name, "ppsrate"):
		return "Packet flood (pps)"
	case strings.HasPrefix(name, "portflood_"):
		return "Port flood"
	case strings.HasPrefix(name, "connlimit_"):
		return "Connection limit"
	case strings.HasPrefix(name, "th_syn"):
		return "SYN flood"
	case strings.HasPrefix(name, "th_pps"):
		return "Packet flood (pps)"
	case strings.HasPrefix(name, "th_pf_tcp"):
		return "TCP port flood"
	case strings.HasPrefix(name, "th_pf_udp"):
		return "UDP port flood"
	case strings.HasPrefix(name, "throttled"):
		return "General throttle"
	case strings.HasPrefix(name, "block_v4"), strings.HasPrefix(name, "block_v6"):
		return "Auto-block"
	case strings.HasPrefix(name, "th_connlimit_"):
		x := strings.TrimPrefix(name, "th_connlimit_")
		x = strings.TrimSuffix(x, "_v4")
		x = strings.TrimSuffix(x, "_v6")
		return "connlimit_" + x
	case strings.HasPrefix(name, "th_pf_"):
		x := strings.TrimPrefix(name, "th_pf_")
		if len(x) > 0 && x[0] >= '0' && x[0] <= '9' {
			parts := strings.Split(x, "_")
			if len(parts) >= 2 {
				return "portflood_" + parts[0] + "_" + parts[1]
			}
		}
		if strings.Contains(x, "_udp_") {
			return "UDP port flood"
		}
		return "TCP port flood"
	case name == "badflags_drop":
		return "Bad TCP flags"
	case name == "newrate_v4", name == "newrate_v6":
		return "Global NEW-rate"
	case name == "icmp_v4", name == "icmp_v6":
		return "ICMP echo limit"
	case strings.HasPrefix(name, "th_new_"):
		return "NEW-rate"
	case strings.HasPrefix(name, "th_icmp_"):
		return "ICMP echo limit"
	default:
		return "unknown"
	}
}
