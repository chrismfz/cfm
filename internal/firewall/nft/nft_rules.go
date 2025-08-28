package nft

import (
	"bufio"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"

	cfgpkg "cfm/internal/config"
)

// -----------------------------------------------------------------------------
// Flood rules application
// -----------------------------------------------------------------------------



// ApplyFloodRules flushes the flood chain and re-applies all rules from config.
func (b *Backend) ApplyFloodRules(f cfgpkg.FloodConfig) error {
	// First, check if the private cfg field is nil and initialize it.
	if b.cfg == nil {
		b.cfg = &cfgpkg.PortsConfig{}
	}

	// Now, store the received FloodConfig in the Backend's cfg field.
	b.cfg.Flood = f

	// make idempotent
	_ = b.nftExpr("flush chain inet cfm flood;")

	// ensure runtime sets for tracking throttled IPs exist
	b.ensureThrottleSets()
	
	// per-IP packet/SYN rate limiting (kernel-only; overflow-only)
	if f.PktRate > 0 {
		burst := f.PktBurst
		if burst <= 0 {
			burst = f.PktRate * 2
		}
		mode := f.PktMode
		if mode == "" {
			mode = "syn"
		}
		if err := b.applyPerIPRateLimit(f.PktRate, burst, mode); err != nil {
			return err
		}
	}

	if err := b.ApplyConnlimit(f.Connlimit); err != nil {
		return err
	}
	if err := b.ApplyPortFlood(f.PortFlood); err != nil {
		return err
	}
	return nil
}



// ensureThrottleSets creates (idempotently) the dynamic sets that hold throttled IPs.
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

// -----------------------------------------------------------------------------
// Connlimit (global per port; nft does not support per-IP ct count)
// -----------------------------------------------------------------------------

// ApplyConnlimit: concurrent connection limits per PORT (global; nft has no per-IP ct count)
func (b *Backend) ApplyConnlimit(rules []cfgpkg.ConnlimitRule) error {
	for _, r := range rules {
		cname := fmt.Sprintf("connlimit_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)

		expr := fmt.Sprintf(
			"add rule inet cfm flood %s dport %d ct count over %d "+
				"counter name %s drop comment \"connlimit %d;%d\";",
			r.Proto, r.Port, r.Limit,
			cname, r.Limit, r.Port,
		)
		if err := b.nftExpr(expr); err != nil {
			return fmt.Errorf("connlimit rule failed: %w", err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// mapRate converts (max per intervalSeconds) into nft syntax <num>/<unit> with unit in {second,minute,hour,day}.
func mapRate(max, intervalSeconds int) (int, string) {
	if intervalSeconds <= 0 {
		intervalSeconds = 60 // sane default to avoid div-by-zero
	}
	type unit struct {
		name string
		sec  int
	}
	candidates := []unit{
		{"day", 86400},
		{"hour", 3600},
		{"minute", 60},
		{"second", 1},
	}
	for _, u := range candidates {
		if intervalSeconds%u.sec == 0 {
			factor := intervalSeconds / u.sec
			num := int(math.Ceil(float64(max) / float64(factor)))
			if num < 1 {
				num = 1
			}
			return num, u.name
		}
	}
	return max, "second"
}

// -----------------------------------------------------------------------------
// PortFlood (per-IP meters with overflow-only matching)
// -----------------------------------------------------------------------------

// ApplyPortFlood: per-port new-connection rate limiting (per-IP, overflow-only).
func (b *Backend) ApplyPortFlood(rules []cfgpkg.PortFloodRule) error {
	for _, r := range rules {
		cname := fmt.Sprintf("portflood_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)

		num, unit := mapRate(r.Max, r.Interval)

		switch strings.ToLower(r.Proto) {
		case "tcp":
			// IPv4
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @th_pf_tcp_v4 { ip saddr timeout 60s } "+
					"add @throttled_v4 { ip saddr timeout 60s } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Max, cname, r.Port, r.Interval, r.Max,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("portflood v4 tcp failed: %w", err)
			}

			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood tcp dport %d ct state new "+
					"meter pf_%d_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @th_pf_tcp_v6 { ip6 saddr timeout 60s } "+
					"add @throttled_v6 { ip6 saddr timeout 60s } "+
					"counter name %s drop comment \"portflood %d;tcp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Max, cname, r.Port, r.Interval, r.Max,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("portflood v6 tcp failed: %w", err)
			}

		case "udp":
			// IPv4
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v4 { ip saddr limit rate over %d/%s burst %d packets } "+
					"add @th_pf_udp_v4 { ip saddr timeout 60s } "+
					"add @throttled_v4 { ip saddr timeout 60s } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Max, cname, r.Port, r.Interval, r.Max,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("portflood v4 udp failed: %w", err)
			}

			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood udp dport %d ct state new "+
					"meter pf_%d_udp_v6 { ip6 saddr limit rate over %d/%s burst %d packets } "+
					"add @th_pf_udp_v6 { ip6 saddr timeout 60s } "+
					"add @throttled_v6 { ip6 saddr timeout 60s } "+
					"counter name %s drop comment \"portflood %d;udp;%d;%d\";",
				r.Port, r.Port, num, unit, r.Max, cname, r.Port, r.Interval, r.Max,
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
func (b *Backend) DumpFloodCounters() {
	out, err := b.runCmdOutput("list counters table inet cfm")
	if err != nil {
		fmt.Println("[flood] cannot list counters:", err)
		return
	}

	wanted := func(name string) bool {
		return strings.HasPrefix(name, "connlimit_") ||
			strings.HasPrefix(name, "portflood_") ||
			strings.HasPrefix(name, "synrate_") ||
			strings.HasPrefix(name, "ppsrate_")
	}

	if b.last == nil {
		b.last = map[string]int{}
	}

	var cur string
	scan := bufio.NewScanner(strings.NewReader(out))
	for scan.Scan() {
		s := strings.TrimSpace(scan.Text())
		if s == "" {
			continue
		}

		if strings.HasPrefix(s, "counter ") {
			f := strings.Fields(s)
			if len(f) >= 2 {
				name := strings.TrimSuffix(f[1], "{")
				if wanted(name) {
					cur = name
				} else {
					cur = ""
				}
			}
			continue
		}

		if cur != "" && strings.HasPrefix(s, "packets ") {
			f := strings.Fields(s) // ["packets", "<N>", "bytes", "<M>"]
			if len(f) >= 2 {
				if pkts, err := strconv.Atoi(f[1]); err == nil && pkts > 0 {
					prev := b.last[cur]
					delta := pkts - prev
					if delta > 0 {
						fmt.Printf("[flood] %-24s packets %d (+%d)\n", cur, pkts, delta)
					}
					b.last[cur] = pkts
				}
			}
		}
	}

	b.DumpThrottledIPs()
}

// DumpThrottledIPs prints current IPs present in throttled sets (v4/v6).
func (b *Backend) DumpThrottledIPs() {
	dump := func(set string) []string {
		out, err := b.runCmdOutput("list set inet cfm " + set)
		if err != nil {
			return nil
		}
		i := strings.Index(out, "elements = {")
		if i < 0 {
			return nil
		}
		rest := out[i+len("elements = {"):]
		j := strings.Index(rest, "}")
		if j < 0 {
			return nil
		}
		elems := rest[:j]

		raw := strings.Split(elems, ",")
		var ips []string
		for _, t := range raw {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if k := strings.IndexByte(t, ' '); k >= 0 { // cut any "timeout 58s"
				t = t[:k]
			}
			ips = append(ips, t)
		}
		if len(ips) > 0 {
			fmt.Printf("[throttle] %s: %s\n", set, strings.Join(ips, ", "))
		}
		return ips
	}

	_ = dump("th_syn_v4")
	_ = dump("th_syn_v6")
	_ = dump("th_pps_v4")
	_ = dump("th_pps_v6")
	_ = dump("th_pf_tcp_v4")
	_ = dump("th_pf_tcp_v6")
	_ = dump("th_pf_udp_v4")
	_ = dump("th_pf_udp_v6")
	v4 := dump("throttled_v4")
	v6 := dump("throttled_v6")


if b.cfg.Flood.Throttle.Enabled {
    b.autoBlockEval(v4, v6, b.cfg.Flood.Throttle)
}


}

// ensureCounter creates the named counter if it doesn't already exist (idempotent).
func (b *Backend) ensureCounter(name string) {
	_ = b.nftExpr(fmt.Sprintf("add counter inet cfm %s;", name))
}

// ---- nft compat helpers ----

// runCmd executes a single nft command preserving quotes via `sh -lc`.
func (b *Backend) runCmd(cmd string) error {
	out, err := exec.Command("sh", "-lc", "nft "+cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft failed: %v (out=%s)", err, out)
	}
	return nil
}

// runCmdOutput executes an nft command and returns its combined output.
func (b *Backend) runCmdOutput(cmd string) (string, error) {
	out, err := exec.Command("sh", "-lc", "nft "+cmd).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft failed: %v (out=%s)", err, out)
	}
	return string(out), nil
}

// -----------------------------------------------------------------------------
// Per-IP rate-limits (PKT): meters with overflow-only matching
// -----------------------------------------------------------------------------

// applyPerIPRateLimit installs per-IP packet/SYN rate limiting using nft "meter".
func (b *Backend) applyPerIPRateLimit(rate, burst int, mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))

	switch mode {
	case "all":
		b.ensureCounter("ppsrate_v4")
		expr4 := fmt.Sprintf(
			"add rule inet cfm flood meter pps_v4 { ip saddr limit rate over %d/second burst %d packets } "+
				"add @th_pps_v4 { ip saddr timeout 60s } "+
				"add @throttled_v4 { ip saddr timeout 60s } "+
				"counter name ppsrate_v4 drop comment \"per-ip pps rate %d/%d\";",
			rate, burst, rate, burst,
		)
		if err := b.nftExpr(expr4); err != nil {
			return fmt.Errorf("per-ip pps v4 failed: %w", err)
		}

		b.ensureCounter("ppsrate_v6")
		expr6 := fmt.Sprintf(
			"add rule inet cfm flood meter pps_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
				"add @th_pps_v6 { ip6 saddr timeout 60s } "+
				"add @throttled_v6 { ip6 saddr timeout 60s } "+
				"counter name ppsrate_v6 drop comment \"per-ip pps rate %d/%d\";",
			rate, burst, rate, burst,
		)
		if err := b.nftExpr(expr6); err != nil {
			return fmt.Errorf("per-ip pps v6 failed: %w", err)
		}

	default: // "syn"
		b.ensureCounter("synrate_v4")
		expr4 := fmt.Sprintf(
			"add rule inet cfm flood tcp flags syn meter syn_v4 { ip saddr limit rate over %d/second burst %d packets } "+
				"add @th_syn_v4 { ip saddr timeout 60s } "+
				"add @throttled_v4 { ip saddr timeout 60s } "+
				"counter name synrate_v4 drop comment \"per-ip syn rate %d/%d\";",
			rate, burst, rate, burst,
		)
		if err := b.nftExpr(expr4); err != nil {
			return fmt.Errorf("per-ip syn v4 failed: %w", err)
		}

		b.ensureCounter("synrate_v6")
		expr6 := fmt.Sprintf(
			"add rule inet cfm flood tcp flags syn meter syn_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
				"add @th_syn_v6 { ip6 saddr timeout 60s } "+
				"add @throttled_v6 { ip6 saddr timeout 60s } "+
				"counter name synrate_v6 drop comment \"per-ip syn rate %d/%d\";",
			rate, burst, rate, burst,
		)
		if err := b.nftExpr(expr6); err != nil {
			return fmt.Errorf("per-ip syn v6 failed: %w", err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Simple autoblock (throttling hits -> block)
// -----------------------------------------------------------------------------

// Auto-block policy (simple): if an IP is throttled >= THRESHOLD times within WINDOW,
// add it to block_v4/v6. MODE can be "permanent" (no TTL) or "ttl" (temporary).



var (
	thV4Hits = map[string][]time.Time{}
	thV6Hits = map[string][]time.Time{}
)


func (b *Backend) autoBlockEval(v4, v6 []string, tc cfgpkg.ThrottleConfig) {
    now := time.Now()
    window := time.Duration(tc.WindowSec) * time.Second
    for _, ip := range v4 {
        thV4Hits[ip] = append(thV4Hits[ip], now)
        thV4Hits[ip] = pruneOld(thV4Hits[ip], now.Add(-window))
        if len(thV4Hits[ip]) >= tc.Hits {
            _ = b.addToBlockSet("v4", ip, tc) // <-- Add the tc argument
            delete(thV4Hits, ip)
        }
    }
    for _, ip := range v6 {
        thV6Hits[ip] = append(thV6Hits[ip], now)
        thV6Hits[ip] = pruneOld(thV6Hits[ip], now.Add(-window))
        if len(thV6Hits[ip]) >= tc.Hits {
            _ = b.addToBlockSet("v6", ip, tc) // <-- Add the tc argument
            delete(thV6Hits, ip)
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

func (b *Backend) addToBlockSet(fam, ip string, tc cfgpkg.ThrottleConfig) error {
    switch tc.Mode {
    case "ttl":
        ttl := tc.TTLSeconds
        if fam == "v4" {
            fmt.Printf("[autoblock] v4 %s -> block_v4 ttl=%ds (hits>=%d in %ds)\n", ip, ttl, tc.Hits, tc.WindowSec)
            return b.nftExpr(fmt.Sprintf("add element inet cfm block_v4 { %s timeout %ds }", ip, ttl))
        }
        fmt.Printf("[autoblock] v6 %s -> block_v6 ttl=%ds (hits>=%d in %ds)\n", ip, ttl, tc.Hits, tc.WindowSec)
        return b.nftExpr(fmt.Sprintf("add element inet cfm block_v6 { %s timeout %ds }", ip, ttl))
    default: // permanent
        if fam == "v4" {
            fmt.Printf("[autoblock] v4 %s -> block_v4 permanent (hits>=%d in %ds)\n", ip, tc.Hits, tc.WindowSec)
            return b.nftExpr(fmt.Sprintf("add element inet cfm block_v4 { %s }", ip))
        }
        fmt.Printf("[autoblock] v6 %s -> block_v6 permanent (hits>=%d in %ds)\n", ip, tc.Hits, tc.WindowSec)
        return b.nftExpr(fmt.Sprintf("add element inet cfm block_v6 { %s }", ip))
    }
}



// GetFloodConfig returns the current flood configuration.
func (b *Backend) GetFloodConfig() cfgpkg.FloodConfig {
    return b.cfg.Flood
}
