package nft

import (
	"bufio"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"os"
	"path/filepath"
	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// -----------------------------------------------------------------------------
// Flood rules application
// -----------------------------------------------------------------------------

func (b *Backend) ApplyFloodRules(c *cfgpkg.Config) error {
    b.cfg = c // απλό replace

    // 1) Ensure βάσης (πίνακας/αλυσίδες/sets + refreshSelfSets μέσα στο EnsureBase)
    if !b.tableExists() {
        if err := b.EnsureBase(); err != nil { return err }
    } else {
        // καλό είναι να ανανεώνεις τα self sets ανά tick αν αλλάζουν IPs
        // π.χ. b.refreshSelfSets() εδώ, αν δεν το καλείς ήδη μέσα στο EnsureBase
    }

    // 2) Καθαρό flood και early self-bypass (να μη γράφουν counters)
    _ = b.nftExpr("flush chain inet cfm flood;")
    _ = b.nftExpr(`add rule inet cfm flood ip saddr @self_v4 return`)
    _ = b.nftExpr(`add rule inet cfm flood ip6 saddr @self_v6 return`)

    // 3) Συνέχισε με τα υπόλοιπα
    b.ensureThrottleSets()

    if err := b.ApplyHardeningRules(c); err != nil { return err }  // badflags/newrate/icmp κ.λπ. :contentReference[oaicite:0]{index=0}

    // PacketRate (pps/syn per-IP)
    if c.PacketRate.Rate > 0 {
        burst := c.PacketRate.Burst
        if burst <= 0 { burst = c.PacketRate.Rate * 2 }
        if err := b.applyPerIPRateLimit(c.PacketRate.Rate, burst, c.PacketRate.Mode); err != nil { return err }
    }

    if err := b.ApplyConnlimit(c.Connlimit.Rules); err != nil { return err }
    if err := b.ApplyPortFlood(c.PortFlood.Rules); err != nil { return err }
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



func (b *Backend) ApplyConnlimit(rules []cfgpkg.ConnlimitRule) error {
	for _, r := range rules {
		cname := fmt.Sprintf("connlimit_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)
		ttl := b.cfg.Throttle.SetTTL

		// dynamic per-port set names so reason can reflect the exact rule (port/proto)
		// Example: th_connlimit_993_tcp_v4, th_connlimit_993_tcp_v6
		setV4 := fmt.Sprintf("th_connlimit_%d_%s_v4", r.Port, r.Proto)
		setV6 := fmt.Sprintf("th_connlimit_%d_%s_v6", r.Port, r.Proto)

		// idempotently create the sets
		_ = b.nftExpr(fmt.Sprintf("add set inet cfm %s { type ipv4_addr; flags timeout; }", setV4))
		_ = b.nftExpr(fmt.Sprintf("add set inet cfm %s { type ipv6_addr; flags timeout; }", setV6))

		switch r.Proto {
		case "tcp":
			// IPv4
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood ip protocol tcp tcp dport %d ct count over %d "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"connlimit %d;%d\";",
				r.Port, r.Limit, setV4, ttl, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("connlimit v4 tcp rule failed: %w", err)
			}
			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr tcp tcp dport %d ct count over %d "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"connlimit %d;%d\";",
				r.Port, r.Limit, setV6, ttl, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("connlimit v6 tcp rule failed: %w", err)
			}

		case "udp":
			// IPv4
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood ip protocol udp udp dport %d ct count over %d "+
					"add @%s { ip saddr timeout %ds } "+
					"counter name %s drop comment \"connlimit %d;%d\";",
				r.Port, r.Limit, setV4, ttl, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("connlimit v4 udp rule failed: %w", err)
			}
			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr udp udp dport %d ct count over %d "+
					"add @%s { ip6 saddr timeout %ds } "+
					"counter name %s drop comment \"connlimit %d;%d\";",
				r.Port, r.Limit, setV6, ttl, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("connlimit v6 udp rule failed: %w", err)
			}

		default:
			return fmt.Errorf("unknown proto %q in CONNLIMIT", r.Proto)
		}
	}
	return nil
}


// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
// listSetsWithPrefix lists set names in table 'inet cfm' that start with the given prefix.
func (b *Backend) listSetsWithPrefix(prefix string) []string {
	out, err := b.runCmdOutput("list table inet cfm")
	if err != nil {
		return nil
	}
	var names []string
	// sets show as: 'set <name> { ... }'
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		name := strings.TrimPrefix(line, "set ")
		if i := strings.Index(name, " "); i >= 0 {
			name = name[:i]
		}
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}


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
// ApplyPortFlood: per-port new-connection rate limiting (per-IP, overflow-only).
func (b *Backend) ApplyPortFlood(rules []cfgpkg.PortFloodRule) error {
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
func (b *Backend) DumpFloodCounters() {
if !b.tableExists() {
    _ = b.EnsureBase() // προσπάθησε να επαναφέρεις βάση
}
	out, err := b.runCmdOutput("list counters table inet cfm")
	if err != nil {
		fmt.Println("[flood] cannot list counters:", err)
		return
	}

	wanted := func(name string) bool {

 if name == "badflags_drop" || name == "newrate_v4" || name == "newrate_v6" || name == "icmp_v4" || name == "icmp_v6" {
        return true
    }

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
						logging.Logf("[flood] %-24s packets %d (+%d) reason=%s", cur, pkts, delta, reasonForName(cur))

					}
					b.last[cur] = pkts
				}
			}
		}
	}

	b.DumpThrottledIPs()
}



func reasonForName(name string) string {
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
	// th_connlimit_<port>_<proto>_(v4|v6) → reason = "connlimit_<port>_<proto>"
	x := strings.TrimPrefix(name, "th_connlimit_")
	x = strings.TrimSuffix(x, "_v4")
	x = strings.TrimSuffix(x, "_v6")
	return "connlimit_" + x

case strings.HasPrefix(name, "th_pf_"):
    // th_pf_<port>_<proto>_(v4|v6)  ή παλιό generic th_pf_tcp_v4
    x := strings.TrimPrefix(name, "th_pf_")      // π.χ. "65535_tcp_v4" ή "tcp_v4"
    // Αν ξεκινάει με ψηφίο, είναι per-port
    if len(x) > 0 && x[0] >= '0' && x[0] <= '9' {
        // μορφή: "<port>_<proto>_v4|v6"
        parts := strings.Split(x, "_")
        if len(parts) >= 2 {
            return "portflood_" + parts[0] + "_" + parts[1]
        }
    }
    // fallback για τα generic:
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









// DumpThrottledIPs prints current IPs present in throttled sets (v4/v6).
func (b *Backend) DumpThrottledIPs() {

dump := func(set string) []string {

if !b.setExists(set) { return nil } // το set δεν υπάρχει; ήσυχα skip

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
        if k := strings.IndexByte(t, ' '); k >= 0 {
            t = t[:k]
        }
        ips = append(ips, t)
    }

{
    filtered := make([]string, 0, len(ips))
    for _, ip := range ips {
        if b.isSelfIPString(ip) {
            continue
        }
        filtered = append(filtered, ip)
    }
    ips = filtered
}


if len(ips) > 0 {
    reason := reasonForName(set)
    if b.enr == nil {
        // χωρίς enrichment, κράτα το παλιό συμπεριφορά
        logging.Logf("[throttle] %s (%s): %s", set, reason, strings.Join(ips, ", "))
        for _, ip := range ips {
            lastThrottleReason[ip] = reason
        }
        return ips
    }

    for _, ip := range ips {
        logging.Logf("[throttle] %s (%s): %s%s", set, reason, ip, b.enrichLabel(ip))
        lastThrottleReason[ip] = reason
    }

}
    return ips
}


// ----------------------------
    // Source-aware collection (honors THROTTLE_SOURCES)
    // ----------------------------
    // Parse enabled sources from config (or env fallback)
    enabled := map[string]bool{}
    var srcs []string
    if len(b.cfg.Throttle.Sources) > 0 {
        srcs = b.cfg.Throttle.Sources
    } else {
        s := os.Getenv("THROTTLE_SOURCES")
        if s == "" {
            s = "syn,portflood,pps,new,icmp" // default
        }
        for _, t := range strings.Split(s, ",") {
            srcs = append(srcs, t)
        }
    }
    for _, t := range srcs {
        k := strings.ToLower(strings.TrimSpace(t))
        if k != "" {
            enabled[k] = true
        }
    }

    // We’ll union all IPs we dumped (but still print per-set lines above).
    uniq4 := map[string]struct{}{}
    uniq6 := map[string]struct{}{}
    merge := func(ips []string) {
        for _, ip := range ips {
            if parseIPFam(ip) == 4 {
                uniq4[ip] = struct{}{}
            } else if parseIPFam(ip) == 6 {
                uniq6[ip] = struct{}{}
            }
        }
    }

    // SYN source
    if enabled["syn"] {
        merge(dump("th_syn_v4"))
        merge(dump("th_syn_v6"))
    }
    // PPS source
    if enabled["pps"] {
        merge(dump("th_pps_v4"))
        merge(dump("th_pps_v6"))
    }
// NEW-rate source
if enabled["new"] {
    merge(dump("th_new_v4"))
    merge(dump("th_new_v6"))
}

// ICMP source
if enabled["icmp"] {
    merge(dump("th_icmp_v4"))
    merge(dump("th_icmp_v6"))
}

    // PortFlood source (per-port sets)
    if enabled["portflood"] {
        for _, s := range b.listSetsWithPrefix("th_pf_") {
            merge(dump(s))
        }
    }

    // Optional: Connlimit (include only if user adds it to THROTTLE_SOURCES)
    if enabled["connlimit"] {
        for _, s := range b.listSetsWithPrefix("th_connlimit_") {
            merge(dump(s))
        }
    }
    // Προσοχή: δεν κάνουμε dump των generic 'throttled_v4/v6' για να μη φαίνεται "General throttle".
    // Αυτό κρατάει το output καθαρό, αλλά το autoblock μετράει κανονικά από τα enabled sources.
    if b.cfg.Throttle.Enabled {
        var v4, v6 []string
        for ip := range uniq4 { v4 = append(v4, ip) }
        for ip := range uniq6 { v6 = append(v6, ip) }
        b.autoBlockEval(v4, v6, b.cfg.Throttle)
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
	ttl := b.cfg.Throttle.SetTTL

	switch mode {
	case "all":
		b.ensureCounter("ppsrate_v4")
		expr4 := fmt.Sprintf(
			"add rule inet cfm flood meter pps_v4 { ip saddr limit rate over %d/second burst %d packets } "+
				"add @th_pps_v4 { ip saddr timeout %ds } "+
				"add @throttled_v4 { ip saddr timeout %ds } "+
				"counter name ppsrate_v4 drop comment \"per-ip pps rate %d/%d\";",
			rate, burst, ttl, ttl, rate, burst,
		)
		if err := b.nftExpr(expr4); err != nil {
			return fmt.Errorf("per-ip pps v4 failed: %w", err)
		}

		b.ensureCounter("ppsrate_v6")
		expr6 := fmt.Sprintf(
			"add rule inet cfm flood meter pps_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
				"add @th_pps_v6 { ip6 saddr timeout %ds } "+
				"add @throttled_v6 { ip6 saddr timeout %ds } "+
				"counter name ppsrate_v6 drop comment \"per-ip pps rate %d/%d\";",
			rate, burst, ttl, ttl, rate, burst,
		)
		if err := b.nftExpr(expr6); err != nil {
			return fmt.Errorf("per-ip pps v6 failed: %w", err)
		}

	default: // "syn"
		b.ensureCounter("synrate_v4")
		expr4 := fmt.Sprintf(
			"add rule inet cfm flood tcp flags syn meter syn_v4 { ip saddr limit rate over %d/second burst %d packets } "+
				"add @th_syn_v4 { ip saddr timeout %ds } "+
				"add @throttled_v4 { ip saddr timeout %ds } "+
				"counter name synrate_v4 drop comment \"per-ip syn rate %d/%d\";",
			rate, burst, ttl, ttl, rate, burst,
		)
		if err := b.nftExpr(expr4); err != nil {
			return fmt.Errorf("per-ip syn v4 failed: %w", err)
		}

		b.ensureCounter("synrate_v6")
		expr6 := fmt.Sprintf(
			"add rule inet cfm flood tcp flags syn meter syn_v6 { ip6 saddr limit rate over %d/second burst %d packets } "+
				"add @th_syn_v6 { ip6 saddr timeout %ds } "+
				"add @throttled_v6 { ip6 saddr timeout %ds } "+
				"counter name synrate_v6 drop comment \"per-ip syn rate %d/%d\";",
			rate, burst, ttl, ttl, rate, burst,
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

	lastThrottleReason = map[string]string{} // ip -> reason string
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
    reason := lastThrottleReason[ip]
    if reason == "" {
        reason = "Auto-block" // fallback
    }

    // Ενιαίο enrichment για όλα τα logs
    extraLabel := b.enrichLabel(ip) // π.χ. "  —  PTR | ASxxx Name | City, Country"
    logIP := ip + extraLabel
    // Για σχόλιο στο cfm.deny θέλουμε χωρίς το leading "—  "
    cleanExtra := strings.TrimSpace(strings.TrimPrefix(extraLabel, "—"))
    cleanExtra = strings.TrimLeft(cleanExtra, "–— ") // ασφάλεια για διαφορετικά dashes
    if cleanExtra == "" {
        cleanExtra = ""
    }

    switch tc.Mode {


case "alert", "dryrun":
    // v4
    if fam == "v4" {
        logging.Logf(
            "[dryrun] v4 %s -> would block_v4 %s (ttl=%ds, hits>=%d in %ds) reason=%s",
            logIP, tc.Mode, tc.TTLSeconds, tc.Hits, tc.WindowSec, reason,
        )
        return nil
    }
    // v6
    logging.Logf(
        "[dryrun] v6 %s -> would block_v6 %s (ttl=%ds, hits>=%d in %ds) reason=%s",
        logIP, tc.Mode, tc.TTLSeconds, tc.Hits, tc.WindowSec, reason,
    )
    return nil



case "ttl":
    ttl := tc.TTLSeconds
    if fam == "v4" {
        logging.Logf("[autoblock] v4 %s -> block_v4 ttl=%ds (hits>=%d in %ds) reason=%s",
            logIP, ttl, tc.Hits, tc.WindowSec, reason)

        // 1) Κάνε το nft add
        err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v4 { %s timeout %ds }", ip, ttl))
        // 2) Report ΜΟΝΟ αν πέτυχε και είναι on το flag
        if err == nil && b.reporter != nil && b.cfg != nil && b.cfg.API.AutoBlockSend {
            _ = b.reporter.ReportBlock(ip, reason, "autoblock", "ttl", ttl)
        }
        return err
    }
    logging.Logf("[autoblock] v6 %s -> block_v6 ttl=%ds (hits>=%d in %ds) reason=%s",
        logIP, ttl, tc.Hits, tc.WindowSec, reason)
    err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v6 { %s timeout %ds }", ip, ttl))
    if err == nil && b.reporter != nil && b.cfg != nil && b.cfg.API.AutoBlockSend {

  cmt := reason
        if cleanExtra != "" { cmt += " | " + cleanExtra }
        _ = b.reporter.ReportBlock(ip, cmt, "autoblock", "ttl", ttl)

    }
    return err

default: // permanent
    comment := reason
    if cleanExtra != "" { comment += " | " + cleanExtra }

    if fam == "v4" {
        logging.Logf("[autoblock] v4 %s -> block_v4 permanent (hits>=%d in %ds) reason=%s",
            logIP, tc.Hits, tc.WindowSec, reason)
        _ = b.appendToDenyFile(ip, comment)

        err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v4 { %s }", ip))
        if err == nil && b.reporter != nil && b.cfg != nil && b.cfg.API.AutoBlockSend {

    _ = b.reporter.ReportBlock(ip, comment, "autoblock", "permanent", 0)
        }
        return err
    }

    logging.Logf("[autoblock] v6 %s -> block_v6 permanent (hits>=%d in %ds) reason=%s",
        logIP, tc.Hits, tc.WindowSec, reason)
    _ = b.appendToDenyFile(ip, comment)

    err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v6 { %s }", ip))
    if err == nil && b.reporter != nil && b.cfg != nil && b.cfg.API.AutoBlockSend {
        _ = b.reporter.ReportBlock(ip, reason, "autoblock", "permanent", 0)
    }
    return err

}
}








func (b *Backend) appendToDenyFile(ip, reason string) error {
    if strings.TrimSpace(b.cfgDir) == "" {
        // ο daemon τρέχει χωρίς persistence — σεβόμαστε την επιλογή
        return nil
    }
    if err := os.MkdirAll(b.cfgDir, 0755); err != nil { return err }
    fp := filepath.Join(b.cfgDir, "cfm.deny")

    f, err := os.OpenFile(fp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil { return err }
    defer f.Close()

    ts := time.Now().Format("2006-01-02 15:04:05")
    line := fmt.Sprintf("%s # autoblock: %s at %s\n", ip, reason, ts)
    _, err = f.WriteString(line)
    return err
}





// -----------------------------------------------------------------------------
// Port-scan tracking: harvest ps_pairs_* sets and reuse autoblock
// -----------------------------------------------------------------------------

// ensurePortscanSets creates (idempotently) the dynamic sets that hold (srcIP . dport).
// ΣΗΜ.: Τα ονόματα των sets (psPairsV4 κ.λπ.) τα έχουμε δηλώσει ήδη στο ports.go
// και επειδή ανήκουν στο ίδιο package `nft`, είναι ορατά εδώ.
func (b *Backend) ensurePortscanSets() {
	_ = b.nftExpr("add set inet cfm " + psPairsV4 + "     { type ipv4_addr . inet_service; flags timeout; }")
	_ = b.nftExpr("add set inet cfm " + psPairsV6 + "     { type ipv6_addr . inet_service; flags timeout; }")
	_ = b.nftExpr("add set inet cfm " + psPairsUDPV4 + "  { type ipv4_addr . inet_service; flags timeout; }")
	_ = b.nftExpr("add set inet cfm " + psPairsUDPV6 + "  { type ipv6_addr . inet_service; flags timeout; }")
}

// dumpPortscanPairs διαβάζει τα ps_pairs_* και επιστρέφει:
//  - tcp: map[ip] -> set(distinct dports)
//  - udp: map[ip] -> set(distinct dports)
func (b *Backend) dumpPortscanPairs() (map[string]map[int]struct{}, map[string]map[int]struct{}) {
	parse := func(set string) map[string]map[int]struct{} {
		m := map[string]map[int]struct{}{}
		if !b.setExists(set) {
			return m
		}

		out, err := b.runCmdOutput("list set inet cfm " + set)
		if err != nil {
			return m
		}

		i := strings.Index(out, "elements = {")
		if i < 0 {
			return m
		}
		rest := out[i+len("elements = {"):]
		j := strings.Index(rest, "}")
		if j < 0 {
			return m
		}
		elems := rest[:j]

		for _, tok := range strings.Split(elems, ",") {
			t := strings.TrimSpace(tok)
			if t == "" {
				continue
			}

			// Κόψε metadata (" timeout ...", " expires ...") χωρίς να χαθεί το " . port"
			if k := strings.Index(t, " timeout "); k >= 0 {
				t = t[:k]
			}
			if k := strings.Index(t, " expires "); k >= 0 {
				t = t[:k]
			}
			t = strings.TrimSpace(t)

			// Αναμένουμε μορφή: "<ip> . <port>"
			var ip, portStr string
			if strings.Contains(t, " . ") {
				parts := strings.SplitN(t, " . ", 2)
				if len(parts) != 2 {
					continue
				}
				ip = strings.TrimSpace(parts[0])
				portStr = strings.TrimSpace(parts[1])
			} else {
				// Fallback: πεδίο-πεδίο "IP . PORT"
				fields := strings.Fields(t)
				if len(fields) >= 3 && fields[1] == "." {
					ip = fields[0]
					portStr = fields[2]
				} else {
					// Τελευταία άμυνα: χώρισε στο τελευταίο '.'
					if idx := strings.LastIndex(t, "."); idx > 0 && idx < len(t)-1 {
						ip = strings.TrimSpace(t[:idx])
						portStr = strings.TrimSpace(t[idx+1:])
					} else {
						continue
					}
				}
			}

			p, err := strconv.Atoi(portStr)
			if err != nil || p < 0 || p > 65535 {
				continue
			}

			if _, ok := m[ip]; !ok {
				m[ip] = map[int]struct{}{}
			}
			m[ip][p] = struct{}{}
		}
		return m
	}

	// TCP = v4 + v6 μαζί
	tcp := map[string]map[int]struct{}{}
	addAll := func(src map[string]map[int]struct{}, dst map[string]map[int]struct{}) {
		for ip, ports := range src {
			if _, ok := dst[ip]; !ok {
				dst[ip] = map[int]struct{}{}
			}
			for p := range ports {
				dst[ip][p] = struct{}{}
			}
		}
	}
	addAll(parse(psPairsV4), tcp)
	addAll(parse(psPairsV6), tcp)

	// UDP = v4 + v6 μαζί
	udp := map[string]map[int]struct{}{}
	addAll(parse(psPairsUDPV4), udp)
	addAll(parse(psPairsUDPV6), udp)

	return tcp, udp
}





// LoadPortScanner: καλείται σε κάθε tick.
// - ensure base & sets
// - αν Portscan disabled -> return
// - harvest ps_pairs_*, μετρά distinct dports ανά IP
// - φτιάχνει reason και καλεί autoBlockEval() με reuse του throttle tc
func (b *Backend) LoadPortScanner() {
	// σιγουρέψου ότι υπάρχει η βάση
	if !b.tableExists() {
		if err := b.EnsureBase(); err != nil {
			return
		}
	}
	b.ensurePortscanSets()

	// προστασία αν δεν έχει φορτωθεί config
	if b.cfg == nil {
		return
	}
	ps := b.cfg.Portscan
	if !ps.Enabled || ps.Interval <= 0 || ps.Limit <= 0 {
		return
	}

	// μάζεψε τα ζεύγη
	tcp, udp := b.dumpPortscanPairs()

	// υπολόγισε counts ανά IP (ανά πρωτόκολλο) και συγχώνευσε αυτά που θες
	counts := map[string]int{}
	addCounts := func(m map[string]map[int]struct{}) {
		for ip, ports := range m {
			counts[ip] += len(ports)
		}
	}
	if ps.TrackTCP {
		addCounts(tcp)
	}
	if ps.TrackUDP {
		addCounts(udp)
	}

	// ετοίμασε ThrottleConfig για reuse του autoBlockEval:
	//  - Hits=1 (το threshold είναι ήδη PS_LIMIT)
	//  - WindowSec=PS_INTERVAL
	tc := cfgpkg.ThrottleConfig{
		WindowSec:  ps.Interval,
		Hits:       1,
		Mode:       "ttl",
		TTLSeconds: ps.TTLSeconds,
	}
	if strings.ToLower(ps.Mode) == "permanent" {
		tc.Mode = "permanent"
	}

	var v4, v6 []string
	for ip, n := range counts {
		if n >= ps.Limit {
			// Φτιάξε reason. Προαιρετικά: δείξε και μερικά ports.
			reason := fmt.Sprintf("portscan (%d distinct ports)", n)

			// Αν θέλεις top-6 ports στο reason:
			// (δούλεψε πάνω στο tcp/udp maps — εδώ παίρνουμε απλά από όπου βρούμε)
			var some []int
			if ps.TrackTCP {
				for p := range tcp[ip] {
					some = append(some, p)
				}
			}
			if ps.TrackUDP {
				for p := range udp[ip] {
					some = append(some, p)
				}
			}
			if len(some) > 0 {
				// μικρό sort
				for i := 0; i < len(some); i++ {
					for j := i + 1; j < len(some); j++ {
						if some[j] < some[i] {
							some[i], some[j] = some[j], some[i]
						}
					}
				}
				if len(some) > 6 {
					some = some[:6]
				}
				var parts []string
				for _, p := range some {
					parts = append(parts, strconv.Itoa(p))
				}
				reason = fmt.Sprintf("%s: %s", reason, strings.Join(parts, ","))
			}

			lastThrottleReason[ip] = reason
			if net := parseIPFam(ip); net == 4 {
				v4 = append(v4, ip)
			} else if net == 6 {
				v6 = append(v6, ip)
			}
		}
	}



{
    keep4 := make([]string, 0, len(v4))
    for _, s := range v4 {
        if !b.isSelfIPString(s) {
            keep4 = append(keep4, s)
        } else {
            delete(lastThrottleReason, s) // μην αφήνεις stale reason
        }
    }
    v4 = keep4

    keep6 := make([]string, 0, len(v6))
    for _, s := range v6 {
        if !b.isSelfIPString(s) {
            keep6 = append(keep6, s)
        } else {
            delete(lastThrottleReason, s)
        }
    }
    v6 = keep6
}



// ... αφού έχεις υπολογίσει τα v4, v6 και έχεις φτιάξει τα lastThrottleReason[..]
// και έχεις γεμίσει το tc (threshold config) με limit/interval κλπ.

mode := strings.ToLower(ps.Mode)

// ALERT / LOG-ONLY / TEST: μόνο log, καθόλου block.
if mode == "alert" || mode == "log" || mode == "test" {
    for _, ip := range v4 {
        enrich := b.enrichLabel(ip) // optional: αν έχεις τον enricher
        reason := lastThrottleReason[ip]
        logging.Logf("[portscan] possible port scan v4 %s%s %s", ip, enrich, reason)
    }
    for _, ip := range v6 {
        enrich := b.enrichLabel(ip)
        reason := lastThrottleReason[ip]
        logging.Logf("[portscan] possible port scan v6 %s%s %s", ip, enrich, reason)
    }
    return // τερματίζουμε εδώ — ΔΕΝ γίνεται block
}

// TTL/PERMANENT: κάνε block
switch mode {
case "ttl", "temporary":
    tc.Mode = "ttl"
    tc.TTLSeconds = ps.TTLSeconds
default:
    tc.Mode = "permanent"
}

// μόνο αν υπάρχουν hits προχώρα σε block
if len(v4) > 0 || len(v6) > 0 {
    b.autoBlockEval(v4, v6, tc)
}




}



// parseIPFam: μικρός helper που γυρίζει 4|6 ή 0 αν δεν είναι IP
func parseIPFam(ip string) int {
	if strings.Contains(ip, ":") {
		return 6
	}
	if strings.Count(ip, ".") == 3 {
		return 4
	}
	return 0
}



// enrichLabel επιστρέφει " — PTR | ASNNAME | City, Country" ή "" αν δεν υπάρχει enricher.
func (b *Backend) enrichLabel(ip string) string {
	if b.enr == nil {
		return ""
	}
	r := b.enr.Lookup(ip)
	var parts []string
	if r.PTR != "" {
		parts = append(parts, r.PTR)
	}
	if r.ASN > 0 {
		if r.ASNName != "" {
			parts = append(parts, fmt.Sprintf("AS%d %s", r.ASN, r.ASNName))
		} else {
			parts = append(parts, fmt.Sprintf("AS%d", r.ASN))
		}
	}
	if r.City != "" || r.Country != "" {
		if r.City != "" {
			parts = append(parts, fmt.Sprintf("%s, %s", r.City, r.Country))
		} else {
			parts = append(parts, r.Country)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "  —  " + strings.Join(parts, " | ")
}
