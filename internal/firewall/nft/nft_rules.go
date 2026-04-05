package nft

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	//	"net"
	//	"encoding/json"
	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
	"cfm/internal/notify"
	"path/filepath"
)

// Keep the last time we successfully autoblocked (and/or notified) a given IP
var (
	thV4Hits = map[string][]time.Time{}
	thV6Hits = map[string][]time.Time{}

	lastThrottleReason = map[string]string{} // ip -> reason

	// NEW: last successful autoblock per IP (v4/v6 share the key as a string)
	lastAutoBlockAt    = map[string]time.Time{}
	lastIgnoredAt      = map[string]time.Time{}
	autoBlockEvalCount int
)

// floodCfgHash returns a cheap hash of all flood-relevant config fields.
// If the hash is identical to the previous tick we skip the full rebuild.
func floodCfgHash(c *cfgpkg.Config) uint64 {
	if c == nil {
		return 0
	}
	// fnv-style: combine all fields that, if changed, require a flood rebuild.
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
	// stir in per-rule details so a rule change is detected
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

// -----------------------------------------------------------------------------
// Flood rules application
// -----------------------------------------------------------------------------

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

	// 1) Ensure βάσης (πίνακας/αλυσίδες/sets + refreshSelfSets μέσα στο EnsureBase)
	if !b.tableExists() {
		if err := b.EnsureBase(); err != nil {
			return err
		}
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

	if err := b.ApplyHardeningRules(c); err != nil {
		return err
	} // badflags/newrate/icmp κ.λπ. :contentReference[oaicite:0]{index=0}

	// PacketRate (pps/syn per-IP)
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
// Connlimit
// -----------------------------------------------------------------------------

func (b *Backend) ApplyConnlimit(rules []cfgpkg.ConnlimitRule) error {

	const meterSize = 65535
	for _, r := range rules {
		cname := fmt.Sprintf("connlimit_%d_%s", r.Port, r.Proto)
		b.ensureCounter(cname)

		switch strings.ToLower(r.Proto) {
		case "tcp":
			// IPv4 per-IP concurrent NEW connections on tcp dport
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood ip protocol tcp ct state new tcp dport %d "+
					"meter cl_%d_tcp_v4 size %d { ip saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("connlimit per-ip v4 tcp rule failed: %w", err)
			}
			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr tcp ct state new tcp dport %d "+
					"meter cl_%d_tcp_v6 size %d { ip6 saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("connlimit per-ip v6 tcp rule failed: %w", err)
			}

		case "udp":
			// IPv4 (UDP: counts conntrack entries per-IP; μικρότερη διάρκεια)
			expr4 := fmt.Sprintf(
				"add rule inet cfm flood ip protocol udp ct state new udp dport %d "+
					"meter cl_%d_udp_v4 size %d { ip saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr4); err != nil {
				return fmt.Errorf("connlimit per-ip v4 udp rule failed: %w", err)
			}
			// IPv6
			expr6 := fmt.Sprintf(
				"add rule inet cfm flood ip6 nexthdr udp ct state new udp dport %d "+
					"meter cl_%d_udp_v6 size %d { ip6 saddr ct count over %d } "+
					"counter name %q drop comment \"connlimit-ip %d;%d\";",
				r.Port, r.Port, meterSize, r.Limit, cname, r.Limit, r.Port,
			)
			if err := b.nftExpr(expr6); err != nil {
				return fmt.Errorf("connlimit per-ip v6 udp rule failed: %w", err)
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

// listSetsWithPrefix: φτιάχνει τα ονόματα από το in-memory registry· κανένα nft call.
func (b *Backend) listSetsWithPrefix(prefix string) []string {
	var out []string

	// per-feed sets (allow/block, v4/v6, hosts/nets)
	if strings.HasPrefix(prefix, "allow_ext_") || strings.HasPrefix(prefix, "block_ext_") {
		for k := range b.feedKeys {
			cand := []string{
				"allow_ext_v4_hosts_" + k, "allow_ext_v4_nets_" + k,
				"allow_ext_v6_hosts_" + k, "allow_ext_v6_nets_" + k,
				"block_ext_v4_hosts_" + k, "block_ext_v4_nets_" + k,
				"block_ext_v6_hosts_" + k, "block_ext_v6_nets_" + k,
			}
			for _, name := range cand {
				if strings.HasPrefix(name, prefix) {
					out = append(out, name)
				}
			}
		}
	}

	// throttling per-port registries (ήδη τα γεμίζεις στην ApplyPortFlood/ApplyConnlimit)
	if strings.HasPrefix(prefix, "th_pf_") {
		out = append(out, b.pfSets...)
	}
	if strings.HasPrefix(prefix, "th_connlimit_") {
		out = append(out, b.clSets...)
	}

	return out
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

func (b *Backend) DumpFloodCounters() {
	b.floodDumpMu.Lock()
	if b.floodDumpRunning {
		b.floodDumpMu.Unlock()
		return
	}
	b.floodDumpRunning = true
	b.floodDumpMu.Unlock()

	go func() {
		defer func() {
			b.floodDumpMu.Lock()
			b.floodDumpRunning = false
			b.floodDumpMu.Unlock()
		}()
		b.dumpFloodCountersOnce()
	}()
}

func (b *Backend) dumpFloodCountersOnce() {
	// Πάρε όλους τους counters του table (χωρίς sets/elements).
	// Use a generous timeout so nft gets enough time under load, without stalling the daemon tick path.
	out, err := b.runCmdOutputWithTimeout("list counters table inet cfm", 30*time.Second)
	if err != nil {
		// Προσπάθησε να επαναφέρεις τη βάση και βγες ήσυχα.
		_ = b.EnsureBase()
		logging.Logf("[flood] cannot list counters: %v", err)
		return
	}

	// Γρήγορο φίλτρο: counters που μας ενδιαφέρουν 1) ονομαστικά, 2) με prefixes
	wantedExact := map[string]struct{}{
		"badflags_drop": {},
		"newrate_v4":    {},
		"newrate_v6":    {},
		"icmp_v4":       {},
		"icmp_v6":       {},
	}
	hasWantedPrefix := func(name string) bool {
		return strings.HasPrefix(name, "connlimit_") ||
			strings.HasPrefix(name, "portflood_") ||
			strings.HasPrefix(name, "synrate_") ||
			strings.HasPrefix(name, "ppsrate_")
	}
	isWanted := func(name string) bool {
		if _, ok := wantedExact[name]; ok {
			return true
		}
		return hasWantedPrefix(name)
	}

	if b.last == nil {
		b.last = map[string]uint64{}
	}

	// Παράδειγμα output (text):
	// counter badflags_drop { packets 1234 bytes 5678 }
	// counter portflood_80_tcp { packets 42 bytes 1234 }
	var cur string
	scan := bufio.NewScanner(strings.NewReader(out))
	for scan.Scan() {
		s := strings.TrimSpace(scan.Text())
		if s == "" {
			continue
		}

		// Νέα καταμέτρηση counter
		if strings.HasPrefix(s, "counter ") {
			// "counter <name> {"
			f := strings.Fields(s)
			if len(f) >= 2 {
				name := strings.TrimSuffix(f[1], "{")
				if isWanted(name) {
					cur = name
				} else {
					cur = ""
				}
			}
			continue
		}

		// Γραμμή πακέτων
		if cur != "" && strings.HasPrefix(s, "packets ") {
			// "packets <N> bytes <M>"
			f := strings.Fields(s)
			if len(f) >= 2 {
				if pkts64, err := strconv.ParseUint(f[1], 10, 64); err == nil {

					pkts := pkts64
					prev := b.last[cur] // 0 αν δεν υπάρχει
					if pkts > prev {
						delta := pkts - prev
						logging.Logf("[flood] %-24s packets %d (+%d) reason=%s",
							cur, pkts, delta, reasonForName(cur))
					}
					// reset (pkts < prev) το χειρίζεσαι ήδη “σιωπηλά” ενημερώνοντας την τιμή
					b.last[cur] = pkts

				}
			}
		}
	}

	// Throttle IPs dump μόνο όταν είναι ενεργό.
	if b.cfg != nil && b.cfg.Throttle.Enabled {
		b.DumpThrottledIPs()
	}
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
		x := strings.TrimPrefix(name, "th_pf_") // π.χ. "65535_tcp_v4" ή "tcp_v4"
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

// DumpThrottledIPs prints current IPs present in throttled sets (v4/v6),
// χωρίς full table dump. Διαβάζει ΜΟΝΟ τα στοχευμένα throttling sets.
func (b *Backend) DumpThrottledIPs() {
	// --- helpers ---

	// Στοχευμένο dump ενός set σε []string IPs (αγνοεί self IPs).
	dumpSet := func(set string) []string {
		if set == "" || !b.setExists(set) {
			return nil
		}
		out, err := b.runCmdOutputWithTimeout("list set inet cfm "+set, 10*time.Second)
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
		elems := strings.Split(strings.TrimSpace(rest[:j]), ",")
		ips := make([]string, 0, len(elems))
		for _, t := range elems {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			// Κόψε οτιδήποτε μετά το IP (π.χ. "timeout 60s")
			if k := strings.IndexByte(t, ' '); k >= 0 {
				t = t[:k]
			}
			if t == "" || b.isSelfIPString(t) {
				continue
			}
			ips = append(ips, t)
		}
		return ips
	}

	// Attach reason + unify (v4/v6) for autoblock.
	//    uniq4 := map[string]struct{}{}
	//    uniq6 := map[string]struct{}{}
	uniq4 := map[string]struct{}{}
	uniq6 := map[string]struct{}{}

	record := func(setName string) {
		ips := dumpSet(setName)
		if len(ips) == 0 {
			return
		}
		rsn := reasonForName(setName)
		for _, ip := range ips {
			// Prefer first/specific reason; avoid overwriting useful text with generic catch-alls
			if prev, ok := lastThrottleReason[ip]; !ok || prev == "" || strings.HasPrefix(prev, "General throttle") || prev == "Auto-block" || prev == "unknown" {
				lastThrottleReason[ip] = rsn
			}

			if parseIPFam(ip) == 4 {
				uniq4[ip] = struct{}{}
			} else if parseIPFam(ip) == 6 {
				uniq6[ip] = struct{}{}
			}

		}
	}

	// Πηγές (THROTTLE_SOURCES ή cfg.Throttle.Sources)
	enabled := map[string]bool{}
	var srcs []string
	if b.cfg != nil && len(b.cfg.Throttle.Sources) > 0 {
		srcs = b.cfg.Throttle.Sources
	} else {
		env := strings.TrimSpace(os.Getenv("THROTTLE_SOURCES"))
		if env == "" {
			env = "syn,portflood,pps,new,icmp,ack" // default
		}
		for _, t := range strings.Split(env, ",") {
			srcs = append(srcs, t)
		}
	}
	for _, t := range srcs {
		k := strings.ToLower(strings.TrimSpace(t))
		if k != "" {
			enabled[k] = true
		}
	}

	if enabled["syn"] {
		record("th_syn_v4")
		record("th_syn_v6")
	}
	if enabled["pps"] {
		record("th_pps_v4")
		record("th_pps_v6")
	}
	if enabled["new"] {
		record("th_new_v4")
		record("th_new_v6")
	}
	if enabled["icmp"] {
		record("th_icmp_v4")
		record("th_icmp_v6")
	}

	// --- per-port PortFlood / Connlimit sets, ΜΟΝΟ στοχευμένα ---
	// Προτεραιότητα: registries (αν τα έχεις υλοποιήσει). Αλλιώς ελαφρύ JSON metadata scan.

	// 1) PortFlood

	// --- per-port PortFlood / Connlimit sets, ΜΟΝΟ μέσω registry ---

	if enabled["portflood"] {
		if len(b.pfSets) == 0 {
			// προαιρετικό debug για να ξέρεις γιατί δεν βλέπεις dumps:
			// logging.Debugf("[throttle] no registered PortFlood sets yet")
		}
		for _, s := range b.pfSets {
			record(s)
		}

	}

	// conn limit
	if enabled["connlimit"] {
		if len(b.clSets) == 0 {
			// logging.Debugf("[throttle] no registered Connlimit sets yet")
		}
		for _, s := range b.clSets {
			record(s)
		}

	}

	// --- autoblock από τις ενεργές πηγές ---
	if b.cfg != nil && b.cfg.Throttle.Enabled {
		var v4, v6 []string
		for ip := range uniq4 {
			v4 = append(v4, ip)
		}
		for ip := range uniq6 {
			v6 = append(v6, ip)
		}
		b.autoBlockEval(v4, v6, b.cfg.Throttle)
	}

}

// ensureCounter creates the named counter if it doesn't already exist (idempotent).
func (b *Backend) ensureCounter(name string) {
	_ = b.nftExpr(fmt.Sprintf("add counter inet cfm %s;", name))
}

// ---- nft compat helpers ----

// runCmdOutput executes an nft command and returns its combined output.
func (b *Backend) runCmdOutput(cmd string) (string, error) {
	out, err := exec.Command("sh", "-lc", "nft "+cmd).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft failed: %v (out=%s)", err, out)
	}
	return string(out), nil
}

// runCmdOutputWithTimeout executes an nft command and returns its combined output.
// It protects long-running debug/telemetry calls from blocking the daemon tick loop.
func (b *Backend) runCmdOutputWithTimeout(cmd string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "sh", "-lc", "nft "+cmd).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("nft timed out after %s", timeout)
		}
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

func (b *Backend) autoBlockEval(v4, v6 []string, tc cfgpkg.ThrottleConfig) {
	// Issue 3: periodic cleanup — every 500 calls (~2.8h at 20s ticks)
	autoBlockEvalCount++
	if autoBlockEvalCount%500 == 0 {
		pruneHitMaps(time.Duration(tc.WindowSec) * time.Second)
	}

	now := time.Now()
	window := time.Duration(tc.WindowSec) * time.Second
	for _, ip := range v4 {
		thV4Hits[ip] = append(thV4Hits[ip], now)
		thV4Hits[ip] = pruneOld(thV4Hits[ip], now.Add(-window))
		if len(thV4Hits[ip]) >= tc.Hits {
			_ = b.addToBlockSet("v4", ip, tc)
			delete(thV4Hits, ip)
		}
	}
	for _, ip := range v6 {
		thV6Hits[ip] = append(thV6Hits[ip], now)
		thV6Hits[ip] = pruneOld(thV6Hits[ip], now.Add(-window))
		if len(thV6Hits[ip]) >= tc.Hits {
			_ = b.addToBlockSet("v6", ip, tc)
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

// pruneHitMaps removes stale entries from all package-level IP maps.
// Called periodically from autoBlockEval to prevent unbounded growth on
// servers that see thousands of unique attacking IPs per day.
func pruneHitMaps(window time.Duration) {
	cutoff := time.Now().Add(-window)
	deadline := time.Now().Add(-24 * time.Hour)

	for ip, ts := range thV4Hits {
		pruned := pruneOld(ts, cutoff)
		if len(pruned) == 0 {
			delete(thV4Hits, ip)
		} else {
			thV4Hits[ip] = pruned
		}
	}
	for ip, ts := range thV6Hits {
		pruned := pruneOld(ts, cutoff)
		if len(pruned) == 0 {
			delete(thV6Hits, ip)
		} else {
			thV6Hits[ip] = pruned
		}
	}
	// Remove reason entries for IPs no longer being tracked
	for ip := range lastThrottleReason {
		_, in4 := thV4Hits[ip]
		_, in6 := thV6Hits[ip]
		if !in4 && !in6 {
			delete(lastThrottleReason, ip)
		}
	}
	// Remove timing entries older than 24h
	for ip, t := range lastAutoBlockAt {
		if t.Before(deadline) {
			delete(lastAutoBlockAt, ip)
		}
	}
	for ip, t := range lastIgnoredAt {
		if t.Before(deadline) {
			delete(lastIgnoredAt, ip)
		}
	}
}

// nft_rules.go
func (b *Backend) addToBlockSet(fam, ip string, tc cfgpkg.ThrottleConfig) error {
	reason := lastThrottleReason[ip]
	if reason == "" {
		reason = "Auto-block"
	}

	// local debounce for repeated "ignored" logs/notifies
	const ignoreNotifyCooldown = 90 * time.Second
	if lastIgnoredAt == nil {
		lastIgnoredAt = map[string]time.Time{}
	}

	// --- NEW: skip if IP is ignored or allowed ---
	if skip, why := b.shouldSkipAutoBlock(ip); skip {
		extraLabel := b.enrichLabel(ip)
		logIP := ip + extraLabel
		ignReason := why
		if ignReason == "" {
			ignReason = "matched allow/ignore policy"
		}

		// Debounce loudness
		t := lastIgnoredAt[ip]
		if time.Since(t) >= ignoreNotifyCooldown {
			logging.Logf("[autoblock][ignored] %s %s reason=%s", fam, logIP, ignReason)
			// Do NOT report to API for ignored events (no external noise)
			note := reason
			if ignReason != "" {
				note += " | " + ignReason
			}
			b.emitAutoBlockNotify(ip, fam, "ignored", note, 0, tc.Hits, tc.WindowSec)
			lastIgnoredAt[ip] = time.Now()
		}
		return nil
	}

	// NEW: cooldown gate (applies to both v4/v6)
	if tc.CooldownSec > 0 {
		if t, ok := lastAutoBlockAt[ip]; ok {
			if time.Since(t) < time.Duration(tc.CooldownSec)*time.Second {
				// Within cooldown → skip quietly (no log, no notify)
				return nil
			}
		}
	}

	extraLabel := b.enrichLabel(ip)
	logIP := ip + extraLabel
	cleanExtra := strings.TrimSpace(strings.TrimPrefix(extraLabel, "—"))
	cleanExtra = strings.TrimLeft(cleanExtra, "–— ")
	comment := reason
	if cleanExtra != "" {
		comment += " | " + cleanExtra
	}

	switch tc.Mode {
	case "alert", "dryrun":
		// unchanged: only log
		if fam == "v4" {
			logging.Logf("[dryrun] v4 %s -> would block_v4 %s (ttl=%ds, hits>=%d in %ds) reason=%s",
				logIP, tc.Mode, tc.TTLSeconds, tc.Hits, tc.WindowSec, reason)
			return nil
		}
		logging.Logf("[dryrun] v6 %s -> would block_v6 %s (ttl=%ds, hits>=%d in %ds) reason=%s",
			logIP, tc.Mode, tc.TTLSeconds, tc.Hits, tc.WindowSec, reason)
		return nil

	case "ttl":
		ttl := tc.TTLSeconds
		if ttl <= 0 {
			ttl = 3600
		}

		// TRY insert first; only log+notify on success
		if fam == "v4" {
			err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v4 { %s timeout %ds }", ip, ttl))
			if err != nil {
				// ignore duplicates to avoid spam
				if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "already exists") {
					return nil
				}
				return err
			}
			logging.Logf("[autoblock] v4 %s -> block_v4 ttl=%ds (hits>=%d in %ds) reason=%s",
				logIP, ttl, tc.Hits, tc.WindowSec, reason)
			lastAutoBlockAt[ip] = time.Now()

			_ = b.ReportBlock(ip, comment, "autoblock", "ttl", ttl)

			b.emitAutoBlockNotify(ip, "v4", "ttl", reason, ttl, tc.Hits, tc.WindowSec)
			return nil
		}

		err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v6 { %s timeout %ds }", ip, ttl))
		if err != nil {
			if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "already exists") {
				return nil
			}
			return err
		}

		logging.Logf("[autoblock] v6 %s -> block_v6 ttl=%ds (hits>=%d in %ds) reason=%s",
			logIP, ttl, tc.Hits, tc.WindowSec, reason)
		lastAutoBlockAt[ip] = time.Now()

		_ = b.ReportBlock(ip, comment, "autoblock", "ttl", ttl)

		b.emitAutoBlockNotify(ip, "v6", "ttl", reason, ttl, tc.Hits, tc.WindowSec)
		return nil

	default: // "permanent"
		if fam == "v4" {

			err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v4 { %s }", ip))
			if err != nil {
				if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "already exists") {
					return nil
				}
				return err
			}

			logging.Logf("[autoblock] v4 %s -> block_v4 permanent (hits>=%d in %ds) reason=%s",
				logIP, tc.Hits, tc.WindowSec, reason)
			lastAutoBlockAt[ip] = time.Now()
			_ = b.appendToDenyFile(ip, comment)
			//            if b.reporter != nil && b.cfg != nil && b.cfg.API.AutoBlockSend {
			//                _ = b.reporter.ReportBlock(ip, comment, "autoblock", "permanent", 0)
			//            }
			_ = b.ReportBlock(ip, comment, "autoblock", "permanent", 0)

			b.emitAutoBlockNotify(ip, "v4", "permanent", reason, 0, tc.Hits, tc.WindowSec)
			return nil
		}

		err := b.nftExpr(fmt.Sprintf("add element inet cfm block_v6 { %s }", ip))
		if err != nil {
			if strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "already exists") {
				return nil
			}
			return err
		}

		logging.Logf("[autoblock] v6 %s -> block_v6 permanent (hits>=%d in %ds) reason=%s",
			logIP, tc.Hits, tc.WindowSec, reason)
		lastAutoBlockAt[ip] = time.Now()
		_ = b.appendToDenyFile(ip, comment)
		//	if b.reporter != nil && b.cfg != nil && b.cfg.API.AutoBlockSend {
		//	    _ = b.reporter.ReportBlock(ip, comment, "autoblock", "permanent", 0)
		//	}
		_ = b.ReportBlock(ip, comment, "autoblock", "permanent", 0)

		b.emitAutoBlockNotify(ip, "v6", "permanent", reason, 0, tc.Hits, tc.WindowSec)
		return nil
	}
}

func (b *Backend) appendToDenyFile(ip, reason string) error {
	if strings.TrimSpace(b.cfgDir) == "" {
		// ο daemon τρέχει χωρίς persistence — σεβόμαστε την επιλογή
		return nil
	}
	if err := os.MkdirAll(b.cfgDir, 0750); err != nil {
		return err
	}
	fp := filepath.Join(b.cfgDir, "cfm.deny")

	f, err := os.OpenFile(fp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
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
//   - tcp: map[ip] -> set(distinct dports)
//   - udp: map[ip] -> set(distinct dports)
func (b *Backend) dumpPortscanPairs() (map[string]map[int]struct{}, map[string]map[int]struct{}) {
	parse := func(set string) map[string]map[int]struct{} {
		m := map[string]map[int]struct{}{}
		if !b.setExists(set) {
			return m
		}

		out, err := b.runCmdOutputWithTimeout("list set inet cfm "+set, 10*time.Second)
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

// notify package helper

func (b *Backend) emitAutoBlockNotify(ip, fam, mode, reason string, ttlSeconds, hits, window int) {
	ev := notify.Event{
		//        Kind:     "autoblock",
		Kind:     reason,
		SrcIP:    ip,
		Reason:   reason,
		TTL:      time.Duration(ttlSeconds) * time.Second,
		Count:    hits,
		Section:  "autoblock",
		When:     time.Now(),
		Severity: "warning",
		Extra: map[string]string{
			"family": fam,
			"mode":   mode, // "ttl" | "permanent"
			"window": fmt.Sprintf("%ds", window),
		},
	}

	if b.enr != nil {
		r := b.enr.Lookup(ip)
		ev.PTR = r.PTR
		if r.ASN > 0 {
			if r.ASNName != "" {
				ev.ASN = fmt.Sprintf("AS%d %s", r.ASN, r.ASNName)
			} else {
				ev.ASN = fmt.Sprintf("AS%d", r.ASN)
			}
		}
		if r.City != "" && r.Country != "" {
			ev.Country = r.City + ", " + r.Country
		} else {
			ev.Country = r.Country
		}
	}
	notify.Enqueue(ev) // non-blocking
}

// shouldSkipAutoBlock returns (true, reason) if ip is in ignore_* OR any allow_* union.
func (b *Backend) shouldSkipAutoBlock(ip string) (bool, string) {
	f := parseIPFam(ip)
	if f == 0 {
		return false, ""
	}

	// manual + dyn allow/ignore first (fast paths)
	var hostSets, netSets []string
	if f == 6 {
		hostSets = []string{"ignore_v6", "allow_v6", "allow_dyn_v6"}
		netSets = []string{"ignore_v6_nets", "allow_v6_nets"}
	} else {
		hostSets = []string{"ignore_v4", "allow_v4", "allow_dyn_v4"}
		netSets = []string{"ignore_v4_nets", "allow_v4_nets"}
	}

	// direct host membership (fast)
	for _, s := range hostSets {
		ok, _ := b.HasElem(s, ip)
		if ok {
			if strings.HasPrefix(s, "ignore_") {
				return true, "in ignore list"
			}
			return true, "already allowed"
		}
	}
	// interval (CIDR) membership: nft get element works against interval sets
	for _, s := range netSets {
		ok, _ := b.HasElem(s, ip) // with interval sets, lookup by /32 or bare IP matches containment
		if ok {
			if strings.HasPrefix(s, "ignore_") {
				return true, "in ignore CIDR"
			}
			return true, "allowed by CIDR"
		}
	}

	// per-feed external ALLOW sets (cached discovery)
	extHosts, extNets := b.getExtAllowSets(f)
	for _, s := range extHosts {
		ok, _ := b.HasElem(s, ip)
		if ok {
			return true, "already allowed (feed)"
		}
	}
	for _, s := range extNets {
		ok, _ := b.HasElem(s, ip)
		if ok {
			return true, "allowed by CIDR (feed)"
		}
	}

	return false, ""
}
