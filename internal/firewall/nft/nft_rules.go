package nft

import (
	"bufio"
	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
	"cfm/internal/firewall/autoblock"
	"cfm/internal/logging"
	"cfm/internal/notify"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)


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
							cur, pkts, delta, autoblock.ReasonForName(cur))
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

// DumpThrottledIPs prints current IPs present in throttled sets (v4/v6),
// χωρίς full table dump. Διαβάζει ΜΟΝΟ τα στοχευμένα throttling sets.
func (b *Backend) DumpThrottledIPs() {
	b.abMu.Lock()
	defer b.abMu.Unlock()

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
		rsn := autoblock.ReasonForName(setName)
		for _, ip := range ips {
			// Prefer first/specific reason; avoid overwriting useful text with generic catch-alls
			if prev, ok := b.ab.Reasons[ip]; !ok || prev == "" || strings.HasPrefix(prev, "General throttle") || prev == "Auto-block" || prev == "unknown" {
				b.ab.Reasons[ip] = rsn
			}

			if autoblock.ParseIPFam(ip) == 4 {
				uniq4[ip] = struct{}{}
			} else if autoblock.ParseIPFam(ip) == 6 {
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
// Calls nft directly (no shell wrapper) to avoid spawning two processes.
func (b *Backend) runCmdOutput(cmd string) (string, error) {
	args := strings.Fields(cmd)
	res, err := runNFTCommand(context.Background(), args...)
	if err != nil {
		return "", fmt.Errorf("nft failed: %w", err)
	}
	return res.Stdout + res.Stderr, nil
}

// runCmdOutputWithTimeout executes an nft command and returns its combined output.
// It protects long-running debug/telemetry calls from blocking the daemon tick loop.
// Calls nft directly (no shell wrapper) — eliminates the redundant sh -lc process
// that was doubling the OS thread consumption per call.
func (b *Backend) runCmdOutputWithTimeout(cmd string, timeout time.Duration) (string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	args := strings.Fields(cmd)
	res, err := runNFTCommand(ctx, args...)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("nft timed out after %s", timeout)
		}
		return "", fmt.Errorf("nft failed: %w", err)
	}
	return res.Stdout + res.Stderr, nil
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
// add it to block_v4/v6. MODE can be "permanent" (no TTL), "ttl" (temporary,
// never shortening an existing block) or "dryrun"/"alert" (log only).

func (b *Backend) autoBlockEval(v4, v6 []string, tc cfgpkg.ThrottleConfig) {
	b.ab.Eval(v4, v6, tc, b.autoBlockAction)
}

// autoBlockAction satisfies autoblock.BlockAction. It is called by the
// Evaluator for each IP that crosses the sliding-window threshold.
func (b *Backend) autoBlockAction(ip, fam, reason string, tc cfgpkg.ThrottleConfig) error {
	if reason == "" {
		reason = "Auto-block"
	}

	const ignoreNotifyCooldown = 90 * time.Second

	if skip, why := b.shouldSkipAutoBlock(ip); skip {
		extraLabel := b.enrichLabel(ip)
		logIP := ip + extraLabel
		ignReason := why
		if ignReason == "" {
			ignReason = "matched allow/ignore policy"
		}
		t := b.lastIgnoredAt[ip]
		if time.Since(t) >= ignoreNotifyCooldown {
			logging.Logf("[autoblock][ignored] %s %s reason=%s", fam, logIP, ignReason)
			note := reason
			if ignReason != "" {
				note += " | " + ignReason
			}
			b.emitAutoBlockNotify(ip, fam, "ignored", note, 0, tc.Hits, tc.WindowSec)
			b.lastIgnoredAt[ip] = time.Now()
		}
		return nil
	}

	if tc.CooldownSec > 0 {
		if t, ok := b.lastAutoBlockAt[ip]; ok {
			if time.Since(t) < time.Duration(tc.CooldownSec)*time.Second {
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
		// AddBlockBatch, not `add element … timeout`: the kernel takes that
		// as a new timeout for an element already in the set, so a ttl
		// autoblock of an address blocked permanently (cfm.deny, a port-scan
		// or manual block) turned it into a timed one.
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return fmt.Errorf("autoBlockAction: invalid IP %q", ip)
		}
		set := "block_v6"
		if parsedIP.To4() != nil { // a v4-mapped address is blocked as IPv4
			set = "block_v4"
		}
		res, err := b.AddBlockBatch([]firewall.BlockEntry{{IP: parsedIP, TTL: time.Duration(ttl) * time.Second}})
		if err != nil {
			logging.Logf("[autoblock] %s %s -> %s ttl=%ds failed: %v", fam, logIP, set, ttl, err)
			return err
		}
		b.lastAutoBlockAt[ip] = time.Now()
		switch {
		case res.Kept > 0:
			logging.Logf("[autoblock] %s %s already in %s for at least ttl=%ds; kept (reason=%s)",
				fam, logIP, set, ttl, reason)
			return nil
		case res.Added+res.Extended == 0:
			logging.Logf("[autoblock] %s %s not blockable (unspecified address); skipped (reason=%s)", fam, logIP, reason)
			return nil
		}
		logging.Logf("[autoblock] %s %s -> %s ttl=%ds (hits>=%d in %ds) reason=%s",
			fam, logIP, set, ttl, tc.Hits, tc.WindowSec, reason)
		_ = b.ReportBlock(ip, comment, "autoblock", "ttl", ttl)
		b.emitAutoBlockNotify(ip, fam, "ttl", reason, ttl, tc.Hits, tc.WindowSec)
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
			b.lastAutoBlockAt[ip] = time.Now()
			_ = b.appendToDenyFile(ip, comment)
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
		b.lastAutoBlockAt[ip] = time.Now()
		_ = b.appendToDenyFile(ip, comment)
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
// Non-blocking: launches work in a goroutine with an overlap guard.
// If the previous tick's port-scanner dump is still running, the new call
// is skipped — preventing process stacking that starves the nginx bridge socket.
func (b *Backend) LoadPortScanner() {
	b.portScanMu.Lock()
	if b.portScanRunning {
		b.portScanMu.Unlock()
		return
	}
	b.portScanRunning = true
	b.portScanMu.Unlock()

	go func() {
		defer func() {
			b.portScanMu.Lock()
			b.portScanRunning = false
			b.portScanMu.Unlock()
		}()
		b.loadPortScannerOnce()
	}()
}

// loadPortScannerOnce does the actual work:
// - ensure base & sets
// - αν Portscan disabled -> return
// - harvest ps_pairs_*, μετρά distinct dports ανά IP
// - φτιάχνει reason και καλεί autoBlockEval() με reuse του throttle tc
func (b *Backend) loadPortScannerOnce() {
	b.abMu.Lock()
	defer b.abMu.Unlock()

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

			b.ab.Reasons[ip] = reason
			if net := autoblock.ParseIPFam(ip); net == 4 {
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
				delete(b.ab.Reasons, s)
			}
		}
		v4 = keep4

		keep6 := make([]string, 0, len(v6))
		for _, s := range v6 {
			if !b.isSelfIPString(s) {
				keep6 = append(keep6, s)
			} else {
				delete(b.ab.Reasons, s)
			}
		}
		v6 = keep6
	}

	mode := strings.ToLower(ps.Mode)

	// ALERT / LOG-ONLY / TEST: μόνο log, καθόλου block.
	if mode == "alert" || mode == "log" || mode == "test" {
		for _, ip := range v4 {
			enrich := b.enrichLabel(ip)
			reason := b.ab.Reasons[ip]
			logging.Logf("[portscan] possible port scan v4 %s%s %s", ip, enrich, reason)
		}
		for _, ip := range v6 {
			enrich := b.enrichLabel(ip)
			reason := b.ab.Reasons[ip]
			logging.Logf("[portscan] possible port scan v6 %s%s %s", ip, enrich, reason)
		}
		return
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
	f := autoblock.ParseIPFam(ip)
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
