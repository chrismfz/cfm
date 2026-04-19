package status

import (
	"bufio"
	"bytes"
	"cfm/internal/detectors/health"
	"cfm/internal/dnat"
	"cfm/internal/enrich"
	"cfm/internal/firewall/nft"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const topN = 10 // δεν διαβάζουμε από config

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

type DaemonInfo struct {
	Running  bool     `json:"running"`
	PIDs     []int    `json:"pids,omitempty"`
	Cmdlines []string `json:"cmdlines,omitempty"`
}

type ServiceInfo struct {
	Installed bool   `json:"installed"`
	Enabled   string `json:"enabled,omitempty"` // enabled/disabled/static/indirect/unknown
	Active    string `json:"active,omitempty"`  // active/inactive/failed/unknown
}

type nftCounter struct {
	Name    string
	Packets int
}

// ---------------------------------------------------------------------------
// Challenge status (nft + journal)
// ---------------------------------------------------------------------------

type ChallengeStatus struct {
	Enabled bool `json:"enabled"`

	PreroutingOK bool     `json:"prerouting_ok,omitempty"`
	Prerouting   []string `json:"prerouting,omitempty"`

	GuardOK bool     `json:"guard_ok,omitempty"`
	Guard   []string `json:"guard,omitempty"`

	CurrentV4 []recentHit `json:"current_v4,omitempty"`
	CurrentV6 []recentHit `json:"current_v6,omitempty"`

	SinceServiceStart bool   `json:"since_service_start,omitempty"`
	ServiceSince      string `json:"service_since,omitempty"`

	TotalChallenged int `json:"total_challenged,omitempty"`
	TotalSolved     int `json:"total_solved,omitempty"`

	TopIPs  []HitCount `json:"top_ips,omitempty"`
	TopASNs []HitCount `json:"top_asns,omitempty"`
}

type HitCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func getDaemonInfo() DaemonInfo {
	if _, err := exec.LookPath("pgrep"); err == nil {
		out, _ := exec.Command("pgrep", "-fa", "cfm daemon").CombinedOutput()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		var pids []int
		var cmds []string
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			parts := strings.Fields(ln)
			if len(parts) < 2 {
				continue
			}
			pid, _ := strconv.Atoi(parts[0])
			cmd := strings.TrimSpace(strings.TrimPrefix(ln, parts[0]))
			if !strings.Contains(cmd, "cfm") || !strings.Contains(cmd, "daemon") {
				continue
			}
			pids = append(pids, pid)
			cmds = append(cmds, cmd)
		}
		return DaemonInfo{Running: len(pids) > 0, PIDs: pids, Cmdlines: cmds}
	}
	// fallback με ps
	out, _ := exec.Command("ps", "ax", "-o", "pid=,cmd=").CombinedOutput()
	var pids []int
	var cmds []string
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) < 2 {
			continue
		}
		pid, _ := strconv.Atoi(parts[0])
		cmd := strings.TrimSpace(strings.TrimPrefix(ln, parts[0]))
		if strings.Contains(cmd, "cfm") && strings.Contains(cmd, "daemon") {
			pids = append(pids, pid)
			cmds = append(cmds, cmd)
		}
	}
	return DaemonInfo{Running: len(pids) > 0, PIDs: pids, Cmdlines: cmds}
}

func trim1(b []byte) string         { return strings.TrimSpace(string(b)) }
func must(b []byte, _ error) []byte { return b }

func getUnitServiceInfo(unit string) ServiceInfo {
	si := ServiceInfo{}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return si
	} // όχι systemd
	// Installed?
	loadOut, _ := exec.Command("systemctl", "show", "-p", "LoadState", unit).CombinedOutput()
	if bytes.Contains(loadOut, []byte("LoadState=loaded")) {
		si.Installed = true
	}
	// Enabled?
	en := trim1(must(exec.Command("systemctl", "is-enabled", unit).CombinedOutput()))
	if en == "" {
		en = "unknown"
	}
	si.Enabled = en
	// Active?
	ac := trim1(must(exec.Command("systemctl", "is-active", unit).CombinedOutput()))
	if ac == "" {
		ac = "unknown"
	}
	si.Active = ac
	return si
}

func serviceHuman(si ServiceInfo) string {
	if !si.Installed {
		return "Service is not installed"
	}
	en := si.Enabled
	switch en {
	case "enabled", "disabled", "static", "indirect":
	default:
		en = "unknown"
	}
	var act string
	switch si.Active {
	case "active":
		act = "started"
	case "inactive":
		act = "stopped"
	case "failed":
		act = "failed"
	default:
		act = "unknown"
	}
	return fmt.Sprintf("Service is %s and %s", en, act)
}

func shOut(cmd string) string {
	out, _ := exec.Command("sh", "-lc", cmd).CombinedOutput()
	return string(out)
}

var (
	reAckOnly = regexp.MustCompile(`tcp flags (?:& \(syn\|ack\) == ack|ack / syn,ack)`)
	reSynAck  = regexp.MustCompile(`tcp flags (?:& \(syn\|ack\) == \(syn\|ack\)|syn,ack / syn,ack)`)
	reNoSyn   = regexp.MustCompile(`tcp flags (?:& syn == 0|! syn)`)
)

func Run(args []string) {

	// optional enrich (δεν διαβάζουμε config· ψάχνει μόνο σε standard dirs)
	en, _ := enrich.New("/etc/cfm", "./configs")
	defer func() {
		if en != nil {
			en.Close()
		}
	}()

	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	showTimings := fs.Bool("timings", false, "print per-section timings")
	noTTL := fs.Bool("no-ttl", false, "skip TTL summary (faster)")
	cacheTTL := fs.Duration("cache-ttl", 0, "cache table/sets summary for duration (example: 5s)")
	_ = fs.Parse(args)
	timing := make(map[string]int64)
	printTimings := func() {
		if !*showTimings {
			return
		}
		fmt.Println("\nTiming (ms):")
		keys := make([]string, 0, len(timing))
		for k := range timing {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-22s %d\n", k+":", timing[k])
		}
	}

	// Daemon/Service state
	di := getDaemonInfo()
	si := getUnitServiceInfo("cfm.service")

	// 1) Table/sets summary (ίδιο output με το παλιό runStatus)
	t0 := time.Now()
	st, fromCache := readCachedTableSummary(*cacheTTL)
	if !fromCache {
		st = readTableSummary()
		if *cacheTTL > 0 {
			writeCachedTableSummary(st)
		}
	}
	timing["table_summary_ms"] = time.Since(t0).Milliseconds()
	if fromCache {
		timing["table_summary_cache_hit"] = 1
	} else {
		timing["table_summary_cache_hit"] = 0
	}
	st.Daemon = di
	st.Service = si

	if *asJSON {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		return
	}

	hdrLeft := "CFM daemon not running"
	if di.Running && len(di.PIDs) > 0 {
		hdrLeft = fmt.Sprintf("CFM daemon running (PID:%d)", di.PIDs[0])
	}
	fmt.Printf("-%s | %s-\n", hdrLeft, serviceHuman(si))

	printSummary(st)

	// --- Challenge section (nft + journal) ---
	t0 = time.Now()
	printChallengeStatus(st, en)
	timing["challenge_ms"] = time.Since(t0).Milliseconds()

	// --- TTL summary (manual hosts + nets) ---
	if st.TablePresent && !*noTTL {
		t0 = time.Now()
		// BLOCK v4
		b4hTTL, b4hTot := countTTLInSet("block_v4")
		b4nTTL, b4nTot := countTTLInSet("block_v4_nets")
		// BLOCK v6
		b6hTTL, b6hTot := countTTLInSet("block_v6")
		b6nTTL, b6nTot := countTTLInSet("block_v6_nets")
		// ALLOW v4
		a4hTTL, a4hTot := countTTLInSet("allow_v4")
		a4nTTL, a4nTot := countTTLInSet("allow_v4_nets")
		// ALLOW v6
		a6hTTL, a6hTot := countTTLInSet("allow_v6")
		a6nTTL, a6nTot := countTTLInSet("allow_v6_nets")

		fmt.Println("TTL summary:")
		fmt.Printf("  BLOCK v4: %d/%d with TTL\n", b4hTTL+b4nTTL, b4hTot+b4nTot)
		fmt.Printf("  BLOCK v6: %d/%d with TTL\n", b6hTTL+b6nTTL, b6hTot+b6nTot)
		if (a4hTot + a4nTot + a6hTot + a6nTot) > 0 {
			fmt.Printf("  ALLOW v4: %d/%d with TTL\n", a4hTTL+a4nTTL, a4hTot+a4nTot)
			fmt.Printf("  ALLOW v6: %d/%d with TTL\n", a6hTTL+a6nTTL, a6hTot+a6nTot)
		}
		timing["ttl_summary_ms"] = time.Since(t0).Milliseconds()
	}

	// --- Health snapshot (works even if daemon is not running) ---
	t0 = time.Now()
	hs := health.SnapshotNow()
	timing["health_ms"] = time.Since(t0).Milliseconds()
	fmt.Printf("\n ====================================================================== \n")
	fmt.Printf("\nHealth:\n")
	fmt.Printf("  Hostname: %s\n", hs.Host)
	fmt.Printf("  CPU load: %.2f (1m)\n", hs.Load1)
	fmt.Printf("  RAM: %.1f%%\n", hs.RamUsedPct)
	fmt.Printf("  Disk /: %.1f%%\n", hs.DiskRootPct)
	fmt.Printf("  Connections: %d (EST:%d SYN_RECV:%d LISTEN:%d)\n",
		hs.TCP["total"], hs.TCP["ESTABLISHED"], hs.TCP["SYN_RECV"], hs.TCP["LISTEN"])

	if hs.Mdadm != "" && hs.Mdadm != "NO RAID" {
		fmt.Printf("  RAID: %s\n", hs.Mdadm)
	}

	// Compact SMART summary
	if len(hs.Smart) > 0 {
		total, fails := 0, 0
		temps := make([]string, 0, 3)
		for dev, info := range hs.Smart {
			total++
			h := strings.ToUpper(info.Health)
			if strings.Contains(h, "FAIL") || strings.Contains(h, "CRIT") {
				fails++
			}
			if info.TempC != "" && len(temps) < 3 {
				temps = append(temps, fmt.Sprintf("%s=%sC", dev, info.TempC))
			}
		}
		if fails > 0 {
			fmt.Printf("  SMART: FAIL=%d/%d", fails, total)
		} else {
			fmt.Printf("  SMART: PASS (%d)", total)
		}
		if len(temps) > 0 {
			fmt.Printf(" | temps: %s", strings.Join(temps, ", "))
		}
		fmt.Println()
	}
	fmt.Printf("\n ====================================================================== \n")

	// --- NEW: Conntrack usage ---
	t0 = time.Now()
	if ct, mx, err := readConntrackUsage(); err == nil && mx > 0 {
		p := float64(ct) * 100 / float64(mx)
		fmt.Printf("Conntrack: %d / %d (%.0f%%)\n", ct, mx, p)
	}
	timing["conntrack_usage_ms"] = time.Since(t0).Milliseconds()

	// --- Conntrack + locals + TCP_IN ports (needed for TopN) ---
	t0 = time.Now()
	entries, err := readConntrack()
	if err != nil {
		printTimings()
		return
	}
	locals := localIPs()
	tcpIn := readTCPInPorts()
	timing["conntrack_scan_ms"] = time.Since(t0).Milliseconds()

	// 2) Top N από conntrack (inbound προς TCP_IN)
	//    - Χρησιμοποίησε τα entries/locals/tcpIn που ήδη υπολογίστηκαν πριν το printRecent
	if len(tcpIn) == 0 {
		// καμία πολιτική TCP_IN φορτωμένη — δεν δείχνουμε Top N
		printTimings()
		return
	}

	t0 = time.Now()
	total, byState, topPorts, topIPs := topNStats(entries, tcpIn, locals, topN)
	timing["topn_aggregate_ms"] = time.Since(t0).Milliseconds()

	fmt.Printf("\nConnections: total=%d", total)
	if len(byState) > 0 {
		fmt.Print(" (")
		i := 0
		for st, c := range byState {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s=%d", st, c)
			i++
		}
		fmt.Print(")")
	}
	fmt.Println()

	if len(topPorts) > 0 {
		fmt.Println("Top ports (active inbound conns):")
		for _, kv := range topPorts {
			fmt.Printf("  :%-5s  %6d\n", kv.Key, kv.Count)
		}
	}

	if len(topIPs) > 0 {
		t0 = time.Now()
		fmt.Println("Top remote IPs (active inbound conns):")
		for _, h := range topIPs {
			// --- extras: states & ports ---
			states := stateBreakdownByIP(entries, tcpIn, locals, h.IP)
			ports := portBreakdownByIP(entries, tcpIn, locals, h.IP)

			var extras []string
			if est := states["ESTABLISHED"]; est > 0 {
				extras = append(extras, fmt.Sprintf("EST:%d", est))
			}
			if syn := states["SYN_SENT"]; syn > 0 {
				extras = append(extras, fmt.Sprintf("SYN:%d", syn))
			}
			if tw := states["TIME_WAIT"]; tw > 0 {
				extras = append(extras, fmt.Sprintf("TW:%d", tw))
			}
			// top port μόνο (όπως το παράδειγμά σου "Port: 443")
			if len(ports) > 0 {
				topPort, topCnt := 0, 0
				for p, c := range ports {
					if c > topCnt {
						topPort, topCnt = p, c
					}
				}
				// αν θέλεις μόνο το port χωρίς "=count", βάλε fmt.Sprintf("Port:%d", topPort)
				extras = append(extras, fmt.Sprintf("Port:%d", topPort))
			}
			extraStr := ""
			if len(extras) > 0 {
				extraStr = " - " + strings.Join(extras, ", ")
			}

			// --- enrich meta όπως πριν ---
			meta := ""
			if en != nil {
				r := en.Lookup(h.IP)
				metaParts := make([]string, 0, 3)
				if r.ASNName != "" {
					metaParts = append(metaParts, r.ASNName)
				} else if r.ASN != 0 {
					metaParts = append(metaParts, "AS"+strconv.Itoa(int(r.ASN)))
				}
				if r.Country != "" {
					if r.City != "" {
						metaParts = append(metaParts, r.Country+" / "+r.City)
					} else {
						metaParts = append(metaParts, r.Country)
					}
				}
				if r.PTR != "" {
					metaParts = append(metaParts, r.PTR)
				}
				if len(metaParts) > 0 {
					meta = " - [" + strings.Join(metaParts, " | ") + "]"
				}
			}

			// Μικραίνω το padding της IP για να χωρέσουν όλα σε μία γραμμή
			fmt.Printf("  %-17s %6d%s%s\n", h.IP, h.Count, extraStr, meta)
		}
		timing["topn_enrich_print_ms"] = time.Since(t0).Milliseconds()
	}

	// --- Bridge / Interceptor (best-effort diagnostics) ---
	t0 = time.Now()
	printBridgeInterceptorStatus()
	timing["bridge_interceptor_ms"] = time.Since(t0).Milliseconds()

	printTimings()

}

func printBridgeInterceptorStatus() {
	fmt.Println("\n---- Bridge / Interceptor ----")

	dnatState := "OFF"
	if on, err := dnat.Status(nft.New()); err == nil && on {
		dnatState = "ON"
	}

	openrestySvc := getUnitServiceInfo("openresty.service")
	angieSvc := getUnitServiceInfo("angie.service")

	sockState := socketStatus("/var/run/sslcollector.sock")

	cfmToken := readLuaToken("/var/lib/cfm/lua/cfm_token.lua")
	bridgeToken := readLuaToken("/var/lib/cfm/lua/cfm_bridge_token.lua")

	orBridge := readLuaToken("/usr/local/openresty/nginx/lua/cfm_bridge_token.lua")
	angieBridge := readLuaToken("/etc/angie/lua/cfm_bridge_token.lua")

	fmt.Printf("  %-24s %s\n", "DNAT:", dnatState)
	fmt.Printf("  %-24s %s\n", "OpenResty:", serviceTriple(openrestySvc))
	fmt.Printf("  %-24s %s\n", "Angie:", serviceTriple(angieSvc))
	fmt.Printf("  %-24s %s\n", "sslcollector.sock:", sockState)
	fmt.Printf("  %-24s %s\n", "cfm_token:", tokenHealth(cfmToken))
	fmt.Printf("  %-24s %s\n", "bridge_token:", tokenHealth(bridgeToken))
	fmt.Printf("  %-24s %s\n", "openresty bridge link:", tokenLinkHealth(bridgeToken, orBridge))
	fmt.Printf("  %-24s %s\n", "angie bridge link:", tokenLinkHealth(bridgeToken, angieBridge))
}

func serviceTriple(s ServiceInfo) string {
	installed := "not-installed"
	if s.Installed {
		installed = "installed"
	}
	return fmt.Sprintf("%s/%s/%s", installed, s.Enabled, s.Active)
}

func socketStatus(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "MISSING"
		}
		return "PERM"
	}
	if st.Mode()&os.ModeSocket == 0 {
		return "PERM"
	}
	f, err := os.Open(path)
	if err != nil {
		return "PERM"
	}
	_ = f.Close()
	return "OK"
}

type luaTokenProbe struct {
	Token   string
	Present bool
	Valid   bool
}

var (
	luaReturnRe = regexp.MustCompile(`(?m)^\s*return\s+["']([^"']+)["']\s*$`)
	badTokenRe  = regexp.MustCompile(`(?i)^(supersecret|changeme|secret|password|default|token|test|demo|placeholder)$`)
)

func readLuaToken(path string) luaTokenProbe {
	b, err := os.ReadFile(path)
	if err != nil {
		return luaTokenProbe{}
	}
	m := luaReturnRe.FindSubmatch(b)
	if len(m) < 2 {
		return luaTokenProbe{Present: true}
	}
	tok := strings.TrimSpace(string(m[1]))
	return luaTokenProbe{
		Token:   tok,
		Present: true,
		Valid:   isStrongToken(tok),
	}
}

func isStrongToken(tok string) bool {
	t := strings.TrimSpace(tok)
	return len(t) >= 32 && !badTokenRe.MatchString(t)
}

func tokenHealth(t luaTokenProbe) string {
	if !t.Present {
		return "MISSING"
	}
	if !t.Valid {
		return "INVALID"
	}
	return "OK"
}

func tokenLinkHealth(shared, local luaTokenProbe) string {
	if !local.Present {
		return "MISSING"
	}
	if !shared.Valid || !local.Valid {
		return "MISMATCH"
	}
	if shared.Token == local.Token {
		return "OK"
	}
	return "MISMATCH"
}

// ---------------------------------------------------------------------------
// Part A: nft summary (ό,τι έκανες παλιότερα, απλώς μεταφερμένο εδώ)
// ---------------------------------------------------------------------------

type statusRow struct {
	Set      string `json:"set"`
	Action   string `json:"action"`
	Family   string `json:"family"`
	Scope    string `json:"scope"`
	Feed     string `json:"feed"`
	Hosts    int    `json:"hosts"`
	Prefixes int    `json:"prefixes"`
}

type statusOut struct {
	TablePresent bool        `json:"table_present"`
	RulesPresent bool        `json:"rules_present"`
	Sets         []statusRow `json:"sets"`
	Totals       struct {
		Allow   struct{ Hosts, Prefixes, Entries int } `json:"allow"`
		Block   struct{ Hosts, Prefixes, Entries int } `json:"block"`
		Overall int                                    `json:"overall"`
	} `json:"totals"`

	Daemon  DaemonInfo  `json:"daemon"`
	Service ServiceInfo `json:"service"`
}

type statusCacheFile struct {
	CreatedAt int64     `json:"created_at"`
	Summary   statusOut `json:"summary"`
}

func statusCachePath() string {
	base := "/run/cfm"
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		base = os.TempDir()
	}
	return filepath.Join(base, "cfm_status_table_summary.json")
}

func readCachedTableSummary(ttl time.Duration) (statusOut, bool) {
	if ttl <= 0 {
		return statusOut{}, false
	}
	b, err := os.ReadFile(statusCachePath())
	if err != nil {
		return statusOut{}, false
	}
	var c statusCacheFile
	if err := json.Unmarshal(b, &c); err != nil {
		return statusOut{}, false
	}
	if c.CreatedAt <= 0 {
		return statusOut{}, false
	}
	if time.Since(time.Unix(c.CreatedAt, 0)) > ttl {
		return statusOut{}, false
	}
	return c.Summary, true
}

func writeCachedTableSummary(st statusOut) {
	payload, err := json.Marshal(statusCacheFile{CreatedAt: time.Now().Unix(), Summary: st})
	if err != nil {
		return
	}
	_ = os.WriteFile(statusCachePath(), payload, 0o600)
}

func readTableSummary() statusOut {
	out := statusOut{}
	raw, err := exec.Command("nft", "-j", "list", "table", "inet", "cfm").CombinedOutput()
	if err != nil {
		out.TablePresent = false
		out.RulesPresent = false
		return out
	}
	out.TablePresent = true

	var parsed struct {
		Nftables []struct {
			Set *struct {
				Family string        `json:"family"`
				Name   string        `json:"name"`
				Table  string        `json:"table"`
				Type   string        `json:"type"`
				Elem   []interface{} `json:"elem"`
			} `json:"set,omitempty"`
			Rule *struct {
				Chain string        `json:"chain"`
				Expr  []interface{} `json:"expr"`
			} `json:"rule,omitempty"`
		} `json:"nftables"`
	}
	_ = json.Unmarshal(raw, &parsed)
	rc := 0
	for _, it := range parsed.Nftables {
		if it.Rule != nil {
			rc++
		}
	}
	out.RulesPresent = rc > 0

	for _, it := range parsed.Nftables {
		if it.Set == nil {
			continue
		}
		s := it.Set
		action, family, scope, feed, ok := classifyStatusSet(s.Name, s.Type)
		if !ok {
			continue
		}
		if s.Type == "ipv4_addr" && family != "v4" {
			family = "v4"
		}
		if s.Type == "ipv6_addr" && family != "v6" {
			family = "v6"
		}
		row := statusRow{Set: s.Name, Action: action, Family: family, Scope: scope, Feed: feed}
		for _, el := range s.Elem {
			switch el.(type) {
			case string:
				row.Hosts++
			case map[string]interface{}:
				if _, ok := el.(map[string]interface{})["prefix"]; ok {
					row.Prefixes++
				}
			}
		}
		out.Sets = append(out.Sets, row)
		if action == "ALLOW" {
			out.Totals.Allow.Hosts += row.Hosts
			out.Totals.Allow.Prefixes += row.Prefixes
		} else {
			out.Totals.Block.Hosts += row.Hosts
			out.Totals.Block.Prefixes += row.Prefixes
		}
	}
	out.Totals.Allow.Entries = out.Totals.Allow.Hosts + out.Totals.Allow.Prefixes
	out.Totals.Block.Entries = out.Totals.Block.Hosts + out.Totals.Block.Prefixes
	out.Totals.Overall = out.Totals.Allow.Entries + out.Totals.Block.Entries

	sort.Slice(out.Sets, func(i, j int) bool {
		a, b := out.Sets[i], out.Sets[j]
		ai := 1
		if a.Scope == "manual" {
			ai = 0
		}
		bj := 1
		if b.Scope == "manual" {
			bj = 0
		}
		if ai != bj {
			return ai < bj
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Feed != b.Feed {
			return a.Feed < b.Feed
		}
		return a.Set < b.Set
	})
	return out
}

func printSummary(st statusOut) {
	if st.TablePresent {
		if st.RulesPresent {
			fmt.Println("Firewall: active (table inet cfm present, rules installed)")
		} else {
			fmt.Println("Firewall: table present, but no rules found")
		}
	} else {
		fmt.Println("Firewall: inactive (table inet cfm NOT present)")
		return
	}
	fmt.Printf("Totals: ALLOW=%d (hosts=%d, prefixes=%d)  BLOCK=%d (hosts=%d, prefixes=%d)  Overall=%d\n",
		st.Totals.Allow.Entries, st.Totals.Allow.Hosts, st.Totals.Allow.Prefixes,
		st.Totals.Block.Entries, st.Totals.Block.Hosts, st.Totals.Block.Prefixes,
		st.Totals.Overall,
	)
	fmt.Println("Sets:")
	for _, r := range st.Sets {
		extra := ""
		if r.Feed != "" {
			extra = " [feed: " + r.Feed + "]"
		}
		fmt.Printf(" - %-5s %-2s %-6s %-35s hosts=%-5d prefixes=%-5d%s\n",
			r.Action, r.Family, r.Scope, r.Set, r.Hosts, r.Prefixes, extra)
	}
}

func classifyStatusSet(name, typ string) (action, family, scope, feed string, ok bool) {
	switch name {
	case "allow_v4":
		return "ALLOW", "v4", "manual", "", true
	case "allow_v6":
		return "ALLOW", "v6", "manual", "", true
	case "allow_dyn_v4":
		return "ALLOW", "v4", "dyn", "", true
	case "allow_dyn_v6":
		return "ALLOW", "v6", "dyn", "", true
	case "block_v4":
		return "BLOCK", "v4", "manual", "", true
	case "block_v6":
		return "BLOCK", "v6", "manual", "", true
	}

	// --- NEW: recognize manual *_nets sets so they show up in "Sets:" ---
	switch name {
	case "allow_v4_nets":
		return "ALLOW", "v4", "manual", "", true
	case "allow_v6_nets":
		return "ALLOW", "v6", "manual", "", true
	case "block_v4_nets":
		return "BLOCK", "v4", "manual", "", true
	case "block_v6_nets":
		return "BLOCK", "v6", "manual", "", true
	}

	if strings.HasPrefix(name, "allow_ext_") || strings.HasPrefix(name, "block_ext_") {
		parts := strings.Split(name, "_")
		if len(parts) >= 5 {
			action = strings.ToUpper(parts[0])
			fam := parts[2]
			if fam == "v4" || fam == "v6" {
				family = fam
			}
			if parts[3] == "hosts" || parts[3] == "nets" {
				scope = parts[3]
			}
			feed = strings.Join(parts[4:], "_")
			return action, family, scope, feed, true
		}
	}
	return "", "", "", "", false
}

// ---------------------------------------------------------------------------
// Part B: conntrack + aggregations (χωρίς config)
// ---------------------------------------------------------------------------

type ctEntry struct {
	Proto string
	State string
	Src   string
	Dst   string
	Sport int
	Dport int
}

func readConntrack() ([]ctEntry, error) {
	path := "/proc/net/nf_conntrack"
	if _, err := os.Stat(path); err != nil {
		path = "/proc/net/ip_conntrack"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []ctEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		parts := strings.Fields(ln)
		if len(parts) < 8 {
			continue
		}
		proto := parts[2]
		state := parts[5]
		var src, dst string
		var sport, dport int
		for _, p := range parts {
			if strings.HasPrefix(p, "src=") && src == "" {
				src = strings.TrimPrefix(p, "src=")
			} else if strings.HasPrefix(p, "dst=") && dst == "" {
				dst = strings.TrimPrefix(p, "dst=")
			} else if strings.HasPrefix(p, "sport=") && sport == 0 {
				sport, _ = strconv.Atoi(strings.TrimPrefix(p, "sport="))
			} else if strings.HasPrefix(p, "dport=") && dport == 0 {
				dport, _ = strconv.Atoi(strings.TrimPrefix(p, "dport="))
			}
		}
		if src == "" || dst == "" || dport == 0 {
			continue
		}
		out = append(out, ctEntry{Proto: proto, State: state, Src: src, Dst: dst, Sport: sport, Dport: dport})
	}
	return out, sc.Err()
}

func localIPs() map[string]struct{} {
	m := make(map[string]struct{})
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if v.IP != nil {
					m[v.IP.String()] = struct{}{}
				}
			case *net.IPAddr:
				if v.IP != nil {
					m[v.IP.String()] = struct{}{}
				}
			}
		}
	}
	return m
}

type topKV struct {
	Key   string
	Count int
}

type topHost struct {
	IP    string
	Count int
}

func topNStats(entries []ctEntry, tcpIn map[int]struct{}, locals map[string]struct{}, n int) (total int, byState map[string]int, ports []topKV, hosts []topHost) {
	byState = map[string]int{}
	mp := map[int]int{}
	ipHits := map[string]int{}

	for _, e := range entries {
		total++
		if e.Proto == "tcp" {
			byState[e.State]++
		}
		_, inbound := locals[e.Dst]
		_, isServer := tcpIn[e.Dport]
		if inbound && isServer {
			mp[e.Dport]++
			ipHits[e.Src]++
		}
	}

	for p, c := range mp {
		ports = append(ports, topKV{Key: strconv.Itoa(p), Count: c})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Count > ports[j].Count })
	if len(ports) > n {
		ports = ports[:n]
	}

	for ip, c := range ipHits {
		hosts = append(hosts, topHost{IP: ip, Count: c})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Count > hosts[j].Count })
	if len(hosts) > n {
		hosts = hosts[:n]
	}
	return
}

// ---------------------------------------------------------------------------
// Part C: read TCP_IN from nft (no config)
// ---------------------------------------------------------------------------

func readTCPInPorts() map[int]struct{} {
	out := make(map[int]struct{})
	raw, err := exec.Command("nft", "-j", "list", "set", "inet", "cfm", "tcp_in_ports").CombinedOutput()
	if err != nil {
		return out
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return out
	}
	arr, _ := root["nftables"].([]any)
	for _, it := range arr {
		m, _ := it.(map[string]any)
		setObj, ok := m["set"].(map[string]any)
		if !ok {
			continue
		}
		elems, _ := setObj["elem"].([]any)
		if len(elems) == 0 {
			elems, _ = setObj["elements"].([]any)
		}
		for _, e := range elems {
			switch v := e.(type) {
			case float64:
				p := int(v)
				if p > 0 && p <= 65535 {
					out[p] = struct{}{}
				}
			case string:
				if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= 65535 {
					out[p] = struct{}{}
				}
			case map[string]any:
				// Handle {"range":[from,to]}
				if rng, ok := v["range"].([]any); ok && len(rng) == 2 {
					from := toInt(rng[0])
					to := toInt(rng[1])
					addPortRange(out, from, to)
					continue
				}
				// Handle {"interval":{"from":X,"to":Y}} (κάποιες εκδόσεις JSON)
				if iv, ok := v["interval"].(map[string]any); ok {
					from := toInt(iv["from"])
					to := toInt(iv["to"])
					addPortRange(out, from, to)
					continue
				}
			}
		}
	}
	return out
}

// helpers για ranges
func toInt(x any) int {
	switch t := x.(type) {
	case float64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}
func addPortRange(out map[int]struct{}, from, to int) {
	if from <= 0 || to <= 0 || to < from {
		return
	}
	// ασφάλεια: αν το range είναι τεράστιο, κόφ’το (status CLI είναι lightweight)
	if to-from > 5000 { // adjust αν θέλεις
		to = from + 5000
	}
	if to > 65535 {
		to = 65535
	}
	for p := from; p <= to; p++ {
		out[p] = struct{}{}
	}
}

// --- Conntrack usage (count/max) ---
func readIntFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	return strconv.Atoi(s)
}
func readConntrackUsage() (count, max int, err error) {
	count, err = readIntFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return
	}
	max, err = readIntFile("/proc/sys/net/netfilter/nf_conntrack_max")
	return
}

// helper to read counters from nft JSON
func readNftCounters() (map[string]int, error) {
	out := map[string]int{}
	b, err := exec.Command("nft", "-j", "list", "counters", "table", "inet", "cfm").CombinedOutput()
	if err != nil {
		return out, err
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return out, err
	}
	arr, _ := root["nftables"].([]any)
	for _, it := range arr {
		m, _ := it.(map[string]any)
		c, ok := m["counter"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := c["name"].(string)
		pkts := 0
		if pk, ok := c["packets"].(float64); ok {
			pkts = int(pk)
		}
		if name != "" {
			out[name] = pkts
		}
	}
	return out, nil
}

// helper list count elements with  "expires/timeout"
func countTTLInSet(set string) (withTTL, total int) {
	s := shOut("nft list set inet cfm " + set + " 2>/dev/null")

	for _, m := range reElem.FindAllStringSubmatch(s, -1) { // reElem matches IP or CIDR
		addr := strings.Trim(m[1], ",}")
		valid := false
		if strings.Contains(addr, "/") {
			if _, _, err := net.ParseCIDR(addr); err == nil {
				valid = true
			}
		} else {
			if net.ParseIP(addr) != nil {
				valid = true
			}
		}
		if !valid {
			continue
		}

		total++
		if len(m) > 2 && strings.Trim(m[2], ",}") != "" {
			withTTL++
		}
	}
	return
}

// Parse "nft list set inet cfm <set>" and return up to max IPs with TTL if present.
type recentHit struct {
	IP      string
	Expires string // e.g. "59m31s" (empty if not parsed)
}

var (
	// NEW: match IP **or CIDR** (v4/v6) plus optional expires/timeout
	reElem = regexp.MustCompile(
		`(?P<addr>(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|` +
			`[0-9a-fA-F:]+(?:/\d{1,3})?)` +
			`(?:\s+(?:expires|timeout)\s+(?P<ttl>[0-9smhd:]+))?`,
	)
)

func listSetElemsDetailed(set string, max int) []recentHit {
	s := shOut("nft list set inet cfm " + set + " 2>/dev/null")
	out := make([]recentHit, 0, max)
	for _, m := range reElem.FindAllStringSubmatch(s, -1) {
		ip := strings.Trim(m[1], ",}")
		// keep only host IPs here (recent hits list is per-IP)
		if net.ParseIP(strings.TrimSuffix(ip, "/32")) == nil || strings.Contains(ip, "/") {
			continue
		}
		ttl := ""
		if len(m) > 2 {
			ttl = strings.Trim(m[2], ",}")
		}
		out = append(out, recentHit{IP: ip, Expires: ttl})
		if len(out) >= max {
			break
		}
	}
	return out
}

//helpers for IP status conntrack

// helpers for IP status conntrack (inbound προς local + μόνο TCP_IN ports)
func stateBreakdownByIP(entries []ctEntry, tcpIn map[int]struct{}, locals map[string]struct{}, ip string) map[string]int {
	m := map[string]int{}
	for _, e := range entries {
		if e.Src != ip {
			continue
		}
		// ίδια λογική με topNStats: inbound προς local & dport ∈ TCP_IN
		if _, inbound := locals[e.Dst]; !inbound {
			continue
		}
		if _, isServer := tcpIn[e.Dport]; !isServer {
			continue
		}
		m[e.State]++
	}
	return m
}

func portBreakdownByIP(entries []ctEntry, tcpIn map[int]struct{}, locals map[string]struct{}, ip string) map[int]int {
	m := map[int]int{}
	for _, e := range entries {
		if e.Src != ip {
			continue
		}
		if _, inbound := locals[e.Dst]; !inbound {
			continue
		}
		if _, isServer := tcpIn[e.Dport]; !isServer {
			continue
		}
		m[e.Dport]++
	}
	return m
}

//////////////CHALLENGE//////////////
// ---------------------------------------------------------------------------
// Challenge printing
// ---------------------------------------------------------------------------

func printChallengeStatus(st statusOut, en *enrich.Enricher) {
	// Enabled if challenge sets or chains exist
	if !st.TablePresent {
		return
	}

	// Check for presence via nft output (cheap + robust)
	pre := listChainFiltered("prerouting", "cfm_challenge_nat_")
	guard := listChainFiltered("challenge_guard", "cfm_challenge_guard_")

	// Also treat as enabled if sets exist even if chain listing fails
	v4 := listSetElemsDetailed("challenge_v4", 50)
	v6 := listSetElemsDetailed("challenge_v6", 50)

	enabled := len(pre) > 0 || len(guard) > 0 || len(v4) > 0 || len(v6) > 0
	if !enabled {
		return
	}

	fmt.Printf("\n---- Challenge ----\n")

	// Prerouting rules
	if len(pre) > 0 {
		fmt.Println("Prerouting OK:")
		for _, ln := range pre {
			fmt.Printf("  %s\n", ln)
		}
	} else {
		fmt.Println("Prerouting: MISSING (no cfm_challenge_nat_* rules found)")
	}

	// Guard chain rules
	if len(guard) > 0 {
		fmt.Println("Guard chain OK (challenge_guard):")
		for _, ln := range guard {
			fmt.Printf("  %s\n", ln)
		}
	} else {
		fmt.Println("Guard chain: MISSING (no cfm_challenge_guard_* rules found)")
	}

	// Current challenged IPs with TTLs
	if len(v4) > 0 || len(v6) > 0 {
		fmt.Println("Current IPs challenged (TTL):")
		if len(v4) > 0 {
			fmt.Println("  v4:")
			for _, h := range v4 {
				if h.Expires != "" {
					fmt.Printf("    %-16s  expires %s\n", h.IP, h.Expires)
				} else {
					fmt.Printf("    %-16s\n", h.IP)
				}
			}
		}
		if len(v6) > 0 {
			fmt.Println("  v6:")
			for _, h := range v6 {
				if h.Expires != "" {
					fmt.Printf("    %-39s  expires %s\n", h.IP, h.Expires)
				} else {
					fmt.Printf("    %-39s\n", h.IP)
				}
			}
		}
	}

	// Journal-based totals (since service start)
	since, ok := serviceActiveSince()
	if ok {
		ch, sol, topIPs, topASNs := readChallengeJournalStats(since, en)
		fmt.Printf("Totals since service start (%s): %d challenged / %d solved\n", since, ch, sol)

		if len(topIPs) > 0 {
			fmt.Println("Top 5 IPs challenged:")
			for _, kv := range topIPs {
				fmt.Printf("  %-17s %6d\n", kv.Key, kv.Count)
			}
		}
		if len(topASNs) > 0 {
			fmt.Println("Top 5 ASNs challenged:")
			for _, kv := range topASNs {
				fmt.Printf("  %-28s %6d\n", kv.Key, kv.Count)
			}
		}
	} else {
		// Still show a hint
		fmt.Println("Totals since startup: (unavailable - systemd/journalctl not found or service not running)")
	}
}

func listChainFiltered(chain, contains string) []string {
	// Use -a so handles present; but we print compact lines without the "table inet cfm {"
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", "cfm", chain).CombinedOutput()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	var keep []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		// skip wrappers
		if strings.HasPrefix(ln, "table ") || strings.HasPrefix(ln, "chain ") || ln == "}" {
			continue
		}
		if contains != "" && !strings.Contains(ln, contains) {
			continue
		}
		keep = append(keep, ln)
	}
	return keep
}

func serviceActiveSince() (string, bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", false
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return "", false
	}
	out, err := exec.Command("systemctl", "show", "-p", "ActiveEnterTimestamp", "cfm.service").CombinedOutput()
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(out))
	s = strings.TrimPrefix(s, "ActiveEnterTimestamp=")
	s = strings.TrimSpace(s)
	if s == "" || s == "n/a" {
		return "", false
	}
	// journalctl likes it as-is (e.g. "Tue 2026-02-17 16:12:03 EET")
	return s, true
}

var (
	reChalIP = regexp.MustCompile(`\bip=([0-9a-fA-F:.]+)\b`)
)

func readChallengeJournalStats(since string, en *enrich.Enricher) (challenged, solved int, topIPs, topASNs []HitCount) {
	// Try journald first (if service logs go there)
	lines := journalChallengeLines(since)

	ipCounts := map[string]int{}
	asnCounts := map[string]int{}

	for _, ln := range lines {
		if !strings.Contains(ln, "[challenge]") && !strings.Contains(ln, " [challenge]") {
			continue
		}
		m := reChalIP.FindStringSubmatch(ln)
		if len(m) < 2 {
			continue
		}
		ip := m[1]

		// Count "challenged" only when actually enforced (not suppressed)
		if strings.Contains(ln, "enforced=challenge") && !strings.Contains(ln, "challenge_suppressed") {
			challenged++
			ipCounts[ip]++

			// ASN bucket (best-effort)
			if en != nil {
				r := en.Lookup(ip)
				if r.ASN != 0 {
					key := fmt.Sprintf("AS%d", r.ASN)
					if r.ASNName != "" {
						key = fmt.Sprintf("AS%d %s", r.ASN, r.ASNName)
					}
					asnCounts[key]++
				}
			}
		}

		if strings.Contains(ln, "result=solved") {
			solved++
		}
	}

	topIPs = topHitCounts(ipCounts, 5)
	topASNs = topHitCounts(asnCounts, 5)

	// Fallback: if journald is empty, parse file logs (common in your setup)
	if challenged == 0 && solved == 0 {
		fileLines := fileChallengeLinesSince(since)
		if len(fileLines) > 0 {
			ipCounts = map[string]int{}
			asnCounts = map[string]int{}
			for _, ln := range fileLines {
				if !strings.Contains(ln, "[challenge]") && !strings.Contains(ln, " [challenge]") {
					continue
				}
				m := reChalIP.FindStringSubmatch(ln)
				if len(m) < 2 {
					continue
				}
				ip := m[1]

				if strings.Contains(ln, "enforced=challenge") && !strings.Contains(ln, "challenge_suppressed") {
					challenged++
					ipCounts[ip]++
					if en != nil {
						r := en.Lookup(ip)
						if r.ASN != 0 {
							key := fmt.Sprintf("AS%d", r.ASN)
							if r.ASNName != "" {
								key = fmt.Sprintf("AS%d %s", r.ASN, r.ASNName)
							}
							asnCounts[key]++
						}
					}
				}
				if strings.Contains(ln, "result=solved") {
					solved++
				}
			}
			topIPs = topHitCounts(ipCounts, 5)
			topASNs = topHitCounts(asnCounts, 5)
		}
	}

	return
}

func journalChallengeLines(since string) []string {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}
	// -o cat: no syslog prefixes, easier parsing
	cmd := exec.Command("journalctl",
		"-u", "cfm.service",
		"--no-pager",
		"-o", "cat",
		"--since", since,
		"-n", "20000",
	)
	b, err := cmd.CombinedOutput()
	if err != nil || len(b) == 0 {
		return nil
	}
	return strings.Split(string(b), "\n")
}

func fileChallengeLinesSince(since string) []string {
	// Parse since time (best-effort). If we can't parse, we still return last lines.
	var sinceT time.Time
	var haveSince bool
	if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", since); err == nil {
		sinceT, haveSince = t, true
	}

	paths := []string{
		"/var/log/cfm-service.log",
		"/var/log/cfm/cfm.challenges.log",
		"/var/log/cfm.log",
	}

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()

		// Read only tail (last ~2MB) to keep it fast
		st, _ := f.Stat()
		if st != nil && st.Size() > 2*1024*1024 {
			_, _ = f.Seek(st.Size()-2*1024*1024, io.SeekStart)
		}
		b, _ := io.ReadAll(f)
		lines := strings.Split(string(b), "\n")

		// Optional time filter: lines start with "YYYY-MM-DD HH:MM:SS ..."
		if haveSince {
			var out []string
			for _, ln := range lines {
				if len(ln) < 19 {
					continue
				}
				ts := ln[:19]
				t, err := time.Parse("2006-01-02 15:04:05", ts)
				if err != nil {
					continue
				}
				if t.Before(sinceT) {
					continue
				}
				out = append(out, ln)
			}
			return out
		}
		return lines
	}
	return nil
}

func topHitCounts(m map[string]int, n int) []HitCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]HitCount, 0, len(m))
	for k, v := range m {
		out = append(out, HitCount{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
