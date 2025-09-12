package status

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"bytes"

	"cfm/internal/enrich"
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

type nftCounter struct{ Name string; Packets int }

func getDaemonInfo() DaemonInfo {
	if _, err := exec.LookPath("pgrep"); err == nil {
		out, _ := exec.Command("pgrep", "-fa", "cfm daemon").CombinedOutput()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		var pids []int; var cmds []string
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" { continue }
			parts := strings.Fields(ln)
			if len(parts) < 2 { continue }
			pid, _ := strconv.Atoi(parts[0])
			cmd := strings.TrimSpace(strings.TrimPrefix(ln, parts[0]))
			if !strings.Contains(cmd, "cfm") || !strings.Contains(cmd, "daemon") { continue }
			pids = append(pids, pid); cmds = append(cmds, cmd)
		}
		return DaemonInfo{Running: len(pids) > 0, PIDs: pids, Cmdlines: cmds}
	}
	// fallback με ps
	out, _ := exec.Command("ps", "ax", "-o", "pid=,cmd=").CombinedOutput()
	var pids []int; var cmds []string
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln); if ln == "" { continue }
		parts := strings.Fields(ln); if len(parts) < 2 { continue }
		pid, _ := strconv.Atoi(parts[0]); cmd := strings.TrimSpace(strings.TrimPrefix(ln, parts[0]))
		if strings.Contains(cmd, "cfm") && strings.Contains(cmd, "daemon") { pids = append(pids, pid); cmds = append(cmds, cmd) }
	}
	return DaemonInfo{Running: len(pids) > 0, PIDs: pids, Cmdlines: cmds}
}

func trim1(b []byte) string { return strings.TrimSpace(string(b)) }
func must(b []byte, _ error) []byte { return b }

func getServiceInfo() ServiceInfo {
	si := ServiceInfo{}
	if _, err := exec.LookPath("systemctl"); err != nil { return si } // όχι systemd
	// Installed?
	loadOut, _ := exec.Command("systemctl", "show", "-p", "LoadState", "cfm.service").CombinedOutput()
	if bytes.Contains(loadOut, []byte("LoadState=loaded")) { si.Installed = true }
	// Enabled?
	en := trim1(must(exec.Command("systemctl", "is-enabled", "cfm.service").CombinedOutput()))
	if en == "" { en = "unknown" }; si.Enabled = en
	// Active?
	ac := trim1(must(exec.Command("systemctl", "is-active", "cfm.service").CombinedOutput()))
	if ac == "" { ac = "unknown" }; si.Active = ac
	return si
}

func serviceHuman(si ServiceInfo) string {
	if !si.Installed { return "Service is not installed" }
	en := si.Enabled
	switch en { case "enabled","disabled","static","indirect": default: en = "unknown" }
	var act string
	switch si.Active { case "active": act="started"; case "inactive": act="stopped"; case "failed": act="failed"; default: act="unknown" }
	return fmt.Sprintf("Service is %s and %s", en, act)
}



func Run(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	// Daemon/Service state
	di := getDaemonInfo()
	si := getServiceInfo()


	// 1) Table/sets summary (ίδιο output με το παλιό runStatus)
	st := readTableSummary()
	st.Daemon = di
	st.Service = si

	if *asJSON {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		return
	}

	hdrLeft := "CFM daemon not running"
	if di.Running && len(di.PIDs) > 0 { hdrLeft = fmt.Sprintf("CFM daemon running (PID:%d)", di.PIDs[0]) }
	fmt.Printf("-%s | %s-\n", hdrLeft, serviceHuman(si))

	printSummary(st)


// NEW ACK-Guard
if ctrs, err := readNftCounters(); err == nil {
    if v, ok := ctrs["acknew_drop"]; ok && v > 0 {
        fmt.Printf("ACK-NEW drops: %d packets\n", v)
    } else {
        fmt.Println("ACK-NEW drops: 0")
    }
}


// --- NEW: Conntrack usage ---
	if ct, mx, err := readConntrackUsage(); err == nil && mx > 0 {
		p := float64(ct) * 100 / float64(mx)
		fmt.Printf("Conntrack: %d / %d (%.0f%%)\n", ct, mx, p)
	}




	// 2) Top N από conntrack (inbound προς TCP_IN)
	//    - TCP_IN ports: από nft set "tcp_in_ports"
	//    - inbound: conn.Dst ∈ local IPs
	tcpIn := readTCPInPorts()
	if len(tcpIn) == 0 {
		// καμία πολιτική TCP_IN φορτωμένη — δεν δείχνουμε Top N
		return
	}

	entries, err := readConntrack()
	if err != nil {
		return
	}
	locals := localIPs()

	total, byState, topPorts, topIPs := topNStats(entries, tcpIn, locals, topN)

	// optional enrich (δεν διαβάζουμε config· ψάχνει μόνο σε standard dirs)
	en, _ := enrich.New("/etc/cfm", "./configs")
	defer func() {
		if en != nil {
			en.Close()
		}
	}()

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
		fmt.Println("Top remote IPs (active inbound conns):")
		for _, h := range topIPs {
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
					fmt.Printf("  %-39s %6d [%s]\n", h.IP, h.Count, strings.Join(metaParts, " | "))
					continue
				}
			}
			fmt.Printf("  %-39s %6d\n", h.IP, h.Count)
		}
	}
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
		Allow struct{ Hosts, Prefixes, Entries int } `json:"allow"`
		Block struct{ Hosts, Prefixes, Entries int } `json:"block"`
		Overall int                                   `json:"overall"`
	} `json:"totals"`

	Daemon  DaemonInfo  `json:"daemon"`
	Service ServiceInfo `json:"service"`

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
			Set  *struct {
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
		i, _ := strconv.Atoi(t); return i
	default:
		return 0
	}
}
func addPortRange(out map[int]struct{}, from, to int) {
	if from <= 0 || to <= 0 || to < from { return }
	// ασφάλεια: αν το range είναι τεράστιο, κόφ’το (status CLI είναι lightweight)
	if to-from > 5000 { // adjust αν θέλεις
		to = from + 5000
	}
	if to > 65535 { to = 65535 }
	for p := from; p <= to; p++ {
		out[p] = struct{}{}
	}
}


// --- Conntrack usage (count/max) ---
func readIntFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil { return 0, err }
	s := strings.TrimSpace(string(b))
	return strconv.Atoi(s)
}
func readConntrackUsage() (count, max int, err error) {
	count, err = readIntFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil { return }
	max, err = readIntFile("/proc/sys/net/netfilter/nf_conntrack_max")
	return
}




// helper to read counters from nft JSON
func readNftCounters() (map[string]int, error) {
    out := map[string]int{}
    b, err := exec.Command("nft", "-j", "list", "counters", "table", "inet", "cfm").CombinedOutput()
    if err != nil { return out, err }
    var root map[string]any
    if err := json.Unmarshal(b, &root); err != nil { return out, err }
    arr, _ := root["nftables"].([]any)
    for _, it := range arr {
        m, _ := it.(map[string]any)
        c, ok := m["counter"].(map[string]any)
        if !ok { continue }
        name, _ := c["name"].(string)
        pkts := 0
        if pk, ok := c["packets"].(float64); ok { pkts = int(pk) }
        if name != "" { out[name] = pkts }
    }
    return out, nil
}
