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
	"regexp"

	"cfm/internal/enrich"
	"cfm/internal/detectors/health"
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

func shOut(cmd string) string {
	out, _ := exec.Command("sh", "-lc", cmd).CombinedOutput()
	return string(out)
}

func ackguardInstalled() bool {
	s := shOut("nft list chain inet cfm flood 2>/dev/null")
	return strings.Contains(s, "jump ackguard")
}

func ackguardPorts() string {
	s := shOut("nft list set inet cfm ackguard_tcp_ports 2>/dev/null")
	i := strings.Index(s, "elements = {")
	if i == -1 { return "(none)" }
	j := strings.Index(s[i:], "}")
	if j == -1 { return "(none)" }
	inner := strings.TrimSpace(s[i+len("elements = {") : i+j])
	// collapse spaces
	inner = strings.ReplaceAll(inner, "\n", " ")
	inner = strings.Join(strings.Fields(inner), " ")
	// return as-is (e.g., "80, 443, 25-30")
	return strings.ReplaceAll(inner, " ,", ",")
}

type AckguardFeatures struct {
	MatchInvalid  bool
	DropNonSynNew bool
	DropSynAckNew bool
	RSTGuard      bool
	FragGuard     bool
}

var (
    reAckOnly = regexp.MustCompile(`tcp flags (?:& \(syn\|ack\) == ack|ack / syn,ack)`)
    reSynAck  = regexp.MustCompile(`tcp flags (?:& \(syn\|ack\) == \(syn\|ack\)|syn,ack / syn,ack)`)
    reNoSyn   = regexp.MustCompile(`tcp flags (?:& syn == 0|! syn)`)
)

func ackguardFeatures() AckguardFeatures {
    s := shOut("nft list chain inet cfm ackguard 2>/dev/null")

    // helpers to check both state and flag patterns
    has := func(needState, needFlag *regexp.Regexp) bool {
        for _, line := range strings.Split(s, "\n") {
            line = strings.TrimSpace(line)
            if needState.MatchString(line) && needFlag.MatchString(line) {
                return true
            }
        }
        return false
    }

    reStateNew     := regexp.MustCompile(`\bct state new\b`)
    reStateInvalid := regexp.MustCompile(`\bct state invalid\b`)

    return AckguardFeatures{
        MatchInvalid:  has(reStateInvalid, reAckOnly),
        DropNonSynNew: has(reStateNew,     reNoSyn),
        DropSynAckNew: has(reStateNew,     reSynAck),

        // RSTGuard: treat as enabled if we see *any* rst rule (NEW+RST or ESTABLISHED RST meter)
        RSTGuard: strings.Contains(s, "flags & rst == rst") || strings.Contains(s, " flags rst"),

        // FragGuard: either IPv4 or IPv6 fragment match present
        FragGuard: strings.Contains(s, " ip frag-off ") || strings.Contains(s, " ip6 frag "),
    }
}


type AckguardCounters struct {
	AckNewDrop   int
	NonSynNew    int
	SynAckIn     int
	RSTNew       int
	RSTEstV4     int
	RSTEstV6     int
	TCPFragV4    int
	TCPFragV6    int
}

func readAckguardCounters() AckguardCounters {
	out := shOut("nft list counters table inet cfm 2>/dev/null")
	// very similar style to your daemon’s DumpFloodCounters scanner. :contentReference[oaicite:1]{index=1}
	get := func(name string) int {
		// look for:
		// counter <name> { packets N bytes M }
		idx := strings.Index(out, "counter "+name+" ")
		if idx == -1 { return 0 }
		frag := out[idx:]
		// find "packets <num>"
		p := strings.Index(frag, "packets ")
		if p == -1 { return 0 }
		frag = frag[p+len("packets "):]
		end := strings.IndexFunc(frag, func(r rune) bool { return r < '0' || r > '9' })
		if end == -1 { end = len(frag) }
		n, _ := strconv.Atoi(strings.TrimSpace(frag[:end]))
		return n
	}
	return AckguardCounters{
		AckNewDrop: get("acknew_drop"),
		NonSynNew:  get("nonsynnew_drop"),
		SynAckIn:   get("synack_in_drop"),
		RSTNew:     get("rstnew_drop"),
		RSTEstV4:   get("rst_est_v4"),
		RSTEstV6:   get("rst_est_v6"),
		TCPFragV4:  get("tcp_frag_drop"),
		TCPFragV6:  get("tcp6_frag_drop"),
	}
}

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


    // --- TTL summary (manual hosts + nets) ---
    if st.TablePresent {
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
        if (a4hTot+a4nTot+a6hTot+a6nTot) > 0 {
            fmt.Printf("  ALLOW v4: %d/%d with TTL\n", a4hTTL+a4nTTL, a4hTot+a4nTot)
            fmt.Printf("  ALLOW v6: %d/%d with TTL\n", a6hTTL+a6nTTL, a6hTot+a6nTot)
        }
    }








// --- Health snapshot (works even if daemon is not running) ---
hs := health.SnapshotNow()
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













// NEW ACK-Guard

    // --- AckGuard summary & counters ---
    if ackguardInstalled() {
        ports := ackguardPorts()
        feats := ackguardFeatures()
        fmt.Printf("AckGuard: installed | ports=[%s]\n", ports)
        // features line
        fmt.Printf("  features: invalid=%v, nonsyn-new=%v, synack-new=%v, rst=%v, frag=%v\n",
            feats.MatchInvalid, feats.DropNonSynNew, feats.DropSynAckNew, feats.RSTGuard, feats.FragGuard)
        // counters (non-zero first, then zeros compact)
        ac := readAckguardCounters()
        type kv struct{ name string; val int }
        all := []kv{
            {"acknew_drop", ac.AckNewDrop},
            {"nonsynnew_drop", ac.NonSynNew},
            {"synack_in_drop", ac.SynAckIn},
            {"rstnew_drop", ac.RSTNew},
            {"rst_est_v4", ac.RSTEstV4},
            {"rst_est_v6", ac.RSTEstV6},
            {"tcp_frag_drop", ac.TCPFragV4},
            {"tcp6_frag_drop", ac.TCPFragV6},
        }
        var nonzero, zero []kv
        for _, x := range all {
            if x.val > 0 { nonzero = append(nonzero, x) } else { zero = append(zero, x) }
        }
        if len(nonzero) > 0 {
            fmt.Print("  counters: ")
            for i, x := range nonzero {
                if i > 0 { fmt.Print(", ") }
                fmt.Printf("%s=%d", x.name, x.val)
            }
            fmt.Println()
        }
        if len(zero) > 0 {
            // keep this compact; it helps confirm wiring even when idle
            fmt.Print("  counters(zero): ")
            for i, x := range zero {
                if i > 0 { fmt.Print(", ") }
                fmt.Print(x.name)
            }
            fmt.Println()
        }
    } else {
        fmt.Println("AckGuard: not installed (no jump in flood)")
    }


// ACKGuard IP List
r4 := listSetElemsDetailed("ackguard_recent_v4", 10)
r6 := listSetElemsDetailed("ackguard_recent_v6", 10)

printRecent := func(label string, items []recentHit) {
    if len(items) == 0 { return }
    fmt.Printf("  recent(%s):\n", label)
    for _, it := range items {
        if en != nil {
            r := en.Lookup(it.IP)
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
            if it.Expires != "" {
                metaParts = append(metaParts, "ttl="+it.Expires)
            }
            if len(metaParts) > 0 {
                fmt.Printf("    %-39s [%s]\n", it.IP, strings.Join(metaParts, " | "))
                continue
            }
        }
        // fallback (no enrich or no meta)
        if it.Expires != "" {
            fmt.Printf("    %-39s [ttl=%s]\n", it.IP, it.Expires)
        } else {
            fmt.Printf("    %s\n", it.IP)
        }
    }
}

printRecent("acknew v4", r4)
printRecent("acknew v6", r6)

//




////




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
        // --- extras: states & ports ---
        states := stateBreakdownByIP(entries, tcpIn, locals, h.IP)
        ports  := portBreakdownByIP(entries, tcpIn, locals, h.IP)

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




// helper list count elements with  "expires/timeout"
func countTTLInSet(set string) (withTTL, total int) {
    s := shOut("nft list set inet cfm " + set + " 2>/dev/null")

    for _, m := range reElem.FindAllStringSubmatch(s, -1) { // reElem matches IP or CIDR
        addr := strings.Trim(m[1], ",}")
        valid := false
        if strings.Contains(addr, "/") {
            if _, _, err := net.ParseCIDR(addr); err == nil { valid = true }
        } else {
            if net.ParseIP(addr) != nil { valid = true }
        }
        if !valid { continue }

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

//helpers for IP status conntrack (inbound προς local + μόνο TCP_IN ports)
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
