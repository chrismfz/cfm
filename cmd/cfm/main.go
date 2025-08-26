package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"net"
	"encoding/json"
	"sort"
	"bytes"
	"path/filepath"
	"context"
	"net/http"

	"cfm/internal/firewall/nft"
	"cfm/internal/firewall"
	"cfm/internal/blocklists"

)

var (
	Version   = "dev"
	BuildTime = ""
)

type fwBackend interface {
	EnsureBase() error
	AddBlock(net.IP, string, *time.Duration) error
	RemoveBlock(net.IP) error
	ListBlocks() ([]firewall.BlockedEntry, error)

	AddAllow(net.IP, *time.Duration) error
	RemoveAllow(net.IP) error
	ListAllows() ([]firewall.BlockedEntry, error)
}

func getBackend() fwBackend {
	if _, ok := lookPath("nft"); ok {
		return nft.New()
	}
	return nil
}

func main() {
	if BuildTime == "" {
		BuildTime = time.Now().Format(time.RFC3339)
	}

	if len(os.Args) == 1 {
		fmt.Printf("cfm v%s (built %s)\n", Version, BuildTime)
		usage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "-h", "--help", "help":
		usage()
	case "-v", "--version", "version":
		fmt.Printf("cfm v%s (built %s)\n", Version, BuildTime)
	case "test":
		runTest()
	case "block":
		runBlock(os.Args[2:])
	case "unblock":
		runUnblock(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "allow":
		runAllow(os.Args[2:])
	case "unallow":
		runUnallow(os.Args[2:])
	case "allow-list":
		runAllowList(os.Args[2:])
	case "daemon":
		runDaemon(os.Args[2:])
	case "flush":
		runFlush(os.Args[2:])
	case "which" , "search":
		runWhich(os.Args[2:])
	case "status":
		runStatus(os.Args[1:])

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`
Usage:
  cfm version
  cfm test
  cfm block <IP> [-r REASON] [--ttl 1h]
  cfm unblock <IP>
  cfm list [--json]
  cfm allow <IP> [--ttl 1h]
  cfm unallow <IP>
  cfm allow-list [--json]
  cfm daemon [--interval 30s]
  cfm flush
  cfm which <IP> [--json]
  cfm status [--json]

Description:
  local nftables manager (block/allow with optional TTL),
  plus simple list/unlist/flush. `)
}

func runTest() {
	fmt.Println("== cfm test ==")

	type check struct {
		name string
		fn   func() (string, bool)
	}
	checks := []check{
		{"nft (binary)", func() (string, bool) { return hasBinary("nft") }},
		{"iptables (binary)", func() (string, bool) { return hasBinary("iptables") }},
		{"ip6tables (binary)", func() (string, bool) { return hasBinary("ip6tables") }},
		{"ipset (binary)", func() (string, bool) { return hasBinary("ipset") }},
		{"kernel module: nf_tables", func() (string, bool) { return hasModule("nf_tables") }},
		{"kernel module: ip_tables", func() (string, bool) { return hasModule("ip_tables") }},
		{"kernel module: xt_owner", func() (string, bool) { return hasModule("xt_owner") }},
	}

	for _, c := range checks {
		msg, ok := c.fn()
		status := "OK"
		if !ok {
			status = "MISSING"
		}
		fmt.Printf(" - %-28s : %-7s %s\n", c.name, status, msg)
	}

	backend := detectBackend()
	fmt.Printf("\nDetected backend preference: %s\n", backend)
}

func detectBackend() string {
	if _, ok := lookPath("nft"); ok {
		return "nftables"
	}
	if _, ok := lookPath("iptables"); ok {
		return "iptables"
	}
	return "none"
}

// ---------- block ----------

// ---------- block ----------
func runBlock(args []string) {
	fs := flag.NewFlagSet("block", flag.ExitOnError)
	reason := fs.String("r", "", "reason/comment (currently ignored)")
	ttlFlag := fs.String("ttl", "", "optional TTL (e.g. 90s, 5m, 1h)")

	// flags οπουδήποτε
	flagArgs, posArgs := splitFlagsAndPositionals(args, map[string]bool{
		"--ttl": true, "-r": true,
	})
	_ = fs.Parse(flagArgs)

	var ipStr string
	if len(posArgs) > 0 {
		ipStr = posArgs[0]
	}
	if ipStr == "" {
		// fallback (σπάνιο: αν κάποιος δώσει IP μετά από άγνωστα flags)
		rem := fs.Args()
		if len(rem) > 0 {
			ipStr = rem[0]
		}
	}
	if ipStr == "" {
		fmt.Fprintln(os.Stderr, "usage: cfm block <IP> [-r REASON] [--ttl 1h]")
		os.Exit(2)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Fprintln(os.Stderr, "invalid IP")
		os.Exit(2)
	}

	var dur *time.Duration
	if *ttlFlag != "" {
		if d, err := time.ParseDuration(*ttlFlag); err == nil && d > 0 {
			dur = &d
		} else {
			fmt.Fprintln(os.Stderr, "invalid --ttl (examples: 90s, 5m, 1h)")
			os.Exit(2)
		}
	}

	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	if err := be.AddBlock(ip, *reason, dur); err != nil {
		fmt.Fprintln(os.Stderr, "block error:", err)
		os.Exit(1)
	}


	// append σε cfm.deny αν ξέρουμε config dir
	if cfgDir, ok := resolveConfigDir(""); ok {
		line := ip.String()
		if dur != nil && *dur > 0 {
			line += " ttl=" + dur.String()
		}
		if err := appendUniqueLine(cfgDir, "cfm.deny", line); err != nil {
			fmt.Fprintln(os.Stderr, "warn: could not update cfm.deny:", err)
		}
	}

	fmt.Printf("✔ blocked %s\n", ip.String())
}


func runUnblock(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm unblock <IP>")
		os.Exit(2)
	}
	ip := net.ParseIP(args[0])
	if ip == nil {
		fmt.Fprintln(os.Stderr, "invalid IP")
		os.Exit(2)
	}
	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	if err := be.RemoveBlock(ip); err != nil {
		fmt.Fprintln(os.Stderr, "unblock error:", err)
		os.Exit(1)
	}


	fmt.Printf("✔ unblocked %s\n", ip.String())
}

// ---------- allow ----------

// ---------- allow ----------
func runAllow(args []string) {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	ttlFlag := fs.String("ttl", "", "optional TTL (e.g. 90s, 5m, 1h)")

	// flags οπουδήποτε
	flagArgs, posArgs := splitFlagsAndPositionals(args, map[string]bool{
		"--ttl": true,
	})
	_ = fs.Parse(flagArgs)

	var ipStr string
	if len(posArgs) > 0 {
		ipStr = posArgs[0]
	}
	if ipStr == "" {
		rem := fs.Args()
		if len(rem) > 0 {
			ipStr = rem[0]
		}
	}
	if ipStr == "" {
		fmt.Fprintln(os.Stderr, "usage: cfm allow <IP> [--ttl 1h]")
		os.Exit(2)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Fprintln(os.Stderr, "invalid IP")
		os.Exit(2)
	}

	var dur *time.Duration
	if *ttlFlag != "" {
		if d, err := time.ParseDuration(*ttlFlag); err == nil && d > 0 {
			dur = &d
		} else {
			fmt.Fprintln(os.Stderr, "invalid --ttl (examples: 90s, 5m, 1h)")
			os.Exit(2)
		}
	}

	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	if err := be.AddAllow(ip, dur); err != nil {
		fmt.Fprintln(os.Stderr, "allow error:", err)
		os.Exit(1)
	}

 // append σε cfm.allow αν ξέρουμε config dir (από /run/cfm/config.path)
 if cfgDir, ok := resolveConfigDir(""); ok {
     line := ip.String()
     if dur != nil && *dur > 0 {
         line += " ttl=" + dur.String()
     }
     if err := appendUniqueLine(cfgDir, "cfm.allow", line); err != nil {
         fmt.Fprintln(os.Stderr, "warn: could not update cfm.allow:", err)
     }
 }


	fmt.Printf("✔ allowed %s\n", ip.String())
}


func runUnallow(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm unallow <IP>")
		os.Exit(2)
	}
	ip := net.ParseIP(args[0])
	if ip == nil {
		fmt.Fprintln(os.Stderr, "invalid IP")
		os.Exit(2)
	}
	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	if err := be.RemoveAllow(ip); err != nil {
		fmt.Fprintln(os.Stderr, "unallow error:", err)
		os.Exit(1)
	}
	fmt.Printf("✔ unallowed %s\n", ip.String())
}

func runAllowList(args []string) {
	fs := flag.NewFlagSet("allow-list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	entries, err := be.ListAllows()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list error:", err)
		os.Exit(1)
	}

	if *asJSON {
		type out struct {
			IP      string     `json:"ip"`
			Expires *time.Time `json:"expires,omitempty"`
		}
		data := make([]out, 0, len(entries))
		for _, e := range entries {
			data = append(data, out{
				IP: e.IP.String(), Expires: e.Expires,
			})
		}
		b, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(b))
		return
	}

	if len(entries) == 0 {
		fmt.Println("(no allowed IPs)")
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].IP.String() < entries[j].IP.String()
	})
	fmt.Printf("%-40s %-20s\n", "IP", "Expires")
	for _, e := range entries {
		exp := "-"
		if e.Expires != nil {
			exp = e.Expires.Format(time.RFC3339)
		}
		fmt.Printf("%-40s %-20s\n", e.IP.String(), exp)
	}
}

// ---------- daemon / common ----------
func runDaemon(args []string) {
    fs := flag.NewFlagSet("daemon", flag.ExitOnError)
    interval := fs.Duration("interval", 30*time.Second, "tick interval")
    cfgFlag := fs.String("c", "", "config directory (contains cfm.allow / cfm.deny)")
    _ = fs.Parse(args)

    // Resolve config dir (flag > env > /run pointer > /etc/cfm > nearest ./configs)
    cfgDir, _ := resolveConfigDir(*cfgFlag)
    if cfgDir != "" {
        writeConfigState(cfgDir)
        fmt.Printf("→ using config dir: %s\n", cfgDir)
    } else {
        fmt.Println("→ no config dir found (no -c / no CFM_CONFIG_DIR / no /etc/cfm / no ./configs). Running without file persistence.")
    }

    be := getBackend()
    if be == nil {
        fmt.Fprintln(os.Stderr, "no firewall backend available")
        os.Exit(1)
    }
    if err := be.EnsureBase(); err != nil {
        fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
        os.Exit(1)
    }

    // keep track to avoid TTL refresh every tick
    seenAllow := map[string]string{} // key=ip → spec (ttl=..., until=..., perm)
    seenBlock := map[string]string{}

    applyFile := func(filePath string, isAllow bool) {
        now := time.Now()
        entries, err := readEntriesFromFile(filePath)
        if err != nil {
            fmt.Fprintln(os.Stderr, "read config error:", err)
            return
        }
        for _, e := range entries {
            spec := "perm"
            if e.Until != nil {
                spec = "until=" + e.Until.UTC().Format(time.RFC3339)
            } else if e.TTL != nil {
                spec = "ttl=" + e.TTL.String()
            }
            key := e.IP.String()
            if isAllow {
                if prev, ok := seenAllow[key]; ok && prev == spec { continue }
            } else {
                if prev, ok := seenBlock[key]; ok && prev == spec { continue }
            }
            dur := durationFromEntryNow(e, now)
            if isAllow {
                if err := be.AddAllow(e.IP, dur); err != nil {
                    fmt.Fprintln(os.Stderr, "allow apply error:", err)
                    continue
                }
                seenAllow[key] = spec
            } else {
                if err := be.AddBlock(e.IP, "", dur); err != nil {
                    fmt.Fprintln(os.Stderr, "block apply error:", err)
                    continue
                }
                seenBlock[key] = spec
            }
        }
    }

    loadAll := func() {
        if cfgDir == "" { return }
        applyFile(filepath.Join(cfgDir, "cfm.allow"), true)
        applyFile(filepath.Join(cfgDir, "cfm.deny"), false)
    }

// ---- Blocklists management ----
type feedState struct {
    feed        blocklists.Feed
    nextRefresh time.Time
    lastV4      []string
    lastV6      []string
}
var feeds map[string]*feedState

loadBlocklists := func() {
    if cfgDir == "" { return }
    fp := filepath.Join(cfgDir, "cfm.blocklists")
    f, err := os.Open(fp)
    if err != nil {
        if !os.IsNotExist(err) {
            fmt.Fprintln(os.Stderr, "blocklists open error:", err)
        }
        return
    }
    defer f.Close()
    parsed, err := blocklists.ParseConfig(f)
    if err != nil {
        fmt.Fprintln(os.Stderr, "blocklists parse error:", err)
        return
    }
    if feeds == nil {
        feeds = make(map[string]*feedState)
    }
    now := time.Now()
    // Update states or add new
    seen := map[string]struct{}{}
    for _, fd := range parsed {
        seen[fd.Name] = struct{}{}
        st, ok := feeds[fd.Name]
        if !ok {
            st = &feedState{feed: fd, nextRefresh: now}
            feeds[fd.Name] = st
            continue
        }
        // update feed params if changed
        st.feed = fd
        if st.nextRefresh.IsZero() {
            st.nextRefresh = now
        }
    }
    // Remove states no longer present (they will be dropped on next union replace)
    for name := range feeds {
        if _, ok := seen[name]; !ok {
            delete(feeds, name)
        }
    }
}

// καλούμε μία φορά στην εκκίνηση
loadBlocklists()





applyUnion := func(be fwBackend, feeds map[string]*feedState) {
    // build unions per TYPE/family
    a4m, a6m := map[string]struct{}{}, map[string]struct{}{}
    b4m, b6m := map[string]struct{}{}, map[string]struct{}{}
    for _, st := range feeds {
        switch st.feed.Type {
        case blocklists.TypeAllow:
            for _, e := range st.lastV4 { a4m[e] = struct{}{} }
            for _, e := range st.lastV6 { a6m[e] = struct{}{} }
        default:
            for _, e := range st.lastV4 { b4m[e] = struct{}{} }
            for _, e := range st.lastV6 { b6m[e] = struct{}{} }
        }
    }
    toSlice := func(m map[string]struct{}) []string {
        out := make([]string, 0, len(m))
        for k := range m { out = append(out, k) }
        return out
    }
    a4, a6 := toSlice(a4m), toSlice(a6m)
    b4, b6 := toSlice(b4m), toSlice(b6m)

    // partition hosts/nets (avoid interval conflicts)
    a4hosts, a4nets := partitionHostsNets(a4, false)
    a6hosts, a6nets := partitionHostsNets(a6, true)
    b4hosts, b4nets := partitionHostsNets(b4, false)
    b6hosts, b6nets := partitionHostsNets(b6, true)

    fmt.Printf("apply blocklists union:\n  allow_ext_v4 hosts=%d nets=%d\n  allow_ext_v6 hosts=%d nets=%d\n  block_ext_v4 hosts=%d nets=%d\n  block_ext_v6 hosts=%d nets=%d\n",
        len(a4hosts), len(a4nets), len(a6hosts), len(a6nets), len(b4hosts), len(b4nets), len(b6hosts), len(b6nets))

    nb, ok := be.(*nft.Backend)
    if !ok {
        fmt.Fprintln(os.Stderr, "warn: external sets apply not supported on this backend")
        return
    }
    // χωρίς TTL προς το παρόν
    if err := nb.ReplaceSetFlushAdd("allow_ext_v4_hosts", a4hosts, nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (allow_ext_v4_hosts):", err) }
    if err := nb.ReplaceSetFlushAdd("allow_ext_v4_nets",  a4nets,  nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (allow_ext_v4_nets):",  err) }
    if err := nb.ReplaceSetFlushAdd("allow_ext_v6_hosts", a6hosts, nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (allow_ext_v6_hosts):", err) }
    if err := nb.ReplaceSetFlushAdd("allow_ext_v6_nets",  a6nets,  nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (allow_ext_v6_nets):",  err) }

    if err := nb.ReplaceSetFlushAdd("block_ext_v4_hosts", b4hosts, nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (block_ext_v4_hosts):", err) }
    if err := nb.ReplaceSetFlushAdd("block_ext_v4_nets",  b4nets,  nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (block_ext_v4_nets):",  err) }
    if err := nb.ReplaceSetFlushAdd("block_ext_v6_hosts", b6hosts, nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (block_ext_v6_hosts):", err) }
    if err := nb.ReplaceSetFlushAdd("block_ext_v6_nets",  b6nets,  nil); err != nil { fmt.Fprintln(os.Stderr, "apply error (block_ext_v6_nets):",  err) }
}













    // αρχικό load & banner
    loadAll()
    fmt.Printf("cfm daemon starting (tick=%s). Ctrl+C to exit.\n", interval.String())

    t := time.NewTicker(*interval)
    defer t.Stop()
    for {
        select {
        case <-t.C:
            loadAll()



    changed := false
    if feeds != nil && len(feeds) > 0 {
        now := time.Now()
        client := &http.Client{Timeout: 30 * time.Second}
        for name, st := range feeds {
            if now.Before(st.nextRefresh) { continue }
            fmt.Printf("blocklist refresh: %s (type=%s, interval=%s)\n", name, st.feed.Type.String(), st.feed.Interval)
            ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
            res, err := blocklists.FetchAndParse(ctx, client, st.feed)
            cancel()
            if err != nil {
                fmt.Fprintln(os.Stderr, "blocklist fetch error:", name, err)
                st.nextRefresh = now.Add(st.feed.Interval)
                continue
            }
            // detect change (cheap)
            changed = changed || !equalSlices(st.lastV4, res.V4) || !equalSlices(st.lastV6, res.V6)
            st.lastV4 = res.V4
            st.lastV6 = res.V6





splitHostsNets := func(in []string) (hosts, nets []string) {
    for _, s := range in {
        s = strings.TrimSpace(s)
        if s == "" { continue }
        if strings.Contains(s, "/") { nets = append(nets, s) } else { hosts = append(hosts, s) }
    }
    return
}

feedKey := nft.SanitizeFeedName(st.feed.Name) // χρήση του helper από nft.go
isAllow := (st.feed.Type == blocklists.TypeAllow)

// Υπολογισμός δυναμικών ονομάτων
var base string
if isAllow { base = "allow_ext" } else { base = "block_ext" }

// split lists
h4, n4 := splitHostsNets(res.V4)
h6, n6 := splitHostsNets(res.V6)

if nb, ok := be.(*nft.Backend); ok {
    // v4
    nameH4 := fmt.Sprintf("%s_v4_hosts_%s", base, feedKey)
    nameN4 := fmt.Sprintf("%s_v4_nets_%s",  base, feedKey)
    if err := nb.EnsureSetDynamic(nameH4, false, false); err == nil {
        _ = nb.ReplaceSetFlushAdd(nameH4, h4, nil)
    }
    if err := nb.EnsureSetDynamic(nameN4, false, true); err == nil {
        _ = nb.ReplaceSetFlushAdd(nameN4, n4, nil)
    }
    // v6
    nameH6 := fmt.Sprintf("%s_v6_hosts_%s", base, feedKey)
    nameN6 := fmt.Sprintf("%s_v6_nets_%s",  base, feedKey)
    if err := nb.EnsureSetDynamic(nameH6, true, false); err == nil {
        _ = nb.ReplaceSetFlushAdd(nameH6, h6, nil)
    }
    if err := nb.EnsureSetDynamic(nameN6, true, true); err == nil {
        _ = nb.ReplaceSetFlushAdd(nameN6, n6, nil)
    }
}




            st.nextRefresh = now.Add(st.feed.Interval)
            fmt.Printf("  -> got v4=%d v6=%d\n", len(res.V4), len(res.V6))
        }
        if changed {
            applyUnion(be, feeds)
        }
    }


        }
    }
}



func equalSlices(a, b []string) bool {
    if len(a) != len(b) { return false }
    // αρκεί μια απλή σύγκριση αν δεν εγγυάται τάξη; Εδώ οι λίστες μπορεί να μην έχουν ίδια σειρά.
    // Για απλότητα, κάνε map-compare:
    ma := make(map[string]struct{}, len(a))
    for _, x := range a { ma[x] = struct{}{} }
    for _, x := range b {
        if _, ok := ma[x]; !ok { return false }
    }
    return true
}










func hasBinary(name string) (string, bool) {
	if p, ok := lookPath(name); ok {
		return p, true
	}
	return "not found in PATH", false
}

func lookPath(name string) (string, bool) {
	p, err := exec.LookPath(name)
	return p, err == nil
}

func hasModule(mod string) (string, bool) {
	f, err := os.Open("/proc/modules")
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, mod+" ") {
				return "present in /proc/modules", true
			}
		}
	}
	if _, err := exec.LookPath("modprobe"); err == nil {
		out, _ := exec.Command("modprobe", "-n", "-v", mod).CombinedOutput()
		txt := strings.TrimSpace(string(out))
		if txt != "" {
			return "modprobe reports: " + short(txt, 120), true
		}
	}
	return "not loaded (and modprobe check inconclusive)", false
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	entries, err := be.ListBlocks()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list error:", err)
		os.Exit(1)
	}

	if *asJSON {
		type out struct {
			IP      string     `json:"ip"`
			Expires *time.Time `json:"expires,omitempty"`
			Comment string     `json:"comment,omitempty"`
		}
		data := make([]out, 0, len(entries))
		for _, e := range entries {
			data = append(data, out{
				IP: e.IP.String(), Expires: e.Expires, Comment: e.Comment,
			})
		}
		b, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(b))
		return
	}

	if len(entries) == 0 {
		fmt.Println("(no blocked IPs)")
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].IP.String() < entries[j].IP.String()
	})
	fmt.Printf("%-40s %-20s %s\n", "IP", "Expires", "Comment")
	for _, e := range entries {
		exp := "-"
		if e.Expires != nil {
			exp = e.Expires.Format(time.RFC3339)
		}
		fmt.Printf("%-40s %-20s %s\n", e.IP.String(), exp, e.Comment)
	}
}

func runFlush(args []string) {
	be := getBackend()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		os.Exit(1)
	}
	if err := be.EnsureBase(); err != nil {
		fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
		os.Exit(1)
	}
	cmds := []string{
		fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "block_v4"),
		fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "block_v6"),
		fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "allow_v4"),
		fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "allow_v6"),
	}
	for _, c := range cmds {
		out, err := exec.Command("nft", strings.Split(c, " ")...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "flush error: %s: %v\n", string(out), err)
			os.Exit(1)
		}
	}
	fmt.Println("✔ flushed all blocked/allowed IPs")
}


// splitFlagsAndPositionals χωρίζει flags (με τα values τους) από τα positionals.
// Υποστηρίζει μορφές --ttl 90s, --ttl=90s, -r "reason". Ο,τι δεν είναι flag πάει στα positionals.
func splitFlagsAndPositionals(args []string, valueFlags map[string]bool) (flagArgs []string, posArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			// flag
			name := a
			if idx := strings.Index(a, "="); idx != -1 {
				// --ttl=90s (έχει ήδη value)
				flagArgs = append(flagArgs, a)
				continue
			}
			flagArgs = append(flagArgs, a)
			// αν είναι flag που περιμένει value και το επόμενο ΔΕΝ ξεκινάει με '-', πάρε το ως value
			if valueFlags[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		// positional
		posArgs = append(posArgs, a)
	}
	return
}



// --- config helpers ---
const cfmStatePath = "/run/cfm/config.path" // daemon γράφει εδώ το ενεργό config dir

func writeConfigState(dir string) {
	_ = os.MkdirAll(filepath.Dir(cfmStatePath), 0755)
	_ = os.WriteFile(cfmStatePath, []byte(dir), 0644)
}

func readConfigState() (string, bool) {
	b, err := os.ReadFile(cfmStatePath)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", false
	}
	return s, true
}

func resolveConfigDir(explicit string) (string, bool) {
    if explicit != "" {
        if dirExists(explicit) { return explicit, true }
        // αν δόθηκε ρητά αλλά δεν υπάρχει, μην συνεχίσεις σε fallbacks — θεώρησέ το σφάλμα κλήσης
        return "", false
    }
    if env := strings.TrimSpace(os.Getenv("CFM_CONFIG_DIR")); env != "" {
        if dirExists(env) { return env, true }
    }
    if s, ok := readConfigState(); ok && dirExists(s) {
        return s, true
    }
    if dirExists("/etc/cfm") {
        return "/etc/cfm", true
    }
    if d, ok := nearestConfigsDir(); ok {
        return d, true
    }
    return "", false
}


func dirExists(p string) bool {
    fi, err := os.Stat(p)
    return err == nil && fi.IsDir()
}

// ψάχνει τον κοντινότερο γονέα που περιέχει φάκελο "configs"
// έτσι δουλεύει ωραία μέσα στο dev repo, ό,τι working dir κι αν έχεις
func nearestConfigsDir() (string, bool) {
    cwd, err := os.Getwd()
    if err != nil { return "", false }
    d := cwd
    for {
        cand := filepath.Join(d, "configs")
        if dirExists(cand) {
            return cand, true
        }
        parent := filepath.Dir(d)
        if parent == d { // φτάσαμε στο root
            break
        }
        d = parent
    }
    return "", false
}


func ensureDir(p string) error { return os.MkdirAll(p, 0755) }

func appendUniqueLine(dir, base, line string) error {
	if err := ensureDir(dir); err != nil { return err }
	fp := filepath.Join(dir, base)
	// avoid duplicates (same line)
	if b, err := os.ReadFile(fp); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == strings.TrimSpace(line) {
				return nil
			}
		}
	}
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil { return err }
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

type fileEntry struct {
	IP    net.IP
	TTL   *time.Duration
	Until *time.Time
}

func readEntriesFromFile(path string) ([]fileEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return nil, nil }
		return nil, err
	}
	var out []fileEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		fields := strings.Fields(line)
		if len(fields) == 0 { continue }

		ip := net.ParseIP(fields[0])
		if ip == nil { continue }

		var ttl *time.Duration
		var until *time.Time
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "ttl=") {
				if d, err := time.ParseDuration(strings.TrimPrefix(f, "ttl=")); err == nil && d > 0 {
					ttl = &d
				}
			} else if strings.HasPrefix(f, "until=") {
				if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(f, "until=")); err == nil {
					until = &t
				}
			}
		}
		out = append(out, fileEntry{IP: ip, TTL: ttl, Until: until})
	}
	return out, nil
}

func durationFromEntryNow(e fileEntry, now time.Time) *time.Duration {
	// priority: until → derive remaining; else ttl
	if e.Until != nil {
		rem := e.Until.Sub(now)
		if rem > 0 { return &rem }
		return nil
	}
	return e.TTL
}


// κόβει σε hosts (IP ή /32|/128) και nets (CIDR με μικρότερο prefix)
func partitionHostsNets(elems []string, isV6 bool) (hosts []string, nets []string) {
    seenH, seenN := map[string]struct{}{}, map[string]struct{}{}
    maxBits := 32
    if isV6 { maxBits = 128 }
    for _, s := range elems {
        s = strings.TrimSpace(s)
        if s == "" { continue }
        if strings.Contains(s, "/") {
            _, n, err := net.ParseCIDR(s)
            if err != nil { continue }
            ones, bits := n.Mask.Size()
            if bits != maxBits { continue } // safety
            if ones == maxBits {
                ip := n.IP.String()
                if _, ok := seenH[ip]; !ok {
                    seenH[ip] = struct{}{}
                    hosts = append(hosts, ip)
                }
            } else {
                if _, ok := seenN[s]; !ok {
                    seenN[s] = struct{}{}
                    nets = append(nets, s)
                }
            }
        } else {
            ip := net.ParseIP(s)
            if ip == nil { continue }
            if !isV6 && ip.To4() == nil { continue }
            if isV6 && (ip.To16() == nil || ip.To4() != nil) { continue }
            ipS := ip.String()
            if _, ok := seenH[ipS]; !ok {
                seenH[ipS] = struct{}{}
                hosts = append(hosts, ipS)
            }
        }
    }
    return
}






// --- which (read-only query) ---

type whichHit struct {
    Set     string `json:"set"`
    Action  string `json:"action"` // ALLOW/BLOCK
    Scope   string `json:"scope"`  // host/cidr
    Match   string `json:"match"`  // ip ή prefix
    Feed    string `json:"feed,omitempty"`
    Family  string `json:"family"` // v4/v6
    Via     string `json:"via"`    // "host" ή "cidr"
}

func runWhich(args []string) {
    fs := flag.NewFlagSet("which", flag.ExitOnError)
    asJSON := fs.Bool("json", false, "output JSON")
    _ = fs.Parse(args)
    if fs.NArg() < 1 {
        fmt.Fprintln(os.Stderr, "usage: cfm which <IP> [--json]")
        os.Exit(2)
    }

//    ip := net.ParseIP(fs.Arg(0))
//    if ip == nil {
//        fmt.Fprintln(os.Stderr, "invalid IP")
//        os.Exit(2)
//    }


    arg := fs.Arg(0)
    var (
//        ip    net.ParseIP
        nip   net.IP
        nnet  *net.IPNet
        isCIDR bool
    )
    if strings.Contains(arg, "/") {
        var err error
        nip, nnet, err = net.ParseCIDR(arg)
        if err != nil {
            fmt.Fprintln(os.Stderr, "invalid CIDR")
            os.Exit(2)
        }
        isCIDR = true
    } else {
        nip = net.ParseIP(arg)
        if nip == nil {
            fmt.Fprintln(os.Stderr, "invalid IP")
            os.Exit(2)
        }
    }

    // Διάβασε τον ορισμό του table (read-only). Αν αποτύχει, δείξε φιλικό μήνυμα.
    tblOut, err := exec.Command("nft", "-j", "list", "table", "inet", "cfm").CombinedOutput()
    if err != nil {
        fmt.Fprintf(os.Stderr, "cannot read nftables table inet cfm (maybe needs sudo?): %v\n%s\n", err, string(tblOut))
        os.Exit(1)
    }

    // Εξήγαγε τα set names και type.
//    setNames := extractCfmSets(tblOut, ip)
    setNames := extractCfmSets(tblOut, nip)
    if len(setNames) == 0 {
        // Κενό/ανύπαρκτο config: απλώς τίποτα
        if *asJSON {
            fmt.Println("[]")
        } else {
            fmt.Println("(no matches)")
        }
        return
    }

    // Σάρωσε κάθε set για host/cidr match
    var hits []whichHit
    for _, s := range setNames {
        so, err := exec.Command("nft", "-j", "list", "set", "inet", "cfm", s.name).CombinedOutput()
        if err != nil {
            // Αγνόησέ το συγκεκριμένο set, συνέχισε
            continue
        }
        //h := querySetForIP(so, ip, s)
        var h []whichHit
        if isCIDR {
            h = querySetForCIDR(so, nnet, s)
        } else {
            h = querySetForIP(so, nip, s)
        }
        hits = append(hits, h...)
    }

    if *asJSON {
        b, _ := json.MarshalIndent(hits, "", "  ")
        fmt.Println(string(b))
        return
    }

    if len(hits) == 0 {
        fmt.Println("(no matches)")
        return
    }
    //fmt.Printf("Matches for %s:\n", ip.String())
fmt.Printf("Matches for %s:\n", arg)
    for _, h := range hits {
        feed := ""
        if h.Feed != "" {
            feed = fmt.Sprintf(" (feed: %s)", h.Feed)
        }
        fmt.Printf(" - %s via %s %s in set %s%s\n",
            h.Action, h.Via, h.Match, h.Set, feed)
    }
}





// Ελέγχει αν δύο δίκτυα επικαλύπτονται (ίδια οικογένεια + a.Contains(b.IP) || b.Contains(a.IP))
func netsOverlap(a, b *net.IPNet) bool {
    if (a.IP.To4() != nil) != (b.IP.To4() != nil) {
        return false
    }
    return a.Contains(b.IP) || b.Contains(a.IP)
}

// CIDR query: βρίσκει hosts εντός του CIDR και prefixes που επικαλύπτονται
func querySetForCIDR(so []byte, q *net.IPNet, s setDesc) []whichHit {
    var hits []whichHit
    var payload struct {
        Nftables []struct {
            Set *struct {
                Elem []interface{} `json:"elem"`
            } `json:"set,omitempty"`
        } `json:"nftables"`
    }
    if err := json.Unmarshal(so, &payload); err != nil {
        return hits
    }
    for _, top := range payload.Nftables {
        if top.Set == nil {
            continue
        }
        for _, raw := range top.Set.Elem {
            switch v := raw.(type) {
            case string:
                // host element
                if hip := net.ParseIP(v); hip != nil && q.Contains(hip) {
                    hits = append(hits, whichHit{
                        Set: s.name, Action: s.action, Scope: "host", Match: hip.String(),
                        Feed: s.feed, Family: s.family, Via: "host",
                    })
                }
            case map[string]interface{}:
                // cidr element
                if p, ok := v["prefix"].(map[string]interface{}); ok {
                    addr, _ := p["addr"].(string)
                    lf, _ := p["len"].(float64)
                    if addr == "" || lf == 0 {
                        continue
                    }
                    plen := int(lf)
                    if ip := net.ParseIP(addr); ip != nil {
                        _, enet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), plen))
                        if err == nil && netsOverlap(q, enet) {
                            hits = append(hits, whichHit{
                                Set: s.name, Action: s.action, Scope: "cidr",
                                Match: fmt.Sprintf("%s/%d", ip.String(), plen),
                                Feed: s.feed, Family: s.family, Via: "cidr",
                            })
                        }
                    }
                }
            }
        }
    }
    return hits
}



// Περιγραφή set που μας νοιάζει
type setDesc struct {
    name   string // set name
    family string // "v4"|"v6"
    kind   string // "hosts"|"nets"|"manual" (manual = allow_v4/block_v4 απλά hosts)
    action string // "ALLOW"|"BLOCK"
    feed   string // π.χ. "dshield" αν υπάρχει suffix
    // note: type (ipv4_addr/ipv6_addr) δεν χρειάζεται εδώ, το family αρκεί
}

// Βρίσκει όλα τα sets του table cfm και κρατά μόνο όσα ταιριάζουν με το family του IP
func extractCfmSets(tableJSON []byte, ip net.IP) []setDesc {
    var doc struct {
        Nftables []struct {
            Set *struct {
                Name  string   `json:"name"`
                Type  string   `json:"type"`
                Flags []string `json:"flags"`
            } `json:"set,omitempty"`
        } `json:"nftables"`
    }
    _ = json.Unmarshal(tableJSON, &doc)

    fam := "v4"
    if ip.To4() == nil {
        fam = "v6"
    }

    var out []setDesc
    for _, n := range doc.Nftables {
        if n.Set == nil { continue }
        t := n.Set.Type // e.g. "ipv4_addr"
        if fam == "v4" && t != "ipv4_addr" { continue }
        if fam == "v6" && t != "ipv6_addr" { continue }

        sd := classifySetName(n.Set.Name)
        if sd.name == "" { // not part of cfm logic we care about
            continue
        }
        // φιλτράρουμε και με family (π.χ. allow_v4, block_ext_v6_nets, κ.λπ.)
        if sd.family != fam { continue }

        out = append(out, sd)
    }
    return out
}

// Κατάταξη set name -> δράση/είδος/οικογένεια/feed
func classifySetName(name string) setDesc {
    // Manual
    if name == "allow_v4" { return setDesc{name: name, family: "v4", kind: "manual", action: "ALLOW"} }
    if name == "allow_v6" { return setDesc{name: name, family: "v6", kind: "manual", action: "ALLOW"} }
    if name == "block_v4" { return setDesc{name: name, family: "v4", kind: "manual", action: "BLOCK"} }
    if name == "block_v6" { return setDesc{name: name, family: "v6", kind: "manual", action: "BLOCK"} }

    // External per-feed (δυναμικά ονόματα)
    // allow_ext_v4_hosts_<feed> | allow_ext_v4_nets_<feed>
    // block_ext_v6_hosts_<feed> | block_ext_v6_nets_<feed>
    parts := strings.Split(name, "_")
   // if len(parts) >= 5 && (parts[0] == "allow" || parts[0] == "block") && parts[1] == "ext" &&
	if (len(parts) == 4 || len(parts) >= 5) &&
	(parts[0] == "allow" || parts[0] == "block") && parts[1] == "ext" &&
        (parts[2] == "v4" || parts[2] == "v6") &&
        (parts[3] == "hosts" || parts[3] == "nets") {
        //feed := strings.Join(parts[4:], "_")
     feed := ""
     if len(parts) >= 5 {
       feed = strings.Join(parts[4:], "_")
     }
        return setDesc{
            name:   name,
            family: parts[2],
            kind:   parts[3], // hosts|nets
            action: strings.ToUpper(parts[0]),
            feed:   feed,
        }
    }

    // Άλλα sets δεν μας απασχολούν εδώ
    return setDesc{}
}

// Παίρνει το JSON ενός set και βρίσκει hits (host ή CIDR containment)


func pickString(m map[string]any, key string) string {
    if v, ok := m[key]; ok {
        if s, ok2 := v.(string); ok2 {
            return s
        }
    }
    return ""
}

func pickPrefix(m map[string]any) (addr string, length int, ok bool) {
    // περιμένουμε {"prefix":{"addr":"A.B.C.D","len":N}}
    if p, ok := m["prefix"].(map[string]any); ok {
        a, aok := p["addr"].(string)
        // το len έρχεται ως float64 λόγω JSON αριθμών
        if l, lok := p["len"].(float64); aok && lok {
            return a, int(l), true
        }
    }
    return "", 0, false
}


// helpers για σύγκριση/containment IPs
func ipLE(a, b net.IP) bool {
    a16 := a.To16()
    b16 := b.To16()
    if a16 == nil || b16 == nil {
        return false
    }
    return bytes.Compare(a16, b16) <= 0
}

func ipInRange(ip, from, to net.IP) bool {
    ip16 := ip.To16()
    if ip16 == nil {
        return false
    }
    return ipLE(from, ip16) && ipLE(ip16, to)
}

// Σκανάρει το JSON του `nft -j list set inet cfm <set>` και βρίσκει host/prefix/interval matches
func querySetForIP(raw []byte, ip net.IP, sd setDesc) []whichHit {
    var root map[string]any
    if err := json.Unmarshal(raw, &root); err != nil {
        return nil
    }
    arr, _ := root["nftables"].([]any)
    if arr == nil {
        return nil
    }

    mk := func(via, match string) whichHit {
        return whichHit{
            Set: sd.name, Action: sd.action, Scope: via, Match: match,
            Feed: sd.feed, Family: sd.family, Via: via,
        }
    }

    var hits []whichHit
    for _, it := range arr {
        m, _ := it.(map[string]any)
        setObj, ok := m["set"].(map[string]any)
        if !ok {
            continue
        }
     //   elems, _ := setObj["elem"].([]any)
        elems, _ := setObj["elem"].([]any)
        if len(elems) == 0 {
            elems, _ = setObj["elements"].([]any)
        }

        for _, e := range elems {
            switch v := e.(type) {
            case string:
                // plain host element
                if parsed := net.ParseIP(v); parsed != nil && ip.Equal(parsed) {
                    hits = append(hits, mk("host", ip.String()))
                }
            case map[string]any:
                // wrapped host string (κάποιες εκδόσεις το έχουν ως {"elem":"1.2.3.4"})
                if s, ok := v["elem"].(string); ok {
                    if parsed := net.ParseIP(s); parsed != nil && ip.Equal(parsed) {
                        hits = append(hits, mk("host", ip.String()))
                        continue
                    }
                }


                // nested μορφές κάτω από "elem": {"elem":{"val":"1.2.3.4"}} / {"elem":{"prefix":...}} / {"elem":{"interval":...}}
                if inner, ok := v["elem"].(map[string]any); ok {
                    if s, ok := inner["val"].(string); ok {
                        if parsed := net.ParseIP(s); parsed != nil && ip.Equal(parsed) {
                            hits = append(hits, mk("host", ip.String()))
                            continue
                        }
                    }
                    if pfx, ok := inner["prefix"].(map[string]any); ok {
                        addr, _ := pfx["addr"].(string)
                        l64, _ := pfx["len"].(float64)
                        if addr != "" && l64 > 0 {
                            cidr := fmt.Sprintf("%s/%d", addr, int(l64))
                            if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
                                hits = append(hits, mk("cidr", cidr))
                            }
                        }
                    }
                    if iv, ok := inner["interval"].(map[string]any); ok {
                        fromStr, _ := iv["from"].(string)
                        toStr, _ := iv["to"].(string)
                        if fromStr != "" && toStr != "" {
                            from := net.ParseIP(fromStr)
                            to := net.ParseIP(toStr)
                            if from != nil && to != nil && ipInRange(ip, from, to) {
                                hits = append(hits, mk("cidr", fmt.Sprintf("%s-%s", fromStr, toStr)))
                            }
                        }
                    }
                }
                // prefix {addr,len}
                if pfx, ok := v["prefix"].(map[string]any); ok {
                    addr, _ := pfx["addr"].(string)
                    l64, _ := pfx["len"].(float64)
                    if addr != "" && l64 > 0 {
                        cidr := fmt.Sprintf("%s/%d", addr, int(l64))
                        if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
                            hits = append(hits, mk("cidr", cidr))
                        }
                    }
                    continue
                }
                // interval {from,to}  ← εδώ κρυβονται τα CIDR όταν το set έχει flag "interval"
                if iv, ok := v["interval"].(map[string]any); ok {
                    fromStr, _ := iv["from"].(string)
                    toStr, _ := iv["to"].(string)
                    if fromStr != "" && toStr != "" {
                        from := net.ParseIP(fromStr)
                        to := net.ParseIP(toStr)
                        if from != nil && to != nil && ipInRange(ip, from, to) {
                            hits = append(hits, mk("cidr", fmt.Sprintf("%s-%s", fromStr, toStr)))
                        }
                    }
                    continue
                }
            }
        }
    }
    return hits
}

















// ---- STATUS ---------------------------------------------------------------

type statusRow struct {
    Set      string `json:"set"`
    Action   string `json:"action"`   // ALLOW/BLOCK
    Family   string `json:"family"`   // v4/v6
    Scope    string `json:"scope"`    // hosts/nets/manual
    Feed     string `json:"feed"`     // "" για manual/union
    Hosts    int    `json:"hosts"`    // πλήθος host entries (απλές IPs)
    Prefixes int    `json:"prefixes"` // πλήθος CIDR entries
}

type statusOut struct {
    TablePresent bool        `json:"table_present"`
    RulesPresent bool        `json:"rules_present"`
    Sets         []statusRow `json:"sets"`
    Totals       struct {
        Allow struct {
            Hosts, Prefixes, Entries int `json:"hosts_prefixes_entries"`
        } `json:"allow"`
        Block struct {
            Hosts, Prefixes, Entries int `json:"hosts_prefixes_entries"`
        } `json:"block"`
        Overall int `json:"overall_entries"`
    } `json:"totals"`
}

// ονοματολογία sets που χρησιμοποιούμε:
// - manual: allow_v4, allow_v6, block_v4, block_v6  (hosts only)
// - per-feed: allow_ext_v{4,6}_{hosts,nets}_{feed}, block_ext_v{4,6}_{hosts,nets}_{feed}
// - union (legacy): allow_ext_v{4,6}_{hosts,nets}, block_ext_v{4,6}_{hosts,nets}
func classifyStatusSet(name, typ string) (action, family, scope, feed string, ok bool) {
    // manual
    switch name {
    case "allow_v4":
        return "ALLOW", "v4", "manual", "", true
    case "allow_v6":
        return "ALLOW", "v6", "manual", "", true
    case "block_v4":
        return "BLOCK", "v4", "manual", "", true
    case "block_v6":
        return "BLOCK", "v6", "manual", "", true
    }
    // per-feed
    // allow_ext_v4_hosts_<feed>
    // allow_ext_v4_nets_<feed>
    // block_ext_v6_hosts_<feed> ... κτλ
    if strings.HasPrefix(name, "allow_ext_") || strings.HasPrefix(name, "block_ext_") {
        parts := strings.Split(name, "_")
        if len(parts) >= 5 {
            action = strings.ToUpper(parts[0]) // allow/block -> ALLOW/BLOCK
            if action == "ALLOW" {
                action = "ALLOW"
            } else {
                action = "BLOCK"
            }
            // parts: [allow|block][ext][v4|v6][hosts|nets][feed?]
            fam := parts[2]
            if fam == "v4" || fam == "v6" {
                family = fam
            }
            if parts[3] == "hosts" || parts[3] == "nets" {
                scope = parts[3]
            }
            if len(parts) >= 5 {
                feed = strings.Join(parts[4:], "_") // υποστήριξη feed με underscores
            }
            return action, family, scope, feed, true
        }
    }
    // δεν μας νοιάζει άλλο set
    return "", "", "", "", false
}

func runStatus(args []string) {
    fs := flag.NewFlagSet("status", flag.ExitOnError)
    asJSON := fs.Bool("json", false, "output JSON")
    _ = fs.Parse(args)

    // list table inet cfm (μια κλήση για να πάρουμε sets + rules)
    out, err := exec.Command("nft", "-j", "list", "table", "inet", "cfm").CombinedOutput()
    if err != nil {
        // table missing
        so := statusOut{TablePresent: false, RulesPresent: false}
        if *asJSON {
            b, _ := json.MarshalIndent(so, "", "  ")
            fmt.Println(string(b))
            return
        }
        fmt.Println("Firewall: inactive (table inet cfm NOT present)")
        return
    }

    // parse JSON
    var parsed struct {
        Nftables []struct {
            Set *struct {
                Family string        `json:"family"`
                Name   string        `json:"name"`
                Table  string        `json:"table"`
                Type   string        `json:"type"`
                Flags  []string      `json:"flags"`
                Elem   []interface{} `json:"elem"`
            } `json:"set,omitempty"`
            Rule *struct {
                Expr []interface{} `json:"expr"`
                Chain string       `json:"chain"`
            } `json:"rule,omitempty"`
        } `json:"nftables"`
    }
    _ = json.Unmarshal(out, &parsed)

    st := statusOut{TablePresent: true}

    // προσπαθούμε να εντοπίσουμε ότι υπάρχουν κανόνες στην αλυσίδα input που αναφέρονται στα set μας
    rulesCount := 0
    for _, it := range parsed.Nftables {
        if it.Rule != nil {
            rulesCount++
        }
    }
    st.RulesPresent = rulesCount > 0

    // Σκανάρουμε όλα τα sets που μας αφορούν και μετράμε hosts/prefixes
    for _, it := range parsed.Nftables {
        if it.Set == nil {
            continue
        }
        s := it.Set
       action, family, scope, feed, ok := classifyStatusSet(s.Name, s.Type)
        if !ok {
            continue
        }
        // φίλτραρε οικογένεια βάσει s.Type (ipv4_addr/ipv6_addr) για ασφάλεια
        if s.Type == "ipv4_addr" && family != "v4" {
            family = "v4"
        }
        if s.Type == "ipv6_addr" && family != "v6" {
            family = "v6"
        }
        row := statusRow{
            Set: s.Name, Action: action, Family: family, Scope: scope, Feed: feed,
        }
        for _, el := range s.Elem {
            switch v := el.(type) {
            case string:
                row.Hosts++
            case map[string]interface{}:
                if _, ok := v["prefix"]; ok {
                    row.Prefixes++
                } else {
                    // μελλοντικά άλλα είδη στοιχείων
                }
            }
        }
        st.Sets = append(st.Sets, row)
        // totals
        if action == "ALLOW" {
            st.Totals.Allow.Hosts += row.Hosts
            st.Totals.Allow.Prefixes += row.Prefixes
        } else {
            st.Totals.Block.Hosts += row.Hosts
            st.Totals.Block.Prefixes += row.Prefixes
        }
    }
    st.Totals.Allow.Entries = st.Totals.Allow.Hosts + st.Totals.Allow.Prefixes
    st.Totals.Block.Entries = st.Totals.Block.Hosts + st.Totals.Block.Prefixes
    st.Totals.Overall = st.Totals.Allow.Entries + st.Totals.Block.Entries

    // σταθερή ταξινόμηση: manual sets πρώτα, μετά per-feed αλφαβητικά
    sort.Slice(st.Sets, func(i, j int) bool {
        a, b := st.Sets[i], st.Sets[j]
        // manual > ext
        ai := 1
        if a.Scope == "manual" { ai = 0 }
        bj := 1
        if b.Scope == "manual" { bj = 0 }
        if ai != bj { return ai < bj }
        // action: ALLOW πριν από BLOCK
        if a.Action != b.Action { return a.Action < b.Action }
        // family: v4 πριν από v6
        if a.Family != b.Family { return a.Family < b.Family }
        // feed/setname
        if a.Feed != b.Feed { return a.Feed < b.Feed }
        return a.Set < b.Set
    })

    if *asJSON {
        b, _ := json.MarshalIndent(st, "", "  ")
        fmt.Println(string(b))
        return
    }

    // Text output
    if st.TablePresent {
        if st.RulesPresent {
            fmt.Println("Firewall: active (table inet cfm present, rules installed)")
        } else {
            fmt.Println("Firewall: table present, but no rules found")
        }
    } else {
        fmt.Println("Firewall: inactive (table inet cfm NOT present)")
    }
    // Manual totals (quick look)
    fmt.Printf("Totals: ALLOW=%d (hosts=%d, prefixes=%d)  BLOCK=%d (hosts=%d, prefixes=%d)  Overall=%d\n",
        st.Totals.Allow.Entries, st.Totals.Allow.Hosts, st.Totals.Allow.Prefixes,
        st.Totals.Block.Entries, st.Totals.Block.Hosts, st.Totals.Block.Prefixes,
        st.Totals.Overall,
    )
    // Detailed per-set
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
