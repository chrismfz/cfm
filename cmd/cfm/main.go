package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
//	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cfm/internal/blocklists"
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	"cfm/internal/logging"
	cfgpkg "cfm/internal/config"
	agentpkg "cfm/internal/agent"
	"cfm/internal/sysctl"
	status "cfm/internal/status"
	ipquery "cfm/internal/ipquery"
	"cfm/internal/unblock"
	"cfm/internal/reporting"

	detpkg "cfm/internal/detectors"
	"cfm/internal/notify"
)

var (
	Version   = "dev"
	BuildTime = ""
)

// ----------------------------------------------------------------------------
// Backend abstraction
// ----------------------------------------------------------------------------


func getBackend() firewall.Backend {
	if _, ok := lookPath("nft"); ok {
		return nft.New()
	}
	return nil
}

// ----------------------------------------------------------------------------
// CLI entrypoint
// ----------------------------------------------------------------------------

func requireRoot() {
    if os.Geteuid() != 0 {
        u, _ := user.Current()
        fmt.Fprintf(os.Stderr,
            "cfm requires root (current user: %s, uid=%d). Try running with sudo.\n",
            u.Username, os.Geteuid())
        os.Exit(1)
    }
}




func main() {
    requireRoot()


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
	case "which", "search":
		runWhich(os.Args[2:])
	case "status":
		status.Run(os.Args[1:])
	case "reset":
		runReset(os.Args[2:])
	case "disable":
		runDisable(os.Args[2:])
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
  cfm daemon [--interval 20s]
  cfm flush
  cfm which <IP> [--json]   -- search <IP>
  cfm status [--json]
  cfm disable -- disable and drop everything in nft
  cfm reset   -- empty all tables / sets

Description:
  local nftables manager (block/allow with optional TTL),
  plus simple list/unlist/flush. `)
}

// ----------------------------------------------------------------------------
// test / env detection
// ----------------------------------------------------------------------------

func runTest() {
	fmt.Println("== cfm test ==")
	type check struct{ name string; fn func() (string, bool) }
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
		msg, ok := c.fn(); status := "OK"
		if !ok { status = "MISSING" }
		fmt.Printf(" - %-28s : %-7s %s\n", c.name, status, msg)
	}
	fmt.Printf("\nDetected backend preference: %s\n", detectBackend())
}

func detectBackend() string {
	if _, ok := lookPath("nft"); ok { return "nftables" }
	if _, ok := lookPath("iptables"); ok { return "iptables" }
	return "none"
}

// ----------------------------------------------------------------------------
// block / allow commands
// ----------------------------------------------------------------------------

func runBlock(args []string) {
    fs := flag.NewFlagSet("block", flag.ExitOnError)
    // reason done
    reasonFlag := fs.String("r", "", "reason/comment")
    ttlFlag := fs.String("ttl", "", "optional TTL (e.g. 90s, 5m, 1h)")
    flagArgs, posArgs := splitFlagsAndPositionals(args, map[string]bool{"--ttl": true, "-r": true})
    _ = fs.Parse(flagArgs)

    // IP
    if len(posArgs) == 0 && len(fs.Args()) > 0 {
        posArgs = append(posArgs, fs.Args()[0])
        if len(fs.Args()) > 1 { posArgs = append(posArgs, fs.Args()[1:]...) }
    }
    if len(posArgs) == 0 {
        fmt.Fprintln(os.Stderr, "usage: cfm block <IP> [-r REASON] [--ttl 1h] | cfm block <IP> <REASON...>")
        os.Exit(2)
    }
    ipStr := posArgs[0]
    ip := net.ParseIP(ipStr)
    if ip == nil { fmt.Fprintln(os.Stderr, "invalid IP"); os.Exit(2) }

    // Reason: είτε από -r, είτε από τα υπόλοιπα positionals
    rsn := strings.TrimSpace(*reasonFlag)
    if rsn == "" && len(posArgs) > 1 {
        rsn = strings.TrimSpace(strings.Join(posArgs[1:], " "))
    }
    if rsn == "" { rsn = "manual block" }

    // TTL
    var dur *time.Duration
    if *ttlFlag != "" {
        if d, err := time.ParseDuration(*ttlFlag); err == nil && d > 0 {
            dur = &d
        } else {
            fmt.Fprintln(os.Stderr, "invalid --ttl (examples: 90s, 5m, 1h)")
            os.Exit(2)
        }
    }

    // Firewall apply
    be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
    if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
    if err := be.AddBlock(ip, rsn, dur); err != nil { fmt.Fprintln(os.Stderr, "block error:", err); os.Exit(1) }

    // cfm.deny (μόνο σε permanent)
    if cfgDir, ok := resolveConfigDir(""); ok {
        if dur == nil || (dur != nil && *dur <= 0) {
            // Γράφουμε σχόλιο μετά το IP — οι helpers σου αγνοούν ό,τι είναι μετά από κενό/# όταν κάνουν remove/search
            line := ip.String()
            if rsn != "" { line += "  # " + rsn }
            if err := appendUniqueLine(cfgDir, "cfm.deny", line); err != nil {
                fmt.Fprintln(os.Stderr, "warn: could not update cfm.deny:", err)
            }
        }
    }

    // API report (προαιρετικό)
    if cfgDir, ok := resolveConfigDir(""); ok {
        if b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf")); err == nil {
            if cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(b)); err == nil && cfg.API.ManualBlockSend {
                if cfg.API.URL != "" && cfg.API.AuthToken != "" {
                    api := &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
                    // Στέλνουμε comment = reason, description = reason
                    // derive mode/ttl from --ttl
                    mode, ttlSec := "permanent", 0
                    if dur != nil && *dur > 0 {
                        mode, ttlSec = "ttl", int(dur.Seconds())
                    }
                                    if err := api.ReportBlock(ip.String(), rsn, "manual-cli", mode, ttlSec); err != nil {
                        fmt.Printf("✔ blocked %s (API report failed: %v)\n", ip.String(), err)
                        return
                    }
                    fmt.Printf("✔ blocked %s (also sent to API)\n", ip.String())
                    return
                }
            }
        }
    }

    fmt.Printf("✔ blocked %s\n", ip.String())
}


//global unblock//
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

    cfgDir, _ := resolveConfigDir("")



    // --- εδώ ακριβώς όπως το έχεις σήμερα ---
    var reporter reporting.Reporter
    var sendAPI bool
    if cfgDir != "" {
        if b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf")); err == nil {
            if cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(b)); err == nil &&
                cfg.API.UnblockSend &&
                cfg.API.URL != "" &&
                cfg.API.AuthToken != "" {
                reporter = &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
                sendAPI = true
            }
        }
    }

    ttl := 1 * time.Hour
    res, err := unblock.Do(context.Background(), ip, unblock.Options{
        BE:            be,
        ConfigDir:     cfgDir,
        TempWhitelist: true,
        AllowTTL:      &ttl,
        Reporter:      reporter,
        ReportWhy:     "cli",
        SendAPI:       sendAPI,
    })
    if err != nil {
        fmt.Fprintln(os.Stderr, "unblock error:", err)
        os.Exit(1)
    }

    // --- εκτύπωση report ---
    suffix := ipquery.EnrichSuffix(cfgDir, ip.String())
    fmt.Printf("Unblock report for %s%s\n", ip, suffix)
    for _, s := range res.Steps {
        feeds := ""
        if len(s.Feeds) > 0 {
            feeds = " [feeds: " + strings.Join(s.Feeds, ",") + "]"
        }
        extra := s.Detail
        if s.Err != "" {
            extra = "ERR: " + s.Err + " " + extra
        }
        fmt.Printf(" - %-9s via %-10s %s%s\n",
            s.Action, s.Source, strings.TrimSpace(extra), feeds)
    }
    if res.Whitelisted {
        fmt.Println("✔ applied local whitelist override (due to feeds)")
    }
}






func runAllow(args []string) {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	ttlFlag := fs.String("ttl", "", "optional TTL (e.g. 90s, 5m, 1h)")
	flagArgs, posArgs := splitFlagsAndPositionals(args, map[string]bool{"--ttl": true})
	_ = fs.Parse(flagArgs)

	ipStr := ""
	if len(posArgs) > 0 { ipStr = posArgs[0] }
	if ipStr == "" { rem := fs.Args(); if len(rem) > 0 { ipStr = rem[0] } }
	if ipStr == "" { fmt.Fprintln(os.Stderr, "usage: cfm allow <IP> [--ttl 1h]"); os.Exit(2) }

	ip := net.ParseIP(ipStr); if ip == nil { fmt.Fprintln(os.Stderr, "invalid IP"); os.Exit(2) }

	var dur *time.Duration
	if *ttlFlag != "" {
		if d, err := time.ParseDuration(*ttlFlag); err == nil && d > 0 { dur = &d } else { fmt.Fprintln(os.Stderr, "invalid --ttl (examples: 90s, 5m, 1h)"); os.Exit(2) }
	}

	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
	if err := be.AddAllow(ip, dur); err != nil { fmt.Fprintln(os.Stderr, "allow error:", err); os.Exit(1) }

	if cfgDir, ok := resolveConfigDir(""); ok {
		line := ip.String(); if dur != nil && *dur > 0 { line += " ttl=" + dur.String() }
		if err := appendUniqueLine(cfgDir, "cfm.allow", line); err != nil { fmt.Fprintln(os.Stderr, "warn: could not update cfm.allow:", err) }
	}
	fmt.Printf("✔ allowed %s\n", ip.String())
}




func runUnallow(args []string) {
    if len(args) < 1 { fmt.Fprintln(os.Stderr, "usage: cfm unallow <IP>"); os.Exit(2) }
    ip := net.ParseIP(args[0]); if ip == nil { fmt.Fprintln(os.Stderr, "invalid IP"); os.Exit(2) }
    be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
    if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
    if err := be.RemoveAllow(ip); err != nil { fmt.Fprintln(os.Stderr, "unallow error:", err); os.Exit(1) }
    fmt.Printf("✔ unallowed %s\n", ip.String())
    if cfgDir, ok := resolveConfigDir(""); ok {
        _, _ = removeIPFromFile(cfgDir, "cfm.allow", ip.String())
    }
}



func runAllowList(args []string) {
	fs := flag.NewFlagSet("allow-list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)
	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
	entries, err := be.ListAllows(); if err != nil { fmt.Fprintln(os.Stderr, "list error:", err); os.Exit(1) }
	if *asJSON {
		type out struct{ IP string `json:"ip"`; Expires *time.Time `json:"expires,omitempty"` }
		data := make([]out, 0, len(entries))
		for _, e := range entries { data = append(data, out{IP: e.IP.String(), Expires: e.Expires}) }
		b, _ := json.MarshalIndent(data, "", "  "); fmt.Println(string(b)); return
	}
	if len(entries) == 0 { fmt.Println("(no allowed IPs)"); return }
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP.String() < entries[j].IP.String() })
	fmt.Printf("%-40s %-20s\n", "IP", "Expires")
	for _, e := range entries { exp := "-"; if e.Expires != nil { exp = e.Expires.Format(time.RFC3339) }; fmt.Printf("%-40s %-20s\n", e.IP.String(), exp) }
}

// ----------------------------------------------------------------------------
// Daemon
// ----------------------------------------------------------------------------

type fileWatcher struct {
	path string
	mod  time.Time
	sum  [32]byte
	have bool
}

func newFileWatcher(path string) *fileWatcher { return &fileWatcher{path: path} }

// Changed returns (data, true) only when the file contents changed since last call.
// If the file is missing, returns (nil, false) and resets state so reappearance triggers.
func (w *fileWatcher) Changed() ([]byte, bool) {
	st, err := os.Stat(w.path)
	if err != nil {
		w.have = false
		return nil, false
	}
	if w.have && st.ModTime().Equal(w.mod) {
		return nil, false
	}
	f, err := os.Open(w.path)
	if err != nil { return nil, false }
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil { return nil, false }
	h := sha256.Sum256(b)
	if w.have && st.ModTime().Equal(w.mod) && h == w.sum {
		return nil, false
	}
	w.mod, w.sum, w.have = st.ModTime(), h, true
	return b, true
}






func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	interval := fs.Duration("interval", 20*time.Second, "tick interval")
	cfgFlag := fs.String("c", "", "config directory (contains cfm.allow / cfm.deny)")
	_ = fs.Parse(args)

	cfgDir, _ := resolveConfigDir(*cfgFlag)
	if cfgDir != "" {
		writeConfigState(cfgDir)
		logging.Logf("CFM Starting")
		logging.Logf("→ using config dir: %s", cfgDir)
	} else {
		logging.Logf("→ no config dir found (no -c / no CFM_CONFIG_DIR / no /etc/cfm / no ./configs). Running without file persistence.")
	}

	// Backend
	be := getBackend()
	if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }

	//Notify manager
	if err := notify.Init(cfgDir); err != nil {
	    logging.Logf("[notify] init error: %v", err)
	} else {
	    logging.Logf("[notify] init OK")
	}


	// DynDNS manager (whitelist)
	ddm := NewDynDNSManager(be, cfgDir)
	_ = ddm.FileChanged()
	_ = ddm.LoadOnce(context.Background())

	// NFT backend extras
	if nb, ok := be.(*nft.Backend); ok {
		nb.EnableEnrichment(cfgDir, "/etc/cfm", "./configs")
		nb.SetConfigDir(cfgDir)
	}

	// Blocklists Manager (scheduler+apply)
	var blMgr *blocklists.Manager
	if nb, ok := be.(*nft.Backend); ok {
		blMgr = blocklists.NewManager(blocklists.ApplierFunc(nb.ApplyFeed))
		blMgr.Start(context.Background())
		defer blMgr.Stop()
	}

	// Watchers
	var allowW, denyW, blW, confW *fileWatcher
	if cfgDir != "" {
		allowW = newFileWatcher(filepath.Join(cfgDir, "cfm.allow"))
		denyW  = newFileWatcher(filepath.Join(cfgDir, "cfm.deny"))
		blW    = newFileWatcher(filepath.Join(cfgDir, "cfm.blocklists"))
		confW  = newFileWatcher(filepath.Join(cfgDir, "cfm.conf"))
	}

	// Track seen allow/block entries to avoid pointless TTL refreshes
	seenAllow := map[string]string{} // ip -> spec (perm|ttl=..|until=..)
	seenBlock := map[string]string{}

	applyFile := func(filePath string, isAllow bool) {
		now := time.Now()
		entries, err := readEntriesFromFile(filePath)
		if err != nil { fmt.Fprintln(os.Stderr, "read config error:", err); return }
		for _, e := range entries {
			spec := "perm"
			if e.Until != nil { spec = "until=" + e.Until.UTC().Format(time.RFC3339) } else if e.TTL != nil { spec = "ttl=" + e.TTL.String() }
			key := e.IP.String()
			if isAllow {
				if prev, ok := seenAllow[key]; ok && prev == spec { continue }
			} else {
				if prev, ok := seenBlock[key]; ok && prev == spec { continue }
			}
			dur := durationFromEntryNow(e, now)
			if isAllow {
				if err := be.AddAllow(e.IP, dur); err != nil { fmt.Fprintln(os.Stderr, "allow apply error:", err); continue }
				seenAllow[key] = spec
			} else {
				if err := be.AddBlock(e.IP, "", dur); err != nil { fmt.Fprintln(os.Stderr, "block apply error:", err); continue }
				seenBlock[key] = spec
			}
		}
	}

	loadAll := func() {
		if cfgDir == "" { return }
		run := false
		if allowW != nil { if _, ch := allowW.Changed(); ch { run = true } }
		if denyW  != nil { if _, ch := denyW.Changed();  ch { run = true } }
		if !run { return }
		applyFile(filepath.Join(cfgDir, "cfm.allow"), true)
		applyFile(filepath.Join(cfgDir, "cfm.deny"),  false)
		if os.Getenv("CFM_DEBUG") != "" { fmt.Println("[allow/deny] updated from files") }
	}

	reloadBlocklists := func() {
		if cfgDir == "" || blW == nil || blMgr == nil { return }
		b, changed := blW.Changed()
		if !changed { return }
		feeds, err := blocklists.ParseConfig(bytes.NewReader(b))
		if err != nil {
			fmt.Fprintln(os.Stderr, "blocklists parse error:", err)
			return
		}
		blMgr.Reload(feeds)
		logging.Logf("[blocklists] config reloaded: %d feeds", len(feeds))
	}

	var (
		ag           *agentpkg.Runner
		agStarted    bool
		lastCfg      *cfgpkg.Config
		lastAgentKey string // "APIURL|TOKEN"
	)

	startOrUpdateAgent := func(cfg *cfgpkg.Config) {
		if cfg == nil || cfg.API.URL == "" || cfg.API.AuthToken == "" {
			return
		}
		key := cfg.API.URL + "|" + cfg.API.AuthToken
		if key == lastAgentKey && agStarted {
			return // no-op
		}
		ac := agentpkg.Config{
			BaseURL:  cfg.API.URL,
			Token:    cfg.API.AuthToken,
			Version:  Version,
			Interval: 20 * time.Second,
		}


        if ag == nil {
            ag = agentpkg.New(ac)
            ag.SetBackend(be)  // ← δώσε backend
            ag.SetConfigDir(cfgDir) // ← και config dir (για cfm.deny cleanup)
            ag.Start()
            agStarted = true
        } else {
            ag.Update(ac)
            ag.SetBackend(be)
            ag.SetConfigDir(cfgDir)
        }


		lastAgentKey = key
	}
	loadAgent := func() { startOrUpdateAgent(lastCfg) }

	// cfm.conf loader/applier (single place)
	applyPorts := func() {
		if cfgDir == "" || confW == nil { return }
		b, ok := confW.Changed()
		if !ok { return }

		cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(b))
		if err != nil {
			fmt.Fprintln(os.Stderr, "cfm.conf parse error:", err)
			return
		}
		lastCfg = cfg

		// Defaults BEFORE summary
		cfg.SystemTweaks.SetDefaults()

		// logger + summary
		logging.Init(&cfg.Logging)
		for _, ln := range cfg.Summary() {
			logging.Logf("[config] %s", ln)
		}

		// sysctl tweaks
		if err := sysctl.ApplyTweaks(&cfg.SystemTweaks); err != nil {
			fmt.Fprintln(os.Stderr, "sysctl tweaks error:", err)
		}

		// nft rules

if nb, ok2 := be.(*nft.Backend); ok2 {

    logging.Logf("[daemon] === Begin ApplyFloodRules ===")
    if err := nb.ApplyFloodRules(cfg); err != nil {
        fmt.Fprintln(os.Stderr, "flood rules apply error:", err)
    }
    logging.Logf("[daemon] === End ApplyFloodRules ===")


// after cfg.Summary() logging, before ApplyFloodRules
if cfg.AckGuard.Enabled {
    logging.Logf("[ackguard] will protect ports with NEW+ACK filter (rate=%d/s burst=%d)",
        cfg.AckGuard.Rate, cfg.AckGuard.Burst)
}



    logging.Logf("[daemon] === Begin ApplyPortsPolicy ===")
    if err := nb.ApplyPortsPolicy(&cfg.Ports); err != nil {
        fmt.Fprintln(os.Stderr, "apply ports policy error:", err)
    }
    logging.Logf("[daemon] === End ApplyPortsPolicy ===")

    logging.Logf("[daemon] === Finished all nft applies ===")


  if cfg.API.URL != "" && cfg.API.AuthToken != "" {
        api := &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
        nb.SetReporter(api) // από εδώ και πέρα τα autoblocks θα κάνουν ReportBlock
    }

}






		// agent
		startOrUpdateAgent(cfg)
	}

	// Initial load
	reloadBlocklists()
	loadAll()
	applyPorts()
	if os.Getenv("CFM_DEBUG") == "2" { fmt.Printf("Starting MAD COW FIREWALL v2 \n") }
	logging.Logf("cfm daemon starting (tick=%s). Ctrl+C to exit.\n", interval.String())



// detectors logic
// wherever you start detectors (e.g., runDaemon)

// detectors logic
detpkg.Start(context.Background(), detpkg.Options{
    CfgPath: filepath.Join(cfgDir, "detectors.conf"), // use the actual filename
    Sink:    detpkg.OutcomeLoggerSink{},              // prints final "Blocked:" outcome
    FW:      be,                                      // reuse the backend created above
})



	// Loop
	t := time.NewTicker(*interval); defer t.Stop()
	for {
		select {
		case <-t.C:
			reloadBlocklists() // only if cfm.blocklists changed
			loadAll()          // only if cfm.allow/cfm.deny changed
			applyPorts()       // only if cfm.conf changed
			loadAgent()

			// periodic maintenance
			if nb, ok := be.(*nft.Backend); ok {
				nb.DumpFloodCounters()
				nb.LoadPortScanner()
			}
			if ddm.FileChanged() {
				_ = ddm.LoadOnce(context.Background())
			} else {
				ddm.Tick(context.Background(), time.Now())
			}
		}
	}
}


// ----------------------------------------------------------------------------
// helpers shared by commands
// ----------------------------------------------------------------------------



func equalSlices(a, b []string) bool {
	if len(a) != len(b) { return false }
	ma := make(map[string]struct{}, len(a))
	for _, x := range a { ma[x] = struct{}{} }
	for _, x := range b { if _, ok := ma[x]; !ok { return false } }
	return true
}

func hasBinary(name string) (string, bool) { if p, ok := lookPath(name); ok { return p, true }; return "not found in PATH", false }
func lookPath(name string) (string, bool) { p, err := exec.LookPath(name); return p, err == nil }

func hasModule(mod string) (string, bool) {
	if f, err := os.Open("/proc/modules"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() { line := sc.Text(); if strings.HasPrefix(line, mod+" ") { return "present in /proc/modules", true } }
	}
	if _, err := exec.LookPath("modprobe"); err == nil {
		out, _ := exec.Command("modprobe", "-n", "-v", mod).CombinedOutput()
		txt := strings.TrimSpace(string(out))
		if txt != "" { return "modprobe reports: " + short(txt, 120), true }
	}
	return "not loaded (and modprobe check inconclusive)", false
}

func short(s string, n int) string { if len(s) <= n { return s }; return s[:n] + "..." }

// list blocked --------------------------------------------------------------

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)
	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
	entries, err := be.ListBlocks(); if err != nil { fmt.Fprintln(os.Stderr, "list error:", err); os.Exit(1) }
	if *asJSON {
		type out struct{ IP string `json:"ip"`; Expires *time.Time `json:"expires,omitempty"`; Comment string `json:"comment,omitempty"` }
		data := make([]out, 0, len(entries))
		for _, e := range entries { data = append(data, out{IP: e.IP.String(), Expires: e.Expires, Comment: e.Comment}) }
		b, _ := json.MarshalIndent(data, "", "  "); fmt.Println(string(b)); return
	}
	if len(entries) == 0 { fmt.Println("(no blocked IPs)"); return }
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP.String() < entries[j].IP.String() })
	fmt.Printf("%-40s %-20s %s\n", "IP", "Expires", "Comment")
	for _, e := range entries { exp := "-"; if e.Expires != nil { exp = e.Expires.Format(time.RFC3339) }; fmt.Printf("%-40s %-20s %s\n", e.IP.String(), exp, e.Comment) }
}

// flush --------------------------------------------------------------------

func runFlush(args []string) {
	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
	cmds := []string{
		fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "block_v4"),
		fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "block_v6"),
		//fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "allow_v4"), // don't touch our whitelists
		//fmt.Sprintf("flush set %s %s %s", "inet", "cfm", "allow_v6"),
	}
	for _, c := range cmds {
		out, err := exec.Command("nft", strings.Split(c, " ")...).CombinedOutput()
		if err != nil { fmt.Fprintf(os.Stderr, "flush error: %s: %v\n", string(out), err); os.Exit(1) }
	}
	fmt.Println("✔ flushed all blocked/allowed IPs")
}

// flags/positionals ---------------------------------------------------------

func splitFlagsAndPositionals(args []string, valueFlags map[string]bool) (flagArgs []string, posArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			name := a
			if idx := strings.Index(a, "="); idx != -1 { flagArgs = append(flagArgs, a); continue }
			flagArgs = append(flagArgs, a)
			if valueFlags[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") { flagArgs = append(flagArgs, args[i+1]); i++ }
			continue
		}
		posArgs = append(posArgs, a)
	}
	return
}

// --- config helpers --------------------------------------------------------

const cfmStatePath = "/run/cfm/config.path" // daemon writes here the active config dir

func writeConfigState(dir string) { _ = os.MkdirAll(filepath.Dir(cfmStatePath), 0755); _ = os.WriteFile(cfmStatePath, []byte(dir), 0644) }

func readConfigState() (string, bool) {
	b, err := os.ReadFile(cfmStatePath); if err != nil { return "", false }
	s := strings.TrimSpace(string(b)); if s == "" { return "", false }
	return s, true
}

func resolveConfigDir(explicit string) (string, bool) {
	if explicit != "" { if dirExists(explicit) { return explicit, true }; return "", false }
	if env := strings.TrimSpace(os.Getenv("CFM_CONFIG_DIR")); env != "" { if dirExists(env) { return env, true } }
	if s, ok := readConfigState(); ok && dirExists(s) { return s, true }
	if dirExists("/etc/cfm") { return "/etc/cfm", true }
	if d, ok := nearestConfigsDir(); ok { return d, true }
	return "", false
}

func dirExists(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

// finds the nearest ancestor containing a "configs" dir (handy in dev repo)
func nearestConfigsDir() (string, bool) {
	cwd, err := os.Getwd(); if err != nil { return "", false }
	d := cwd
	for {
		cand := filepath.Join(d, "configs")
		if dirExists(cand) { return cand, true }
		parent := filepath.Dir(d)
		if parent == d { break }
		d = parent
	}
	return "", false
}

func ensureDir(p string) error { return os.MkdirAll(p, 0755) }

func appendUniqueLine(dir, base, line string) error {
	if err := ensureDir(dir); err != nil { return err }
	fp := filepath.Join(dir, base)
	if b, err := os.ReadFile(fp); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() { if strings.TrimSpace(sc.Text()) == strings.TrimSpace(line) { return nil } }
	}
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); if err != nil { return err }
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

// παλιά υπογραφή:
// func removeIPFromFile(dir, base, ip string) error {

// νέα υπογραφή:
func removeIPFromFile(dir, base, ip string) (bool, error) {
    fp := filepath.Join(dir, base)
    b, err := os.ReadFile(fp)
    if err != nil {
        if os.IsNotExist(err) { return false, nil }
        return false, err
    }
    var out bytes.Buffer
    removed := false

    sc := bufio.NewScanner(bytes.NewReader(b))
    for sc.Scan() {
        line := sc.Text()
        trim := strings.TrimSpace(line)
        if trim == "" || strings.HasPrefix(trim, "#") {
            fmt.Fprintln(&out, line)
            continue
        }
        // κόψε στο 1ο token (πριν από κενό/σχόλιο)
        first := trim
        if i := strings.IndexAny(first, " \t#"); i >= 0 {
            first = first[:i]
        }
        if first == ip || first == ip+"/32" {
            removed = true
            continue
        }
        fmt.Fprintln(&out, line)
    }
    if err := sc.Err(); err != nil { return false, err }
    if !removed { return false, nil }
    return true, os.WriteFile(fp, out.Bytes(), 0644)
}

func containsIPInFile(dir, base, ip string) bool {
    fp := filepath.Join(dir, base)
    b, err := os.ReadFile(fp)
    if err != nil { return false }
    sc := bufio.NewScanner(bytes.NewReader(b))
    for sc.Scan() {
        trim := strings.TrimSpace(sc.Text())
        if trim == "" || strings.HasPrefix(trim, "#") { continue }
        first := trim
        if i := strings.IndexAny(first, " \t#"); i >= 0 { first = first[:i] }
        if first == ip || first == ip+"/32" { return true }
    }
    return false
}



// entries parsing -----------------------------------------------------------

type fileEntry struct { IP net.IP; TTL *time.Duration; Until *time.Time }

func readEntriesFromFile(path string) ([]fileEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil { if os.IsNotExist(err) { return nil, nil }; return nil, err }
	var out []fileEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text()); if line == "" || strings.HasPrefix(line, "#") { continue }
		fields := strings.Fields(line); if len(fields) == 0 { continue }
		ip := net.ParseIP(fields[0]); if ip == nil { continue }
		var ttl *time.Duration; var until *time.Time
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "ttl=") {
				if d, err := time.ParseDuration(strings.TrimPrefix(f, "ttl=")); err == nil && d > 0 { ttl = &d }
			} else if strings.HasPrefix(f, "until=") {
				if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(f, "until=")); err == nil { until = &t }
			}
		}
		out = append(out, fileEntry{IP: ip, TTL: ttl, Until: until})
	}
	return out, nil
}

func durationFromEntryNow(e fileEntry, now time.Time) *time.Duration {
	if e.Until != nil { rem := e.Until.Sub(now); if rem > 0 { return &rem }; return nil }
	return e.TTL
}

// blocklist utils -----------------------------------------------------------

// split into hosts (IPs or /32|/128) vs nets (CIDR < max prefix)
func partitionHostsNets(elems []string, isV6 bool) (hosts []string, nets []string) {
	seenH, seenN := map[string]struct{}{}, map[string]struct{}{}
	maxBits := 32; if isV6 { maxBits = 128 }
	for _, s := range elems {
		s = strings.TrimSpace(s); if s == "" { continue }
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s); if err != nil { continue }
			ones, bits := n.Mask.Size(); if bits != maxBits { continue }
			if ones == maxBits { ip := n.IP.String(); if _, ok := seenH[ip]; !ok { seenH[ip] = struct{}{}; hosts = append(hosts, ip) } } else {
				if _, ok := seenN[s]; !ok { seenN[s] = struct{}{}; nets = append(nets, s) }
			}
		} else {
			ip := net.ParseIP(s); if ip == nil { continue }
			if !isV6 && ip.To4() == nil { continue }
			if isV6 && (ip.To16() == nil || ip.To4() != nil) { continue }
			ipS := ip.String(); if _, ok := seenH[ipS]; !ok { seenH[ipS] = struct{}{}; hosts = append(hosts, ipS) }
		}
	}
	return
}

// ----------------------------------------------------------------------------
// which command (read-only query)
// ----------------------------------------------------------------------------
func runWhich(args []string) {
    fs := flag.NewFlagSet("which", flag.ExitOnError)
    asJSON := fs.Bool("json", false, "output JSON")
    _ = fs.Parse(args)
    if fs.NArg() < 1 {
        fmt.Fprintln(os.Stderr, "usage: cfm which <IP> [--json]")
        os.Exit(2)
    }

    arg := fs.Arg(0)

    hits, err := ipquery.Find(arg)
    if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
        os.Exit(1)
    }

    // πάρ’ το cfgDir (αν έχεις ήδη αυτή τη helper)
    cfgDir, _ := resolveConfigDir("")
    suffix := ipquery.EnrichSuffix(cfgDir, arg)

    if *asJSON {
        b, _ := json.MarshalIndent(hits, "", "  ")
        fmt.Println(string(b))
        return
    }
    if len(hits) == 0 {
        fmt.Println("(no matches)")
        return
    }
    fmt.Printf("Matches for %s%s:\n", arg, suffix)
    for _, h := range hits {
        feed := ""
        if h.Feed != "" {
            feed = fmt.Sprintf(" (feed: %s)", h.Feed)
        }
        fmt.Printf(" - %s via %s %s in set %s%s\n", h.Action, h.Via, h.Match, h.Set, feed)
    }
}



// reset/disable -------------------------------------------------------------

func runReset(args []string) {
	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if nb, ok := be.(*nft.Backend); ok { if err := nb.ResetTable(); err != nil { fmt.Fprintln(os.Stderr, "reset error:", err); os.Exit(1) }; fmt.Println("✔ reset: flushed table inet cfm (rules & sets emptied)"); return }
	fmt.Fprintln(os.Stderr, "reset: unsupported backend"); os.Exit(1)
}

func runDisable(args []string) {
	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
	if nb, ok := be.(*nft.Backend); ok { if err := nb.DropEverything(); err != nil { fmt.Fprintln(os.Stderr, "disable error:", err); os.Exit(1) }; fmt.Println("✔ disable: deleted table inet cfm (firewall off)"); return }
	fmt.Fprintln(os.Stderr, "disable: unsupported backend"); os.Exit(1)
}

