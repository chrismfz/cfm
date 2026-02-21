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
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"strconv"
	"math"
//	"log"
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

	//Debugging profiler for CPU usage
	"net/http"
	"net/http/pprof"
	//Debugging End
	nflog "cfm/internal/nflog"

	mmdb "cfm/internal/maxmindupdater"

        webdet "cfm/internal/webdetector"
	"cfm/internal/sslcollector"
	"cfm/internal/vhostmap"

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
// Debugger - Start in runDaemon
// ----------------------------------------------------------------------------
// startDebug launches a local pprof/metrics server on given address (e.g. "127.0.0.1:6060")
//
// Access only from localhost unless you change the bind address.
// Safe to leave running permanently; overhead is near zero until endpoints hit.
//
// Example usage when daemon is running:
//
//   # 60-second CPU profile → load in go tool pprof
//   curl -o /tmp/cfm.cpu http://127.0.0.1:6060/debug/pprof/profile?seconds=60
//   go tool pprof /usr/bin/cfm /tmp/cfm.cpu
//
//   # Goroutine dump (text)
//   curl http://127.0.0.1:6060/debug/pprof/goroutine?debug=2 | less
//
//   # Heap profile
//   curl -o /tmp/cfm.heap http://127.0.0.1:6060/debug/pprof/heap
//   go tool pprof /usr/bin/cfm /tmp/cfm.heap
//
//   # Metrics (if promhttp enabled)
//   curl http://127.0.0.1:6060/metrics
//

func startDebug(addr string) {
    // Resolve cfgDir once (so /unblock’s background job can edit cfm.deny)
    var cfgDir string
    if d, ok := resolveConfigDir(""); ok {
        cfgDir = d
    }

    // Grab the already-initialized backend (daemon mode)
    be := getBackend()
mux := http.NewServeMux()

    // /unblock: fast local unblock + immediate response, then background cleanup (CSF/Fail2Ban/Imunify)
        mux.HandleFunc("/unblock", func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        w.Header().Set("Content-Type", "application/json")

        // ---- Parse IP from query, form, JSON, or raw body ----
        ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
        if ipStr == "" && r.Method == http.MethodPost {
            ct := strings.ToLower(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0])
            switch {
            case ct == "application/json":
                var tmp struct{ IP string `json:"ip"` }
                _ = json.NewDecoder(r.Body).Decode(&tmp)
                ipStr = strings.TrimSpace(tmp.IP)
            case ct == "application/x-www-form-urlencoded" || strings.HasPrefix(ct, "multipart/form-data"):
                if err := r.ParseForm(); err == nil {
                    ipStr = strings.TrimSpace(r.Form.Get("ip"))
                    if ipStr == "" && len(r.Form) == 1 {
                        // Allow bare payload: -d "1.2.3.4"
                        for k := range r.Form { ipStr = strings.TrimSpace(k); break }
                    }
                }
            default:
                // text/plain or unknown: support "IP" or "IP # comment"
                b, _ := io.ReadAll(r.Body)
                s := strings.TrimSpace(string(b))
                if i := strings.IndexAny(s, " \t#"); i > 0 { s = strings.TrimSpace(s[:i]) }
                ipStr = s
            }
        }

        ip := net.ParseIP(ipStr)
        if ip == nil {
            w.WriteHeader(http.StatusBadRequest)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid or missing ip"})
            return
        }
        if be == nil {
            w.WriteHeader(http.StatusServiceUnavailable)
            _ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no firewall backend"})
            return
        }

        // ---- FAST local path: detect + remove from nft
        wasBlocked := false
        if entries, err := be.ListBlocks(); err == nil {
            for _, e := range entries {
                if e.IP.Equal(ip) { wasBlocked = true; break }
            }
        }
        _ = be.RemoveBlock(ip) // idempotent; fine if not present

        // (A) capture requester once (for logs later)
        requester := func() string {
            if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
                parts := strings.Split(xf, ",")
                return strings.TrimSpace(parts[0])
            }
            host, _, err := net.SplitHostPort(r.RemoteAddr)
            if err != nil { return r.RemoteAddr }
            return host
        }()

        // ---- Immediate response
        _ = json.NewEncoder(w).Encode(map[string]any{
            "ok":          true,
            "ip":          ip.String(),
            "was_blocked": wasBlocked,
            "duration_ms": time.Since(start).Milliseconds(),
            "bg_cleanup":  true,
        })

        // ---- Fire-and-forget: CSF / Fail2Ban / Imunify (and logs) ----
        go func(ip net.IP, requester string) {
            bgStart := time.Now()
            ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
            defer cancel()

            // Re-run local removals idempotently + cfm.deny cleanup + csf/fail2ban/imunify + feed detection
            res, _ := unblock.Do(ctx, ip, unblock.Options{
                BE:            be,
                ConfigDir:     cfgDir,
                TempWhitelist: true,     // add allow if feed-blocked (override); set to false if you don’t want this
                AllowTTL:      nil,      // e.g. &ttl := 24*time.Hour
                Reporter:      nil,      // no API chatter from this endpoint
                ReportWhy:     "debug-endpoint",
                SendAPI:       false,
                Fail2BanUnban: true,
                // RemoveFromFeeds: true, // enable if you also want to delete from block_ext_* host sets (not recommended)
            })

            // (B) Summarize to api.log (single summary + per-step)
            elapsed := time.Since(bgStart)
            logging.LogfAPI("[unblock] requester=%s ip=%s took=%s was_blocked=%t from_feeds=%s whitelisted=%t steps=%d",
                requester, ip.String(), elapsed, res.WasBlocked, strings.Join(res.FromFeeds, ","), res.Whitelisted, len(res.Steps))

            for _, s := range res.Steps {
                detail := s.Detail
                if len(detail) > 200 { detail = detail[:200] + "…" }
                logging.LogfAPI("[unblock.step] ip=%s src=%s action=%s dur=%s feeds=%v err=%q detail=%q",
                    ip.String(), s.Source, s.Action, s.Dur, s.Feeds, s.Err, detail)
            }
        }(ip, requester)
    })




// pprof endpoints — registered on our private mux only
    mux.HandleFunc("/debug/pprof/", pprof.Index)
    mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
    mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
    mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
    mux.HandleFunc("/debug/pprof/trace", pprof.Trace)




// Optional: small banner without requiring logging.Init
go func(a string) {
    time.Sleep(50 * time.Millisecond)

    srv := &http.Server{
        Addr:              a,
        Handler:           mux,
        ReadHeaderTimeout: 2 * time.Second,
        ReadTimeout:       5 * time.Second,
        WriteTimeout:      10 * time.Second,
        IdleTimeout:       60 * time.Second,
        MaxHeaderBytes:    1 << 20, // 1MB
    }

    // Start server
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        // log if you want: logging.Logf("debug HTTP: %v", err)
    }
}(addr)


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


//CUSTOM CONFIG CODE//
// loadConfigWithAPIOverride parses cfm.conf, then (if present) parses cfm.api.conf
// and overwrites only API fields when set.  If cfm.api.conf exists, it ensures
// safe permissions (0600) since it may contain credentials.
func loadConfigWithAPIOverride(cfgDir string, baseBytes []byte) (*cfgpkg.Config, error) {
    cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(baseBytes))
    if err != nil {
        return nil, err
    }

    if cfgDir == "" {
        return cfg, nil
    }

    apiPath := filepath.Clean(filepath.Join(cfgDir, "cfm.api.conf"))

    info, err := os.Stat(apiPath)
    if err != nil {
        // file missing or unreadable → return base config
        return cfg, nil
    }

    // tighten permissions if too open (group/other readable)
    if info.Mode().Perm()&0o077 != 0 {
        if chErr := os.Chmod(apiPath, 0o600); chErr != nil {
            fmt.Fprintf(os.Stderr, "warning: could not chmod 600 %s: %v\n", apiPath, chErr)
        }
    }

    b, err := os.ReadFile(apiPath)
    if err != nil || len(b) == 0 {
        return cfg, nil
    }

    if api, err := cfgpkg.ParseCFMConf(bytes.NewReader(b)); err == nil {
        // Only override API fields when present in the override file.
        if s := strings.TrimSpace(api.API.URL); s != "" {
            cfg.API.URL = s
        }
        if s := strings.TrimSpace(api.API.AuthToken); s != "" {
            cfg.API.AuthToken = s
        }

        // Merge boolean flags (allow enabling but not forcing off)
        if api.API.AutoBlockSend {
            cfg.API.AutoBlockSend = true
        }
        if api.API.ManualBlockSend {
            cfg.API.ManualBlockSend = true
        }
        if api.API.UnblockSend {
            cfg.API.UnblockSend = true
        }
        if api.API.DetectorsSend {
            cfg.API.DetectorsSend = true
        }
    }

    return cfg, nil
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

case "ssl", "sslcollector", "ssl-collector":
    sslcollector.RunCLI(os.Args[2:])



        case "webtop" , "nginx-top" , "httpd-top":
            // Default to the same address as API_LISTEN
            addr := os.Getenv("CFM_WEBDETECTOR_ADDR")
            if addr == "" {
                addr = "http://127.0.0.1:9070"
            }
            if err := webdet.RunWebTop(addr, os.Args[2:]); err != nil {
                fmt.Fprintln(os.Stderr, "webtop error:", err)
                os.Exit(1)
            }




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
  cfm block <IP|CIDR> [-r REASON] [--ttl 1h]
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

  cfm ssl stats [--json]
  cfm ssl scan  [--json]
  cfm ssl dump <host> [--json]
  cfm ssl refresh [--json]

  cfm webtop  <vhost> -- Live stats for specific vhost

Options (overall top):
  --limit N        rows for the main top table (default 10)
  --smin F         suspicious score threshold (default 0.60)
  --slimit N       rows under "Suspicious vhosts" (default 10)
  --json           output JSON of the main top table (suppresses the pretty table)


Description:
  local nftables manager (block/allow with optional TTL),
  plus -NOT SO SIMPLE NOW- simple (lol) list/unlist/flush. `)
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
        fmt.Fprintln(os.Stderr, "usage: cfm block <IP|CIDR> [-r REASON] [--ttl 1h] | cfm block <IP|CIDR> <REASON...>")
        os.Exit(2)
    }

    target := strings.TrimSpace(posArgs[0])
    ip := net.ParseIP(target)
    var isCIDR bool
    var cidrNet string
    if ip == nil {
        if strings.ContainsRune(target, '/') {
            if _, nw, err := net.ParseCIDR(target); err == nil {
                // canonicalize: use network IP/mask
                nw.IP = nw.IP.Mask(nw.Mask)
                cidrNet = nw.String()
                isCIDR = true
            } else {
                fmt.Fprintln(os.Stderr, "invalid CIDR")
                os.Exit(2)
            }
        } else {
            fmt.Fprintln(os.Stderr, "invalid IP")
            os.Exit(2)
        }
    }

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
    // Fast path: table is already there in normal operation
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil {
            fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
            os.Exit(1)
        }
    }
    if isCIDR {
        if err := be.AddBlockNet(cidrNet, dur); err != nil {
            fmt.Fprintln(os.Stderr, "block error:", err); os.Exit(1)
        }
    } else {
        if err := be.AddBlock(ip, rsn, dur); err != nil {
            fmt.Fprintln(os.Stderr, "block error:", err); os.Exit(1)
        }
    }

    // cfm.deny (μόνο σε permanent)
    if cfgDir, ok := resolveConfigDir(""); ok {
        if dur == nil || (dur != nil && *dur <= 0) {
            // Γράφουμε σχόλιο μετά το IP — οι helpers σου αγνοούν ό,τι είναι μετά από κενό/# όταν κάνουν remove/search
            var line string
            if isCIDR { line = cidrNet } else { line = ip.String() }
            if rsn != "" { line += "  # " + rsn }
            if err := appendUniqueLine(cfgDir, "cfm.deny", line); err != nil {
                fmt.Fprintln(os.Stderr, "warn: could not update cfm.deny:", err)
            }
        }
    }

    // API report
    if cfgDir, ok := resolveConfigDir(""); ok {
        cfgPath := filepath.Clean(filepath.Join(cfgDir, "cfm.conf"))
	if b, err := os.ReadFile(cfgPath); err == nil {
            //if cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(b)); err == nil && cfg.API.ManualBlockSend {
		//use new custom conf if exists
		if cfg, err := loadConfigWithAPIOverride(cfgDir, b); err == nil && cfg.API.ManualBlockSend {
                if cfg.API.URL != "" && cfg.API.AuthToken != "" {
                    api := &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
                    // Στέλνουμε comment = reason, description = reason
                    // derive mode/ttl from --ttl
                    mode, ttlSec := "permanent", 0
                    if dur != nil && *dur > 0 {
                        mode, ttlSec = "ttl", int(dur.Seconds())
                    }
               // Προσοχή: αν το API δεν δέχεται CIDR, στείλ’ το μόνο για host IP.
                    if !isCIDR {
                        if err := api.ReportBlock(ip.String(), rsn, "manual-cli", mode, ttlSec); err != nil {
                            fmt.Printf("✔ blocked %s (API report failed: %v)\n", target, err)
                            return
                        }
                        fmt.Printf("✔ blocked %s (also sent to API)\n", target)
                        return
                    }
                    // CIDR: skip API report για να μη σπάσει
                    fmt.Printf("✔ blocked %s (API report skipped for CIDR)\n", cidrNet)
                    return

                }
            }
        }
    }

    if isCIDR {
        fmt.Printf("✔ blocked %s\n", cidrNet)
    } else {
        fmt.Printf("✔ blocked %s\n", ip.String())
    }

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

    // Only ensure on a truly fresh box; otherwise skip the expensive bootstrapping.
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil {
            fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
            os.Exit(1)
        }
    }

    cfgDir, _ := resolveConfigDir("")



    var reporter reporting.Reporter
    var sendAPI bool
    if cfgDir != "" {
        cfgPath := filepath.Clean(filepath.Join(cfgDir, "cfm.conf"))
	if b, err := os.ReadFile(cfgPath); err == nil {
            if cfg, err := loadConfigWithAPIOverride(cfgDir, b); err == nil &&
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
        dur := ""
        if s.Dur > 0 {
            dur = fmt.Sprintf(" (%.2fs)", s.Dur.Seconds())
        }
        fmt.Printf(" - %-9s via %-10s %s%s%s\n",
            s.Action, s.Source, strings.TrimSpace(extra), feeds, dur)

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
	// Πάρε το 1ο positional (ή από fs.Args() αν δεν πέρασαν με flag-split)
	target := ""
	if len(posArgs) > 0 {
		target = strings.TrimSpace(posArgs[0])
	}
	if target == "" {
		rem := fs.Args()
		if len(rem) > 0 {
			target = strings.TrimSpace(rem[0])
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: cfm allow <IP|CIDR> [--ttl 1h]")
		os.Exit(2)
	}
	// IP ή CIDR;
	var (
		ip      = net.ParseIP(target)
		isCIDR  bool
		cidrNet string
	)
	if ip == nil {
		if strings.ContainsRune(target, '/') {
			if _, nw, err := net.ParseCIDR(target); err == nil {
				nw.IP = nw.IP.Mask(nw.Mask) // canonicalize
				cidrNet = nw.String()
				isCIDR  = true
			} else {
				fmt.Fprintln(os.Stderr, "invalid CIDR")
				os.Exit(2)
			}
		} else {
			fmt.Fprintln(os.Stderr, "invalid IP")
			os.Exit(2)
		}
	}
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
    // Fast path: table is already there in normal operation
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil {
            fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
            os.Exit(1)
        }
    }

	if isCIDR {
		if err := be.AddAllowNet(cidrNet, dur); err != nil {
			fmt.Fprintln(os.Stderr, "allow error:", err)
			os.Exit(1)
		}
	} else {
		if err := be.AddAllow(ip, dur); err != nil {
			fmt.Fprintln(os.Stderr, "allow error:", err)
			os.Exit(1)
		}
	}
	// cfm.allow — μόνο για permanent (να μην αποθηκεύουμε TTL που θα λήξουν)

    if cfgDir, ok := resolveConfigDir(""); ok {
        if dur == nil || (dur != nil && *dur <= 0) {
            var line string
            if isCIDR {
                line = cidrNet // canonical μορφή στο αρχείο
            } else {
                line = ip.String()
            }
			if err := appendUniqueLine(cfgDir, "cfm.allow", line); err != nil {
				fmt.Fprintln(os.Stderr, "warn: could not update cfm.allow:", err)
			}
		}
	}
	if isCIDR {
		fmt.Printf("✔ allowed %s\n", cidrNet)
	} else {
		fmt.Printf("✔ allowed %s\n", ip.String())
	}
}




func runUnallow(args []string) {
    if len(args) < 1 {
        fmt.Fprintln(os.Stderr, "usage: cfm unallow <IP|CIDR>")
        os.Exit(2)
    }
    raw := strings.TrimSpace(args[0])

    // Κανονικοποίηση IP/CIDR (χρησιμοποιεί τη normalizeTarget που ήδη έχεις)
    isCIDR, ipStr, cidrStr, err := normalizeTarget(raw)
    if err != nil {
        fmt.Fprintln(os.Stderr, "invalid IP/CIDR")
        os.Exit(2)
    }

    be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
    // Fast path: table is already there in normal operation
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil {
            fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
            os.Exit(1)
        }
    }

    if isCIDR {
        if err := be.RemoveAllowNet(cidrStr); err != nil {
            fmt.Fprintln(os.Stderr, "unallow error:", err)
            os.Exit(1)
        }
    } else {
        if err := be.RemoveAllow(net.ParseIP(ipStr)); err != nil {
            fmt.Fprintln(os.Stderr, "unallow error:", err)
            os.Exit(1)
        }
    }

    // Καθάρισε από το cfm.allow (exact first-token match, canonicalized)
    if cfgDir, ok := resolveConfigDir(""); ok {
        if err := removeIPFromFile(cfgDir, "cfm.allow", raw); err != nil {
            // optional προειδοποίηση, δεν είναι fatal
            fmt.Fprintln(os.Stderr, "warn: could not update cfm.allow:", err)
        }
    }

    if isCIDR {
        fmt.Printf("✔ unallowed %s\n", cidrStr)
    } else {
        fmt.Printf("✔ unallowed %s\n", ipStr)
    }
}




func runAllowList(args []string) {
	fs := flag.NewFlagSet("allow-list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)
	be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }

    // read-only; only bootstrap when table is missing
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
    }
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


// timing helper for startup profiling
step := func(name string) func() {
    t := time.Now()
    logging.Logf("[startup] begin %s", name)
    return func() {
        logging.Logf("[startup] end %s (%s)", name, time.Since(t))
    }
}



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

//Start Debug//
//startDebug()
// Debug server will be started after we parse cfm.conf in applyPorts (respects LISTEN_ADDRESS/PORT)
//End Debug//


	// Backend
done := step("backend:getBackend")
be := getBackend()
done()
if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }

done = step("backend:EnsureBase")
if err := be.EnsureBase(); err != nil {
    done()
    fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
    os.Exit(1)
}
done()



	//Notify manager

done = step("notify.Init")
if err := notify.Init(cfgDir); err != nil {
    done()
    logging.Logf("[notify] init error: %v", err)
} else {
    done()
    logging.Logf("[notify] init OK")
}



	// DynDNS manager (whitelist)
done = step("dyndns:NewDynDNSManager")
ddm := NewDynDNSManager(be, cfgDir)
done()

done = step("dyndns:FileChanged")
_ = ddm.FileChanged()
done()

done = step("dyndns:LoadOnce")
_ = ddm.LoadOnce(context.Background())
done()




	// NFT backend extras
done = step("nft:extras")
if nb, ok := be.(*nft.Backend); ok {
    nb.EnableEnrichment(cfgDir, "/var/lib/cfm/maxmind", "/etc/cfm", "./configs")
    nb.SetConfigDir(cfgDir)
    notify.SetEnricher(nb.GetEnricher())
}
done()


	// Blocklists Manager (scheduler+apply)

done = step("blocklists:wiring")
var (
    blMgr      *blocklists.Manager
    nb         *nft.Backend
    blReloadCh chan []blocklists.Feed
)

if x, ok := be.(*nft.Backend); ok {
    nb = x

    blMgr = blocklists.NewManager(blocklists.ApplierFunc(nb.ApplyFeed))

    // Start scheduler
    blMgr.Start(context.Background())
    defer blMgr.Stop()

    blReloadCh = make(chan []blocklists.Feed, 1)

    go func() {
        for feeds := range blReloadCh {
            start := time.Now()
            blMgr.Reload(feeds)
            logging.Logf("[blocklists] reload applied: %d feeds in %s", len(feeds), time.Since(start))

            if nb != nil {
                keys := make([]string, 0, len(feeds))
                for _, f := range feeds { keys = append(keys, f.Name) }
                _ = nb.PruneExternalFeeds(keys)
            }
        }
    }()
    defer close(blReloadCh)
}
done()




	// Watchers
	var allowW, denyW, blW, confW, ignW *fileWatcher
	if cfgDir != "" {
		allowW = newFileWatcher(filepath.Join(cfgDir, "cfm.allow"))
		denyW  = newFileWatcher(filepath.Join(cfgDir, "cfm.deny"))
		blW    = newFileWatcher(filepath.Join(cfgDir, "cfm.blocklists"))
		confW  = newFileWatcher(filepath.Join(cfgDir, "cfm.conf"))
		ignW   = newFileWatcher(filepath.Join(cfgDir, "cfm.ignore"))
	}

	// Track seen allow/block entries to avoid pointless TTL refreshes
	seenAllow := map[string]string{} // ip -> spec (perm|ttl=..|until=..)
	seenBlock := map[string]string{}
	seenIgnore := map[string]string{}

	applyFile := func(filePath string, isAllow bool) {
		now := time.Now()
		entries, err := readEntriesFromFile(filePath)
		if err != nil { fmt.Fprintln(os.Stderr, "read config error:", err); return }
		for _, e := range entries {
			spec := "perm"
			if e.Until != nil { spec = "until=" + e.Until.UTC().Format(time.RFC3339) } else if e.TTL != nil { spec = "ttl=" + e.TTL.String() }
	   // διαφοροποίηση key για IP vs CIDR
	             key := ""
	            if e.CIDR != "" { key = "cidr|" + e.CIDR } else { key = "ip|" + e.IP.String() }
			if isAllow {
				if prev, ok := seenAllow[key]; ok && prev == spec { continue }
			} else {
				if prev, ok := seenBlock[key]; ok && prev == spec { continue }
			}
			dur := durationFromEntryNow(e, now)
			if isAllow {
                if e.CIDR != "" {
                    if err := be.AddAllowNet(e.CIDR, dur); err != nil { fmt.Fprintln(os.Stderr, "allow apply error:", err); continue }
                } else {
                    if err := be.AddAllow(e.IP, dur); err != nil { fmt.Fprintln(os.Stderr, "allow apply error:", err); continue }
                }
                seenAllow[key] = spec
			} else {

                if e.CIDR != "" {
                    if err := be.AddBlockNet(e.CIDR, dur); err != nil { fmt.Fprintln(os.Stderr, "block apply error:", err); continue }
                } else {
                    if err := be.AddBlock(e.IP, "", dur); err != nil { fmt.Fprintln(os.Stderr, "block apply error:", err); continue }
                }
                seenBlock[key] = spec
			}
		}
	}



//ignore feature //
        applyIgnoreFile := func(filePath string) {
                now := time.Now()
                entries, err := readEntriesFromFile(filePath)
                if err != nil { fmt.Fprintln(os.Stderr, "read ignore error:", err); return }
                for _, e := range entries {
                        spec := "perm"
                        if e.Until != nil { spec = "until=" + e.Until.UTC().Format(time.RFC3339) } else if e.TTL != nil { spec = "ttl=" + e.TTL.String() }
                        key := ""
                        if e.CIDR != "" { key = "cidr|" + e.CIDR } else { key = "ip|" + e.IP.String() }
                        if prev, ok := seenIgnore[key]; ok && prev == spec { continue }
                        dur := durationFromEntryNow(e, now)
                        if e.CIDR != "" {
                                if err := be.AddIgnoreNet(e.CIDR, dur); err != nil { fmt.Fprintln(os.Stderr, "ignore apply error:", err); continue }
                        } else {
                                if err := be.AddIgnore(e.IP, dur); err != nil { fmt.Fprintln(os.Stderr, "ignore apply error:", err); continue }
                        }
                        seenIgnore[key] = spec
                }
        }
// ignore end//


loadAll := func() {
    if cfgDir == "" { return }

    // decide what changed (and avoid reapplying both if only one changed)
    var allowChanged, denyChanged, ignChanged bool

    if allowW != nil {
        if _, ch := allowW.Changed(); ch { allowChanged = true }
    }
    if denyW != nil {
        if _, ch := denyW.Changed(); ch { denyChanged = true }
    }
    if ignW != nil {
        if _, ch := ignW.Changed(); ch { ignChanged = true }
    }

    if !allowChanged && !denyChanged && !ignChanged {
        return
    }

    // timing helper (local)
    step := func(name string) func() {
        t := time.Now()
        logging.Logf("[startup] begin %s", name)
        return func() { logging.Logf("[startup] end %s (%s)", name, time.Since(t)) }
    }

    doneTop := step("loadAll(total)")
    defer doneTop()

    // Apply only what's needed
    if allowChanged {
        done := step("loadAll:applyFile cfm.allow")
        applyFile(filepath.Join(cfgDir, "cfm.allow"), true)
        done()
    } else {
        logging.Logf("[startup] loadAll: skip cfm.allow (unchanged)")
    }

    if denyChanged {
        done := step("loadAll:applyFile cfm.deny")
        applyFile(filepath.Join(cfgDir, "cfm.deny"), false)
        done()
    } else {
        logging.Logf("[startup] loadAll: skip cfm.deny (unchanged)")
    }

    if ignChanged && ignW != nil {
        done := step("loadAll:applyIgnoreFile")
        applyIgnoreFile(ignW.path)
        done()
    } else if ignW != nil {
        logging.Logf("[startup] loadAll: skip ignore (unchanged)")
    }

    if os.Getenv("CFM_DEBUG") != "" {
        fmt.Println("[allow/deny/ignore] updated from files",
            "allowChanged=", allowChanged,
            "denyChanged=", denyChanged,
            "ignChanged=", ignChanged,
        )
    }
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

		// enqueue (coalesce) so we never block the main tick loop
		if blReloadCh != nil {
			select {
			case blReloadCh <- feeds:
				// ok
			default:
				// replace pending work with the latest config
				select { case <-blReloadCh: default: }
				blReloadCh <- feeds
			}
			logging.Logf("[blocklists] config reloaded (queued): %d feeds", len(feeds))
			return
		}
		// fallback (shouldn't happen)
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
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()


// --- SSL collector (start once; used later by webdetector TLS proxy) ---
sslcol := sslcollector.New(sslcollector.Config{
    Enabled:        true,
    CacheDir:       "/var/lib/cfm/sslcollector",
    StatEvery:      60 * time.Second,
    DiscoveryEvery: 6 * time.Hour,
    NegativeTTL:    30 * time.Second,
    MaxCertCache:   20000,
})

// Do one refresh now so we can log totals immediately
_ = sslcol.Refresh(context.Background())
st := sslcol.Stats()
logging.Logf("[sslcollector] pairs=%d exact_hosts=%d wildcards=%d files=%d src=%v",
    st.UniquePairs, st.ExactHosts, st.WildcardZones, st.KnownFiles, st.BySource)

// Background loop for ongoing refresh
go func() {
    if err := sslcol.Run(ctx); err != nil && ctx.Err() == nil {
        logging.Logf("[sslcollector] stopped: %v", err)
    }
}()

webdet.SetSSLCollector(sslcol)
logging.Logf("[sslcollector] started")

// --- sslcollector sock server lifecycle (driven by config reload) ---
var sslSockCancel context.CancelFunc
var sslSockCfgKey string

// vhostmap
var vhostMapCancel context.CancelFunc
var vhostMapCfgKey string


onConfigLoaded := func(cfg *cfgpkg.Config) {
    if cfg == nil {
        return
    }

    // Normalize defaults (config.SetDefaults should do this too, but be defensive)
    sp := cfg.SSLCollectorSock.SockPath
    if sp == "" {
        sp = "/var/run/sslcollector.sock"
    }
    ttl := cfg.SSLCollectorSock.PEMTTL
    if ttl <= 0 {
        ttl = 10 * time.Minute
    }
    max := cfg.SSLCollectorSock.PEMMax
    if max <= 0 {
        max = 50000
    }

    enabled := cfg.SSLCollectorSock.Enabled
    token := cfg.SSLCollectorSock.Token

    // Key used to detect changes that require restart
    key := fmt.Sprintf("%t|%s|%s|%s|%d", enabled, sp, token, ttl.String(), max)

    // Disable -> stop if running
    if !enabled {
        if sslSockCancel != nil {
            sslSockCancel()
            sslSockCancel = nil
            sslSockCfgKey = ""
            logging.Logf("[sslcollector] sock server stopped (disabled)")
        }
        return
    }

    // No change -> do nothing
    if key == sslSockCfgKey && sslSockCancel != nil {
        return
    }

    // Change -> restart
    if sslSockCancel != nil {
        sslSockCancel()
        sslSockCancel = nil
    }

    c, cancel := context.WithCancel(ctx)
    sslSockCancel = cancel
    sslSockCfgKey = key

    go func(sockPath string) {
        err := sslcollector.ServeSock(c, sslcol, sslcollector.SockServerConfig{
            Enabled:  true,
            SockPath: sockPath,
            Token:    token,
            PEMTTL:   ttl,
            PEMMax:   max,
        })
        if err != nil && c.Err() == nil {
            logging.Logf("[sslcollector] sock server stopped: %v", err)
        }
    }(sp)

    logging.Logf("[sslcollector] sock server enabled path=%s ttl=%s max=%d", sp, ttl, max)


////// SSL COLLECTOR END////


// vhostmap //

// --- vhostmap lifecycle (driven by config reload) ---
{
    vm := cfg.VHostMap

    // defaults
    if vm.TTL <= 0 {
        vm.TTL = 10 * time.Minute
    }
    if vm.VarName == "" {
        vm.VarName = "origin_http_ip"
    }
    if vm.ReloadCmd == "" {
        vm.ReloadCmd = "systemctl reload openresty"
    }

    enabled := vm.Enable
    key := fmt.Sprintf("%t|%s|%s|%s|%s|%s|%s",
        enabled, vm.WritePath, vm.TTL.String(), vm.VarName, vm.Source, vm.DefaultIP, vm.ReloadCmd)

    if !enabled {
        if vhostMapCancel != nil {
            vhostMapCancel()
            vhostMapCancel = nil
            vhostMapCfgKey = ""
            logging.Logf("[vhostmap] stopped (disabled)")
        }
    } else {
        if vm.WritePath == "" {
            logging.Logf("[vhostmap] enabled but VHOST_MAP_WRITE is empty (skipping)")
        } else if key != vhostMapCfgKey || vhostMapCancel == nil {
            if vhostMapCancel != nil {
                vhostMapCancel()
                vhostMapCancel = nil
            }
            c, cancel := context.WithCancel(ctx)
            vhostMapCancel = cancel
            vhostMapCfgKey = key

            go func(local cfgpkg.Config, vmCfg cfgpkg.VHostMapConfig) {
                _ = vhostmap.Run(c, vhostmap.Config{
                    Enable:    true,
                    WritePath: vmCfg.WritePath,
                    TTL:       vmCfg.TTL,
                    VarName:   vmCfg.VarName,
                    Source:    vmCfg.Source,
                    DefaultIP: vmCfg.DefaultIP,
                    ReloadCmd: vmCfg.ReloadCmd,
                }, loggerAdapter{})
            }(*cfg, vm)

            logging.Logf("[vhostmap] started write=%s ttl=%s var=%s", vm.WritePath, vm.TTL, vm.VarName)
        }
    }
}

//vhostmap end//

}

	var smtpSnoopStarted bool

    // Ensure base data dir exists very early
    ensureDir := func(path string, mode os.FileMode) {
        if err := os.MkdirAll(path, mode); err != nil {
            logging.Logf("[init] failed to create %s: %v", path, err)
            return
        }
        // Honor desired perms even if umask interfered
        if err := os.Chmod(path, mode); err != nil {
            logging.Logf("[init] failed to chmod %s to %o: %v", path, mode, err)
        }
    }


ensureDir("/var/lib/cfm", 0o701)
ensureDir("/var/lib/cfm/sslcollector", 0o701)
ensureDir("/var/log/cfm", 0o700)


	// MaxMind updater lifecycle
	var mmdbStarted bool
	var mmdbCancel context.CancelFunc
	// (we create the updater instance inside applyPorts after config is parsed)


	applyPorts := func() {
		if cfgDir == "" || confW == nil { return }
		b, ok := confW.Changed()
		if !ok { return }

		cfg, err := loadConfigWithAPIOverride(cfgDir, b)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cfm.conf parse error:", err)
			return
		}
		lastCfg = cfg
		onConfigLoaded(cfg)


        // ---- Debug server (start once, with config values) ----
        // Build addr from config defaults (defaults are applied by SetDefaults)
        debugAddr := fmt.Sprintf("%s:%d", cfg.Debug.ListenAddress, cfg.Debug.Port)
        // start only once; rely on ListenAndServe returning error if already bound
        // (we gate with an env flag to avoid accidental multiple starts if applyPorts runs many times)
        if os.Getenv("CFM_DEBUG_HTTP_STARTED") == "" {
            startDebug(debugAddr)
            // mark as started in-process (no need to export to env; just set process-wide)
            _ = os.Setenv("CFM_DEBUG_HTTP_STARTED", "1")
            logging.Logf("[debug] http server on %s", debugAddr)
        }



        // Ensure MaxMind dir exists after config defaults/overrides
        if cfg.MaxMind.Dir == "" {
            cfg.MaxMind.Dir = "/var/lib/cfm/maxmind"
        }
        ensureDir(cfg.MaxMind.Dir, 0o755)


		// ---- MaxMind updater start/stop based on config ----
		if cfg.MaxMind.Enabled && !mmdbStarted {
			upd := mmdb.New(mmdb.Config{
				Enabled:         cfg.MaxMind.Enabled,
				AccountID:       cfg.MaxMind.AccountID,
				LicenseKey:      cfg.MaxMind.LicenseKey,
				Editions:        cfg.MaxMind.Editions,
				Dir:             cfg.MaxMind.Dir,
				CheckEvery:      cfg.MaxMind.CheckEvery,
				MinAgeBetweenDL: cfg.MaxMind.MinAgeBetweenDL,
				HTTPTimeout:     cfg.MaxMind.HTTPTimeout,
				Permalinks:      cfg.MaxMind.Permalinks,
			})
			var c context.Context
			c, mmdbCancel = context.WithCancel(ctx)
			go func() {
				if err := upd.Run(c, func(f string, a ...any) { logging.Logf(f, a...) }); err != nil && c.Err() == nil {
					logging.Logf("[maxmind] updater stopped: %v", err)
				}
			}()
			mmdbStarted = true
			logging.Logf("[maxmind] updater started (editions=%v dir=%s every=%s min_age=%s)", cfg.MaxMind.Editions, cfg.MaxMind.Dir, cfg.MaxMind.CheckEvery, cfg.MaxMind.MinAgeBetweenDL)
		} else if !cfg.MaxMind.Enabled && mmdbStarted {
			mmdbCancel(); mmdbStarted = false; logging.Logf("[maxmind] updater stopped (disabled)")
		}


		// Defaults BEFORE summary
		cfg.SystemTweaks.SetDefaults()

		// logger + summary
		logging.Init(&cfg.Logging)
		for _, ln := range cfg.Summary() {
			logging.Logf("[config] %s", ln)
		}

		// --- SMTPBlock: resolve names -> IDs, then apply nft rules, then (optionally) start NFLOG snooper
		resolveSMTPAllowOwners(cfg)


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




    logging.Logf("[daemon] === Begin ApplyPortsPolicy ===")
    if err := nb.ApplyPortsPolicy(&cfg.Ports); err != nil {
        fmt.Fprintln(os.Stderr, "apply ports policy error:", err)
    }
    logging.Logf("[daemon] === End ApplyPortsPolicy ===")


    // Apply SMTPBlock rules (if enabled)
    if cfg.SMTPBlock.Enabled {
        if err := nb.ApplySMTPBlock(&cfg.SMTPBlock); err != nil {
            fmt.Fprintln(os.Stderr, "smtpblock apply error:", err)
        } else {
            logging.Logf("[smtpblock] applied (mode=%s, ports=%v, allow_local=%v, nflog=%d)",
                map[bool]string{false:"block", true:"redirect"}[cfg.SMTPBlock.Redirect],
                cfg.SMTPBlock.Ports, cfg.SMTPBlock.AllowLocal, cfg.SMTPBlock.LogNFLOG,
            )
        }
    }

    logging.Logf("[daemon] === Finished all nft applies ===")


  if cfg.API.URL != "" && cfg.API.AuthToken != "" {
        api := &agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken}
        nb.SetReporter(api) // από εδώ και πέρα τα autoblocks θα κάνουν ReportBlock
    }


// Start SMTP NFLOG snooper once (only if enabled + using NFLOG group)
if cfg.SMTPBlock.Enabled && cfg.SMTPBlock.LogEnabled && cfg.SMTPBlock.LogNFLOG > 0 && !smtpSnoopStarted {
    grpInt := cfg.SMTPBlock.LogNFLOG
    if grpInt < 0 || grpInt > int(math.MaxUint16) {
        logging.Logf("[smtpblock] invalid NFLOG group %d (must be 0..65535) — skipping snooper", grpInt)
    } else {
        grp := uint16(grpInt)
        go func(grp uint16, enrich bool) {
            err := nflog.Start(ctx, nflog.SnoopConfig{
                Group:  grp,
                Enrich: enrich,
                Queue:  1024,
            })
            if err != nil {
                logging.Logf("[smtpblock] nflog start error: %v", err)
            } else {
                logging.Logf("[smtpblock] nflog reader started (group=%d, enrich=%v)", grp, enrich)
            }
        }(grp, cfg.SMTPBlock.LogEnrich)
        smtpSnoopStarted = true
    }
}



	}










		// agent
		startOrUpdateAgent(cfg)
	}

	// Initial load

done = step("initial:loadAll")
loadAll()
done()

done = step("initial:applyPorts")
applyPorts()
done()

done = step("initial:reloadBlocklists(queue)")
reloadBlocklists()
done()



	if ignW != nil { applyIgnoreFile(ignW.path) }
	if os.Getenv("CFM_DEBUG") == "1" { fmt.Printf("Starting MAD COW FIREWALL v2 Moooooooh Maf|[]z05 rulez\n") }
	logging.Logf("cfm daemon starting (tick=%s). Ctrl+C to exit.\n", interval.String())



// detectors logic
// wherever you start detectors (e.g., runDaemon)

// detectors logic
//detpkg.Start(context.Background(), detpkg.Options{
detpkg.SetFW(be)

detpkg.Start(ctx, detpkg.Options{
    CfgPath: filepath.Join(cfgDir, "detectors.conf"), // use the actual filename
    Sink:    detpkg.OutcomeLoggerSink{},              // prints final "Blocked:" outcome
    FW:      be,                                      // reuse the backend created above


})



	// Loop

    t := time.NewTicker(*interval); defer t.Stop()
    for range t.C {
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


// ----------------------------------------------------------------------------
// helpers shared by commands
// ----------------------------------------------------------------------------




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

    // read-only; only bootstrap when table is missing
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
    }

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

    // mutate existing sets; only ensure when table is missing
    if !nft.TableExistsCFM() {
        if err := be.EnsureBase(); err != nil { fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1) }
    }
        sets := []string{"block_v4", "block_v6"}
        for _, setName := range sets {
                out, err := exec.Command("nft", "-n", "flush", "set", "inet", "cfm", setName).CombinedOutput()

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

func writeConfigState(dir string) { _ = os.MkdirAll(filepath.Dir(cfmStatePath), 0750); _ = os.WriteFile(cfmStatePath, []byte(dir), 0600) }

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

func ensureDir(p string) error { return os.MkdirAll(p, 0750) }

// Resolve SMTP allow-list owners (usernames/groups) into numeric IDs in-place.
func resolveSMTPAllowOwners(cfg *cfgpkg.Config) {
	if cfg == nil { return }
	// Users → UIDs
	seenUID := map[uint32]struct{}{}
	for _, u := range cfg.SMTPBlock.AllowUIDs { seenUID[u] = struct{}{} }
	for _, name := range cfg.SMTPBlock.AllowUsers {
		name = strings.TrimSpace(name); if name == "" { continue }
		if u, err := user.Lookup(name); err == nil {
            // Parse as unsigned and ensure it fits in uint32
            if uid64, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
                seenUID[uint32(uid64)] = struct{}{}
            }
		}
	}
	// Always allow root
	seenUID[0] = struct{}{}
	cfg.SMTPBlock.AllowUIDs = cfg.SMTPBlock.AllowUIDs[:0]
	for id := range seenUID { cfg.SMTPBlock.AllowUIDs = append(cfg.SMTPBlock.AllowUIDs, id) }

	// Groups → GIDs
	seenGID := map[uint32]struct{}{}
	for _, g := range cfg.SMTPBlock.AllowGIDs { seenGID[g] = struct{}{} }
	for _, name := range cfg.SMTPBlock.AllowGroups {
		name = strings.TrimSpace(name); if name == "" { continue }
		if g, err := user.LookupGroup(name); err == nil {
            if gid64, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
                seenGID[uint32(gid64)] = struct{}{}
            }
		}
	}
	cfg.SMTPBlock.AllowGIDs = cfg.SMTPBlock.AllowGIDs[:0]
	for id := range seenGID { cfg.SMTPBlock.AllowGIDs = append(cfg.SMTPBlock.AllowGIDs, id) }
}

func appendUniqueLine(dir, base, line string) error {
        if err := ensureDir(dir); err != nil { return err }
        fp := filepath.Clean(filepath.Join(dir, base))
	if b, err := os.ReadFile(fp); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() { if strings.TrimSpace(sc.Text()) == strings.TrimSpace(line) { return nil } }
	}
        // #nosec G304 - fp is a constant filename under a trusted dir
        f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); if err != nil { return err }
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}


 func removeIPFromFile(dir, filename, target string) error {
     isCIDR, ipStr, cidrStr, err := normalizeTarget(target)
     if err != nil { return err }
     want := ipStr
     if isCIDR { want = cidrStr }

     path := filepath.Clean(filepath.Join(dir, filename))
     b, err := os.ReadFile(path) // #nosec G304 - constant filename under trusted dir
     var out []string
     sc := bufio.NewScanner(bytes.NewReader(b))
     for sc.Scan() {
         raw := sc.Text()
         line := strings.TrimSpace(raw)
         if line == "" || strings.HasPrefix(line, "#") { out = append(out, raw); continue }
         head := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
         fields := strings.Fields(head); if len(fields) == 0 { out = append(out, raw); continue }
         // drop exact IP or canonical CIDR
         if fields[0] == want { continue }
         out = append(out, raw)
     }
     // keep ending newline
     return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
 }


// entries parsing -----------------------------------------------------------

 type fileEntry struct {
     IP   net.IP     // single ip
     CIDR string     // subnet
     TTL  *time.Duration
     Until *time.Time
 }



func readEntriesFromFile(path string) ([]fileEntry, error) {
        path = filepath.Clean(path)
        b, err := os.ReadFile(path) // #nosec G304 - callers pass constant filenames from a trusted config dir

	if err != nil { if os.IsNotExist(err) { return nil, nil }; return nil, err }
	var out []fileEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {

        raw := strings.TrimSpace(sc.Text())
        if raw == "" || strings.HasPrefix(raw, "#") { continue }
        // κόψε inline σχόλια: "value ... # comment"
        head := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
        fields := strings.Fields(head); if len(fields) == 0 { continue }

        tok := fields[0]
        var ttl *time.Duration; var until *time.Time
        for _, f := range fields[1:] {
			if strings.HasPrefix(f, "ttl=") {
				if d, err := time.ParseDuration(strings.TrimPrefix(f, "ttl=")); err == nil && d > 0 { ttl = &d }
			} else if strings.HasPrefix(f, "until=") {
				if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(f, "until=")); err == nil { until = &t }
			}
		}
        // IP ή CIDR;
        if strings.ContainsRune(tok, '/') {
            if _, nw, err := net.ParseCIDR(tok); err == nil {
                nw.IP = nw.IP.Mask(nw.Mask) // canonicalize
                out = append(out, fileEntry{CIDR: nw.String(), TTL: ttl, Until: until})
            }
            continue
        }
        if ip := net.ParseIP(tok); ip != nil {
            out = append(out, fileEntry{IP: ip, TTL: ttl, Until: until})
        }

	}
	return out, nil
}

func durationFromEntryNow(e fileEntry, now time.Time) *time.Duration {
	if e.Until != nil { rem := e.Until.Sub(now); if rem > 0 { return &rem }; return nil }
	return e.TTL
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
    be := getBackend(); if be == nil { fmt.Fprintln(os.Stderr, "no firewall backend available"); os.Exit(1) }
 // read-only: only ensure on a fresh box
 if !nft.TableExistsCFM() {
     if err := be.EnsureBase(); err != nil {
         fmt.Fprintln(os.Stderr, "EnsureBase error:", err); os.Exit(1)
     }
 }
    hitsFast, err := fastWhich(be, arg)
    if err != nil { fmt.Fprintln(os.Stderr, err.Error()); os.Exit(1) }


    cfgDir, _ := resolveConfigDir("")
    suffix := ipquery.EnrichSuffix(cfgDir, arg)

    if *asJSON {
        b, _ := json.MarshalIndent(hitsFast, "", "  ")
        fmt.Println(string(b))
        return
    }
    if len(hitsFast) == 0 {
        fmt.Println("(no matches)")
        return
    }
    fmt.Printf("Matches for %s%s:\n", arg, suffix)

    for _, h := range hitsFast {
        feed := ""
        if h.Feed != "" { feed = fmt.Sprintf(" (feed: %s)", h.Feed) }
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


// normalizeTarget canonicalizes an input target to either an IP string or a CIDR string.
// Returns: isCIDR, ipStr, cidrStr, error
func normalizeTarget(s string) (bool, string, string, error) {
    s = strings.TrimSpace(s)
    if s == "" {
        return false, "", "", fmt.Errorf("empty target")
    }
    if ip := net.ParseIP(s); ip != nil {
        return false, ip.String(), "", nil
    }
    if strings.ContainsRune(s, '/') {
        if _, nw, err := net.ParseCIDR(s); err == nil {
            nw.IP = nw.IP.Mask(nw.Mask)
            return true, "", nw.String(), nil
        }
        return false, "", "", fmt.Errorf("invalid CIDR")
    }
    return false, "", "", fmt.Errorf("invalid IP or CIDR")
}




// listSetNamesByPrefixes returns set names that start with any of the given prefixes,
// using a single 'nft -t list table inet cfm' (no elements printed).
func listSetNamesByPrefixes(prefixes ...string) ([]string, error) {
	out, err := exec.Command("nft", "-t", "-n", "list", "table", "inet", "cfm").CombinedOutput()
	if err != nil { return nil, fmt.Errorf("nft list table: %v: %s", err, string(out)) }

	var names []string
	pfx := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p != "" { pfx = append(pfx, p) }
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "set ") { continue }
		fields := strings.Fields(line)
		if len(fields) < 2 { continue }
		name := fields[1]
		for _, p := range pfx {
			if strings.HasPrefix(name, p) { names = append(names, name); break }
		}
	}
	return names, nil
}


// fastWhich returns hits by probing membership (no full dumps).
type whichHit struct {
	Action string // "ALLOW"/"BLOCK"
	Via    string // "manual"/"feed"
	Set    string // set name
	Match  string // exact ip or cidr
	Feed   string // optional feed key, if set name encodes it
}

func fastWhich(be firewall.Backend, ipStr string) ([]whichHit, error) {
	nb, ok := be.(*nft.Backend)
	if !ok {
		return nil, fmt.Errorf("nft backend required")
	}

	var hits []whichHit

	// -------- manual sets (hosts + nets) --------
	manualHostSets := []string{"allow_v4", "block_v4", "allow_v6", "block_v6"}
	manualNetSets  := []string{"allow_v4_nets", "block_v4_nets", "allow_v6_nets", "block_v6_nets"}

	// hosts membership (if arg is an IP)
	if ip := net.ParseIP(ipStr); ip != nil {
		ipNorm := ip.String()
		for _, s := range manualHostSets {
			ok, _ := nb.HasElem(s, ipNorm)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, whichHit{Action: act, Via: "manual", Set: s, Match: ipNorm})
			}
		}
	}

	// nets membership (if arg is a CIDR)
	if _, nw, err := net.ParseCIDR(ipStr); err == nil && nw != nil {
		cidr := nw.String()
		for _, s := range manualNetSets {
			ok, _ := nb.HasElem(s, cidr)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, whichHit{Action: act, Via: "manual", Set: s, Match: cidr})
			}
		}
	}

	// -------- feed sets (discover once, terse; then HasElem) --------
	feedSets, _ := listSetNamesByPrefixes(
		"allow_ext_v4_hosts_", "allow_ext_v6_hosts_", "allow_ext_v4_nets_", "allow_ext_v6_nets_",
		"block_ext_v4_hosts_", "block_ext_v6_hosts_", "block_ext_v4_nets_", "block_ext_v6_nets_",
	)

	// feed hosts
	if ip := net.ParseIP(ipStr); ip != nil {
		ipNorm := ip.String()
		for _, s := range feedSets {
			if !strings.Contains(s, "_hosts_") { continue }
			ok, _ := nb.HasElem(s, ipNorm)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, whichHit{
					Action: act, Via: "feed", Set: s, Match: ipNorm, Feed: feedKeyFromSet(s),
				})
			}
		}
	}

	// feed nets
	if _, nw, err := net.ParseCIDR(ipStr); err == nil && nw != nil {
		cidr := nw.String()
		for _, s := range feedSets {
			if !strings.Contains(s, "_nets_") { continue }
			ok, _ := nb.HasElem(s, cidr)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, whichHit{
					Action: act, Via: "feed", Set: s, Match: cidr, Feed: feedKeyFromSet(s),
				})
			}
		}
	}

	return hits, nil
}

// feedKeyFromSet extracts the feed name from a set like "block_ext_v4_hosts_myblock".
func feedKeyFromSet(setName string) string {
	if i := strings.LastIndex(setName, "_"); i > 0 && i < len(setName)-1 {
		return setName[i+1:]
	}
	return ""
}




func urlQueryEscape(s string) string { return strings.ReplaceAll(s, " ", "%20") }
func httpGetJSON(url string, out any) error {
    resp, err := http.Get(url); if err != nil { return err }
    defer resp.Body.Close()
    return json.NewDecoder(resp.Body).Decode(out)
}

type loggerAdapter struct{}
func (loggerAdapter) Logf(f string, a ...any) { logging.Logf(f, a...) }

