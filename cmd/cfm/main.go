package main

import (
	"bytes"
	agentpkg "cfm/internal/agent"
	"cfm/internal/allowlist"
	"cfm/internal/blocklists"
	cfgpkg "cfm/internal/config"
	detpkg "cfm/internal/detectors"
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	"cfm/internal/firewall/nftlib"
	"cfm/internal/logging"
	"cfm/internal/notify"
	"cfm/internal/panelauth"
	status "cfm/internal/status"
	"cfm/internal/sysctl"
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	// api server for debug and api endpoints //
	"cfm/internal/apiserver"

	nflog "cfm/internal/nflog"
	"cfm/internal/outbound"

	mmdb "cfm/internal/maxmindupdater"

	"cfm/internal/detectors/mysql"
	"cfm/internal/dnat"
	"cfm/internal/sslcollector"
	webdet "cfm/internal/webdetector"

	"cfm/internal/clam"
	"cfm/internal/cli"
	"cfm/internal/clihttp"
	"cfm/internal/dyndns"
	"cfm/internal/filewatch"
	"cfm/internal/healthcli"
)

var (
	Version   = "dev"
	BuildTime = ""
)

// ----------------------------------------------------------------------------
// Backend abstraction
// ----------------------------------------------------------------------------

func resolveFirewallEngine(cfg *cfgpkg.Config) (string, string) {
	if engine := strings.ToLower(strings.TrimSpace(os.Getenv("CFM_FIREWALL_ENGINE"))); engine != "" {
		return engine, "env"
	}
	if cfg != nil {
		if engine := strings.ToLower(strings.TrimSpace(cfg.Firewall.Engine)); engine != "" {
			return engine, "config"
		}
	}
	return "nft", "default"
}

func getBackend(engine string) (firewall.Backend, error) {
	switch engine {
	case "nft":
		if _, ok := cli.LookPath("nft"); ok {
			return nft.New(), nil
		}
		return nil, fmt.Errorf("nft backend selected but nft binary not found")
	case "nftlib":
		be, err := nftlib.New()
		if err != nil {
			return nil, fmt.Errorf("nftlib backend: %w", err)
		}
		return be, nil
	case "pf":
		// Placeholder for future pf backend.
		return nil, fmt.Errorf("firewall engine \"pf\" not built yet")
	case "iptables":
		// Placeholder for future iptables backend.
		return nil, fmt.Errorf("firewall engine \"iptables\" not built yet")
	default:
		return nil, fmt.Errorf("unsupported firewall engine %q (supported: nft, nftlib, pf, iptables)", engine)
	}
}

func mustBackend() firewall.Backend {
	engine, _ := resolveFirewallEngine(nil)
	be, err := getBackend(engine)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return be
}

func tableExistsProbe(be firewall.Backend) func() bool {
	return func() bool {
		if engine, _ := resolveFirewallEngine(nil); engine == "nft" {
			return nft.TableExistsCFM()
		}
		return be != nil
	}
}

// cfgDir resolves the active config directory for one-shot CLI commands.
func cfgDir() string {
	d, _ := cli.ResolveConfigDir("")
	return d
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

// Base URL helper for API Address and loader //
func apiBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("CFM_API_ADDR")); v != "" {
		return strings.TrimRight(v, "/")
	}

	dir, _ := cli.ResolveConfigDir("")
	if dir == "" {
		return "http://127.0.0.1:6060"
	}

	b, err := os.ReadFile(filepath.Join(dir, "cfm.conf"))
	if err != nil {
		return "http://127.0.0.1:6060"
	}

	cfg, err := cli.LoadConfigWithAPIOverride(dir, b)
	if err != nil || cfg == nil {
		return "http://127.0.0.1:6060"
	}

	host := strings.TrimSpace(cfg.Debug.ListenAddress)
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}

	return fmt.Sprintf("http://%s:%d", host, cfg.Debug.Port)
}

// apiAuthToken reads AUTH_TOKEN from cfm.conf for use by CLI commands.
// Returns empty string if config cannot be read or token is not set.
func apiAuthToken() string {
	dir, _ := cli.ResolveConfigDir("")
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "cfm.conf"))
	if err != nil {
		return ""
	}
	cfg, err := cli.LoadConfigWithAPIOverride(dir, b)
	if err != nil || cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.API.AuthToken)
}

func sslSockDefaults() (string, string) {
	dir := cfgDir()
	if dir == "" {
		return "/var/run/sslcollector.sock", ""
	}

	b, err := os.ReadFile(filepath.Join(dir, "cfm.conf"))
	if err != nil {
		return "/var/run/sslcollector.sock", ""
	}

	cfg, err := cli.LoadConfigWithAPIOverride(dir, b)
	if err != nil || cfg == nil {
		return "/var/run/sslcollector.sock", ""
	}

	sock := strings.TrimSpace(cfg.SSLCollectorSock.SockPath)
	if sock == "" {
		sock = "/var/run/sslcollector.sock"
	}

	return sock, cfg.SSLCollectorSock.Token
}

func main() {

	// cfm auth — short-circuits before config load or server start.
	// The daemon does not need to be running.
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		runAuthCLI()
		return
	}

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
		cli.RunTest()
	case "block":
		be := mustBackend()
		os.Exit(cli.RunBlock(os.Args[2:], be, cfgDir(), tableExistsProbe(be)))
	case "unblock":
		be := mustBackend()
		os.Exit(cli.RunUnblock(os.Args[2:], be, cfgDir(), tableExistsProbe(be)))
	case "list":
		be := mustBackend()
		os.Exit(cli.RunList(os.Args[2:], be, tableExistsProbe(be)))
	case "allow":
		be := mustBackend()
		os.Exit(cli.RunAllow(os.Args[2:], be, cfgDir(), tableExistsProbe(be)))
	case "unallow":
		be := mustBackend()
		os.Exit(cli.RunUnallow(os.Args[2:], be, cfgDir(), tableExistsProbe(be)))
	case "allow-list":
		be := mustBackend()
		os.Exit(cli.RunAllowList(os.Args[2:], be, tableExistsProbe(be)))
	case "daemon":
		runDaemon(os.Args[2:])
	case "flush":
		be := mustBackend()
		os.Exit(cli.RunFlush(os.Args[2:], be, tableExistsProbe(be)))
	case "which", "search":
		be := mustBackend()
		os.Exit(cli.RunWhich(os.Args[2:], be, cfgDir(), tableExistsProbe(be)))
	case "asn":
		os.Exit(cli.RunASN(os.Args[2:]))
	case "htpasswd":
		os.Exit(cli.RunHtpasswd(os.Args[2:]))
	case "status":
		status.Run(os.Args[2:], mustBackend())
	case "reset":
		os.Exit(cli.RunReset(os.Args[2:], mustBackend()))
	case "disable":
		os.Exit(cli.RunDisable(os.Args[2:], mustBackend()))

	case "ssl", "sslcollector", "ssl-collector":
		sock, token := sslSockDefaults()
		sslcollector.RunCLI(os.Args[2:], sock, token)

	case "dnat":
		os.Exit(dnat.RunCLI(os.Args[2:], mustBackend()))

	case "webtop", "nginx-top", "httpd-top":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := webdet.RunWebTop(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "webtop error:", err)
			os.Exit(1)
		}

	case "mysqltop", "mysql-top", "mysql":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := mysql.RunMySQLTop(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "mysqltop error:", err)
			os.Exit(1)
		}

	case "health":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := healthcli.Run(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "health error:", err)
			os.Exit(1)
		}

	case "clam", "clamd", "clamav":
		os.Exit(cli.RunClam(os.Args[2:], cfgDir()))

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
  cfm auth ... -- authentication/user-session management for cfm-admin UI (OpenResty proxy and direct UI ports like 6060/6061 /cfm-admin)
  cfm daemon [--interval 20s]
  cfm flush
  cfm which <IP> [--json]   -- search <IP>
  cfm asn <AS12345> [--json] -- list announced prefixes for ASN
  cfm htpasswd <username> [password] -- legacy quick helper: generate OpenResty/htpasswd-compatible bcrypt ($2y$) entry
  cfm status [--json] [--timings] [--ttl-summary] [--cache-ttl 5s]
  cfm disable -- disable and drop everything in nft
  cfm reset   -- empty all tables / sets

  cfm ssl stats [--json]
  cfm ssl scan  [--json]
  cfm ssl dump <host> [--json]
  cfm ssl refresh [--json]

  cfm dnat

  cfm webtop  <vhost> -- Live stats for specific vhost
  cfm mysqltop -- MySQL Live stats
  cfm health                      -- local-node health summary (federation view planned)
  cfm health json                 -- machine-readable local snapshot
  cfm health watch --interval=2s  -- periodic one-line local snapshot output
  cfm health live                 -- TTY dashboard; non-TTY auto-falls back to watch

  cfm clam ping
  cfm clam version
  cfm clam scan <file-or-dir>

Options (overall top):
  --limit N        rows for the main top table (default 10)
  --smin F         suspicious score threshold (default 0.60)
  --slimit N       rows under "Suspicious vhosts" (default 10)
  --json           output JSON of the main top table (suppresses the pretty table)


Description:
  local nftables manager (block/allow with optional TTL),
   `)
}

// ----------------------------------------------------------------------------
// Daemon
// ----------------------------------------------------------------------------

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

	cfgDir, _ := cli.ResolveConfigDir(*cfgFlag)

	// ── GOMAXPROCS floor ─────────────────────────────────────────────────────────
	// The cfm daemon runs blocking exec.Command calls (nft list set, nft list
	// counter, ps, etc.) that pin Go OS threads. If GOMAXPROCS equals the CPU
	// count (the default), a burst of shell-outs can starve the nginx bridge
	// socket HTTP server goroutines — Lua times out and sites go down.
	// Ensure at least 8 threads so the HTTP server always has scheduling capacity.
	{
		const minProcs = 8
		if cur := runtime.GOMAXPROCS(0); cur < minProcs {
			runtime.GOMAXPROCS(minProcs)
			logging.Logf("[daemon] GOMAXPROCS raised %d → %d (floor for shell-out safety)", cur, minProcs)
		}
	}

	if cfgDir != "" {
		cli.WriteConfigState(cfgDir)
		logging.Logf("CFM Starting")
		logging.Logf("→ using config dir: %s", cfgDir)
	} else {
		logging.Logf("→ no config dir found (no -c / no CFM_CONFIG_DIR / no /etc/cfm / no ./configs). Running without file persistence.")
	}

	var engineCfg *cfgpkg.Config
	if cfgDir != "" {
		if b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf")); err == nil {
			if cfg, err := cli.LoadConfigWithAPIOverride(cfgDir, b); err == nil {
				engineCfg = cfg
			}
		}
	}
	engine, engineSource := resolveFirewallEngine(engineCfg)
	logging.Logf("[startup] firewall engine: %s (source=%s)", engine, engineSource)

	// Backend
	done := step("backend:getBackend")
	be, err := getBackend(engine)
	done()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

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
	ddm := dyndns.NewManager(be, cfgDir)
	done()

	done = step("dyndns:FileChanged")
	_ = ddm.FileChanged()
	done()

	done = step("dyndns:LoadOnce")
	_ = ddm.LoadOnce(context.Background())
	done()

	// NFT backend extras
	done = step("nft:extras")
	be.EnableEnrichment(cfgDir, "/var/lib/cfm/maxmind", "/etc/cfm", "./configs")
	be.SetConfigDir(cfgDir)
	notify.SetEnricher(be.GetEnricher())
	done()

	// Blocklists Manager (scheduler+apply)

	done = step("blocklists:wiring")
	var (
		blMgr      *blocklists.Manager
		blReloadCh chan []blocklists.Feed
	)

	blMgr = blocklists.NewManager(blocklists.ApplierFunc(be.ApplyFeed))

	// Start scheduler
	blMgr.Start(context.Background())
	defer blMgr.Stop()

	blReloadCh = make(chan []blocklists.Feed, 1)

	go func() {
		for feeds := range blReloadCh {
			start := time.Now()
			blMgr.Reload(feeds)
			logging.Logf("[blocklists] reload applied: %d feeds in %s", len(feeds), time.Since(start))

			if be != nil {
				keys := make([]string, 0, len(feeds))
				for _, f := range feeds {
					keys = append(keys, f.Name)
				}
				_ = be.PruneExternalFeeds(keys)
			}
		}
	}()
	defer close(blReloadCh)
	done()

	// Watchers
	var allowW, denyW, blW, confW, ignW *filewatch.Watcher
	if cfgDir != "" {
		allowW = filewatch.New(filepath.Join(cfgDir, "cfm.allow"))
		denyW = filewatch.New(filepath.Join(cfgDir, "cfm.deny"))
		blW = filewatch.New(filepath.Join(cfgDir, "cfm.blocklists"))
		confW = filewatch.New(filepath.Join(cfgDir, "cfm.conf"))
		ignW = filewatch.New(filepath.Join(cfgDir, "cfm.ignore"))
	}

	// Track seen allow/block entries to avoid pointless TTL refreshes
	seenAllow := map[string]string{} // ip -> spec (perm|ttl=..|until=..)
	seenBlock := map[string]string{}
	seenIgnore := map[string]string{}

	applyFile := func(filePath string, isAllow bool) {
		now := time.Now()
		entries, _, err := allowlist.ReadEntriesFromFile(context.Background(), filePath, allowlist.ReadOptions{ResolveHostnames: isAllow, ResolverTimeout: 2 * time.Second})
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
			// διαφοροποίηση key για IP vs CIDR
			key := ""
			if e.Kind == allowlist.KindCIDR {
				key = "cidr|" + e.CIDR
			} else {
				key = "ip|" + e.IP.String()
			}
			if isAllow {
				if prev, ok := seenAllow[key]; ok && prev == spec {
					continue
				}
			} else {
				if prev, ok := seenBlock[key]; ok && prev == spec {
					continue
				}
			}
			dur := allowlist.DurationFromEntryNow(e, now)
			if isAllow {
				if e.Kind == allowlist.KindCIDR {
					if err := be.AddAllowNet(e.CIDR, dur); err != nil {
						fmt.Fprintln(os.Stderr, "allow apply error:", err)
						continue
					}
				} else {
					if err := be.AddAllow(e.IP, dur); err != nil {
						fmt.Fprintln(os.Stderr, "allow apply error:", err)
						continue
					}
				}
				seenAllow[key] = spec
			} else {

				if e.Kind == allowlist.KindCIDR {
					if err := be.AddBlockNet(e.CIDR, dur); err != nil {
						fmt.Fprintln(os.Stderr, "block apply error:", err)
						continue
					}
				} else {
					if err := be.AddBlock(e.IP, "", dur); err != nil {
						fmt.Fprintln(os.Stderr, "block apply error:", err)
						continue
					}
				}
				seenBlock[key] = spec
			}
		}
	}

	//ignore feature //
	applyIgnoreFile := func(filePath string) {
		now := time.Now()
		entries, _, err := allowlist.ReadEntriesFromFile(context.Background(), filePath, allowlist.ReadOptions{ResolverTimeout: 2 * time.Second})
		if err != nil {
			fmt.Fprintln(os.Stderr, "read ignore error:", err)
			return
		}
		for _, e := range entries {
			spec := "perm"
			if e.Until != nil {
				spec = "until=" + e.Until.UTC().Format(time.RFC3339)
			} else if e.TTL != nil {
				spec = "ttl=" + e.TTL.String()
			}
			key := ""
			if e.Kind == allowlist.KindCIDR {
				key = "cidr|" + e.CIDR
			} else {
				key = "ip|" + e.IP.String()
			}
			if prev, ok := seenIgnore[key]; ok && prev == spec {
				continue
			}
			dur := allowlist.DurationFromEntryNow(e, now)
			if e.Kind == allowlist.KindCIDR {
				if err := be.AddIgnoreNet(e.CIDR, dur); err != nil {
					fmt.Fprintln(os.Stderr, "ignore apply error:", err)
					continue
				}
			} else {
				if err := be.AddIgnore(e.IP, dur); err != nil {
					fmt.Fprintln(os.Stderr, "ignore apply error:", err)
					continue
				}
			}
			seenIgnore[key] = spec
		}
	}
	// ignore end//

	loadAll := func() {
		if cfgDir == "" {
			return
		}

		// decide what changed (and avoid reapplying both if only one changed)
		var allowChanged, denyChanged, ignChanged bool

		if allowW != nil {
			if _, ch := allowW.Changed(); ch {
				allowChanged = true
			}
		}
		if denyW != nil {
			if _, ch := denyW.Changed(); ch {
				denyChanged = true
			}
		}
		if ignW != nil {
			if _, ch := ignW.Changed(); ch {
				ignChanged = true
			}
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
			applyIgnoreFile(ignW.Path())
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
		if cfgDir == "" || blW == nil || blMgr == nil {
			return
		}
		b, changed := blW.Changed()
		if !changed {
			return
		}
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
				select {
				case <-blReloadCh:
				default:
				}
				blReloadCh <- feeds
			}
			logging.Logf("[blocklists] config reloaded (queued): %d feeds", len(feeds))
			return
		}
		// fallback (shouldn't happen)
		blMgr.Reload(feeds)
		logging.Logf("[blocklists] config reloaded: %d feeds", len(feeds))

	}

	// agent
	agLc := agentpkg.NewLifecycle(Version, be, cfgDir)
	defer agLc.Stop()

	// cfm.conf loader/applier (single place)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// periodic clam bridge retry
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = detpkg.TryWireClamBridge()
			}
		}
	}()

	// NOTE: detectors should be started early so config-only sections (like mysql_governor)
	// can populate pending configs before applyDebugServer() tries to consume them.

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
	sslSockLc := sslcollector.NewSockLifecycle(sslcol, filepath.Join(cfgDir, "cfm.conf"))
	defer sslSockLc.Stop()

	go func() {
		if err := panelauth.Serve(ctx, "/var/run/cfm-auth.sock"); err != nil && ctx.Err() == nil {
			logging.Logf("[panel-auth] stopped: %v", err)
		}
	}()

	// SMTP NFLOG snooper lifecycle (start-once, driven by config)
	smtpLc := nflog.NewSnoopLifecycle()

	// Outbound Abuse Sentinel lifecycle (phase 1: observe + warn)
	outboundLc := outbound.NewLifecycle()

	// Ensure base data dirs exist with correct permissions.
	// /var/lib/cfm/sslcollector is owned root:cfm 0770 so the OpenResty worker
	// (running as the cfm user) can write the cert snapshot there.
	// cfmGID is 0 when the cfm group does not exist yet (install-openresty.sh
	// not yet run); os.Chown with GID 0 is a no-op — permissions stay root:root
	// and the daemon logs a warning when the socket server starts.
	cfmGID := sslcollector.CfmGroupID()
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/var/lib/cfm", 0o701},
		{"/var/lib/cfm/lua", 0o750},
		{"/var/lib/cfm/sslcollector", 0o770},
		{"/var/lib/cfm/scanner", 0o700},
		{"/var/lib/cfm/scanner/pending", 0o700},
		{"/var/lib/cfm/scanner/infected", 0o700},
		{"/var/log/cfm", 0o700},
		// /var/run is tmpfs on systemd systems — recreate on every daemon start.
		// Without this the bridge socket (OPENRESTY_SOCK) creation fails on boot.
		// 0750 root:cfm: OpenResty/Angie workers (cfm group) need to traverse in
		// to reach sockets; no other local user has a reason to list this dir.
		// The chown to cfm gid happens below alongside the other cfm-group dirs.
		{"/var/run/cfm", 0o750},
	} {
		_ = os.MkdirAll(d.path, d.mode)
		_ = os.Chmod(d.path, d.mode)
	}
	if cfmGID > 0 {
		_ = os.Chown("/var/lib/cfm/lua", 0, cfmGID)
		_ = os.Chown("/var/lib/cfm/sslcollector", 0, cfmGID)
		_ = os.Chown("/var/run/cfm", 0, cfmGID)
		// Chown the snapshot file if it already exists (e.g. written as root:root
		// before the cfm group was in place). Without this, OpenResty (cfm user)
		// cannot read the snapshot on startup until it successfully writes a new one.
		_ = os.Chown("/var/lib/cfm/sslcollector/dump.json", 0, cfmGID)
		// nginx cache dirs: root:cfm 0770 so OpenResty workers (cfm group) can write.
		for _, d := range []string{
			"/var/cache/nginx/cfm_static",
			"/var/cache/nginx/cfm_micro",
		} {
			_ = os.MkdirAll(d, 0o770)
			_ = os.Chmod(d, 0o770)
			_ = os.Chown(d, 0, cfmGID)
		}
	}

	// ── Lifecycle managers ──────────────────────────────────────────────────────
	mmdbLc := mmdb.NewLifecycle()
	defer mmdbLc.Stop()

	govLc := mysql.NewGovernorLifecycle()

	var clamMgr *clam.Manager
	defer func() {
		if clamMgr != nil {
			clamMgr.Stop()
		}
	}()

	// ── applySystemConfig ────────────────────────────────────────────────────────
	// Stateless: logging init, sysctl tweaks, SMTP owner resolution.
	applySystemConfig := func(cfg *cfgpkg.Config) {
		cfg.SystemTweaks.SetDefaults()
		logging.Init(&cfg.Logging)

		clam.SetLogger(logging.LogfCLAM)

		if clamMgr != nil {
			clamMgr.Stop()
			clamMgr = nil
			detpkg.SetClamManager(nil)
			detpkg.ResetClamBridgeWireState()
		}

		if cfg.Clam.Enabled {
			clamMgr = clam.NewManager(clam.Config{
				Enabled:     cfg.Clam.Enabled,
				Network:     cfg.Clam.Network,
				Address:     cfg.Clam.Address,
				Timeout:     cfg.Clam.Timeout,
				MaxWorkers:  cfg.Clam.MaxWorkers,
				QueueSize:   cfg.Clam.QueueSize,
				PendingDir:  cfg.Clam.PendingDir,
				InfectedDir: cfg.Clam.InfectedDir,
			})
			if nb, ok := be.(*nft.Backend); ok {
				if enr := nb.GetEnricher(); enr != nil {
					clamMgr.SetEnricher(enr)
				}
			}
			clamMgr.Start()
			detpkg.SetClamManager(clamMgr)
			_ = detpkg.TryWireClamBridge()

			if cfg.Clam.PendingDir != "" {
				go func(dir string) {
					t := time.NewTicker(5 * time.Minute)
					defer t.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-t.C:
							sweepPendingDir(dir, 10*time.Minute)
						}
					}
				}(cfg.Clam.PendingDir)
			}

			logging.LogfCLAM("[clam] enabled network=%s address=%s timeout=%s workers=%d queue=%d pending=%s infected=%s",
				cfg.Clam.Network, cfg.Clam.Address, cfg.Clam.Timeout,
				cfg.Clam.MaxWorkers, cfg.Clam.QueueSize,
				cfg.Clam.PendingDir, cfg.Clam.InfectedDir)
		} else {
			detpkg.SetClamManager(nil)
			detpkg.ResetClamBridgeWireState()
			logging.LogfCLAM("[clam] disabled")
		}

		for _, ln := range cfg.Summary() {
			logging.Logf("[config] %s", ln)
		}
		resolveSMTPAllowOwners(cfg)
		resolveOutboundAllowOwners(cfg)
		if err := sysctl.ApplyTweaks(&cfg.SystemTweaks); err != nil {
			fmt.Fprintln(os.Stderr, "sysctl tweaks error:", err)
		}
	}

	// ── applyDebugServer ─────────────────────────────────────────────────────────
	// ── NEW applyDebugServer ─────────────────────────────────────────────────────

	applyDebugServer := func(cfg *cfgpkg.Config) {
		if os.Getenv("CFM_DEBUG_HTTP_STARTED") != "" {
			return
		}

		// Start the MySQL governor (unchanged logic — was already here).
		govCfg, ok := detpkg.GetPendingGovernorConfig()
		var cfgPtr *mysql.GovernorConfig
		if ok {
			cfgPtr = &govCfg
		}
		gov := govLc.StartOnce(ctx, cfgPtr)

		// Start the unified internal HTTP server.
		// Registers pprof, /unblock, and mysql governor routes internally.
		go apiserver.Start(ctx, cfg, be, cfgDir, gov, sslcol)

		_ = os.Setenv("CFM_DEBUG_HTTP_STARTED", "1")
		logging.Logf("[apiserver] http server on %s:%d", cfg.Debug.ListenAddress, cfg.Debug.Port)
	}

	// ── applyNFTRules ────────────────────────────────────────────────────────────
	// Stateless: flood rules, ports policy, SMTP block, reporter, NFLOG snooper.
	applyNFTRules := func(cfg *cfgpkg.Config) {

		logging.Logf("[daemon] === Begin ApplyFloodRules ===")
		if err := be.ApplyFloodRules(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "flood rules apply error:", err)
		}
		logging.Logf("[daemon] === End ApplyFloodRules ===")

		logging.Logf("[daemon] === Begin ApplyPortsPolicy ===")
		if err := be.ApplyPortsPolicy(&cfg.Ports); err != nil {
			fmt.Fprintln(os.Stderr, "apply ports policy error:", err)
		}
		logging.Logf("[daemon] === End ApplyPortsPolicy ===")

		if cfg.SMTPBlock.Enabled {
			if err := be.ApplySMTPBlock(&cfg.SMTPBlock); err != nil {
				fmt.Fprintln(os.Stderr, "smtpblock apply error:", err)
			} else {
				logging.Logf("[smtpblock] applied (mode=%s, ports=%v, allow_local=%v, nflog=%d)",
					map[bool]string{false: "block", true: "redirect"}[cfg.SMTPBlock.Redirect],
					cfg.SMTPBlock.Ports, cfg.SMTPBlock.AllowLocal, cfg.SMTPBlock.LogNFLOG,
				)
			}
		}
		logging.Logf("[daemon] === Finished all nft applies ===")

		if cfg.API.URL != "" && cfg.API.AuthToken != "" {
			be.SetReporter(&agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken})
		}
		smtpLc.ApplyConfig(ctx, &cfg.SMTPBlock)

		// Outbound Abuse Sentinel — observe-only nft chain + NFLOG collector.
		// The chain is installed/cleaned every reload (idempotent); the
		// collector goroutine is start-once.
		if err := be.ApplyOutboundObserve(&cfg.Outbound); err != nil {
			fmt.Fprintln(os.Stderr, "outbound observe apply error:", err)
		} else if cfg.Outbound.Enabled {
			logging.Logf("[outbound] observe chain applied (group=%d)", cfg.Outbound.NFLOGGroup)
		}
		outboundLc.ApplyConfig(ctx, &cfg.Outbound)
	}

	// ── onCFMConfChanged ─────────────────────────────────────────────────────────
	// Parses cfm.conf once when it changes.
	loadCFMConfigIfChanged := func() (*cfgpkg.Config, bool) {
		if cfgDir == "" || confW == nil {
			return nil, false
		}
		b, ok := confW.Changed()
		if !ok {
			return nil, false
		}
		cfg, err := cli.LoadConfigWithAPIOverride(cfgDir, b)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cfm.conf parse error:", err)
			return nil, false
		}
		return cfg, true
	}

	// Phase 1: config/system + MaxMind lifecycle (must happen before detectors on first boot).
	applyCFMConfigEarly := func(cfg *cfgpkg.Config) {
		applySystemConfig(cfg)                // logging, sysctl, SMTP owners
		mmdbLc.ApplyConfig(ctx, &cfg.MaxMind) // MaxMind updater/fallback
	}

	// Phase 3: remaining subsystems after detector startup on first boot.
	applyCFMConfigRemaining := func(cfg *cfgpkg.Config) {
		sslSockLc.ApplyConfig(ctx, &cfg.SSLCollectorSock) // SSL collector socket
		agLc.ApplyConfig(cfg)                             // API agent
		applyDebugServer(cfg)                             // MySQL governor + debug HTTP (start-once)
		applyNFTRules(cfg)                                // nft: flood, ports, smtp, reporter, nflog
	}

	// Parses cfm.conf once when it changes and applies all reloadable phases.
	onCFMConfChanged := func() {
		cfg, ok := loadCFMConfigIfChanged()
		if !ok {
			return
		}
		applyCFMConfigEarly(cfg)
		applyCFMConfigRemaining(cfg)
	}

	// ── Initial load ─────────────────────────────────────────────────────────────
	done = step("initial:loadAll")
	loadAll()
	done()

	// First boot sequencing:
	//   1) early cfm.conf phase (system + MaxMind updater/fallback),
	//   2) detector startup (needed for mysql_governor pending config),
	//   3) remaining cfm.conf phase (API/debug/nft/etc.).
	done = step("initial:loadCFMConfigIfChanged")
	cfg, cfgOK := loadCFMConfigIfChanged()
	done()
	if cfgOK {
		done = step("initial:applyCFMConfigEarly")
		applyCFMConfigEarly(cfg)
		done()
	}

	done = step("initial:detectorsStart")
	detpkg.SetFW(be)
	detpkg.Start(ctx, detpkg.Options{
		CfgPath: filepath.Join(cfgDir, "detectors.conf"),
		Sink:    detpkg.OutcomeLoggerSink{},
		FW:      be,
	})
	done()

	if cfgOK {
		done = step("initial:applyCFMConfigRemaining")
		applyCFMConfigRemaining(cfg)
		done()
	}

	done = step("initial:reloadBlocklists")
	reloadBlocklists()
	done()

	if ignW != nil {
		applyIgnoreFile(ignW.Path())
	}
	if os.Getenv("CFM_DEBUG") == "1" {
		fmt.Printf("Starting MAD COW FIREWALL v2 Moooooooh Maf|[]z05 rulez\n")
	}
	logging.Logf("cfm daemon starting (tick=%s). Ctrl+C to exit.\n", interval.String())

	// DNAT failsafe: if OpenResty ports die while DNAT is ON, turn it OFF.
	dnat.StartFailSafe(ctx, be)

	// ── Main tick loop ───────────────────────────────────────────────────────────
	t := time.NewTicker(*interval)
	defer t.Stop()
	for range t.C {
		reloadBlocklists() // only if cfm.blocklists changed
		loadAll()          // only if cfm.allow / cfm.deny / cfm.ignore changed
		onCFMConfChanged() // only if cfm.conf changed

		// DumpFloodCounters and LoadPortScanner are internally non-blocking:
		// each launches its own goroutine with an overlap guard (if a previous
		// tick's work is still running, the new call is a no-op). No wrapper
		// goroutine needed here — they return immediately.
		be.DumpFloodCounters()
		be.LoadPortScanner()
		if ddm.FileChanged() {
			_ = ddm.LoadOnce(context.Background())
		} else {
			ddm.Tick(context.Background(), time.Now())
		}
	}
}

// --- config helpers --------------------------------------------------------

// Resolve SMTP allow-list owners (usernames/groups) into numeric IDs in-place.
func resolveSMTPAllowOwners(cfg *cfgpkg.Config) {
	if cfg == nil {
		return
	}
	// Users → UIDs
	seenUID := map[uint32]struct{}{}
	for _, u := range cfg.SMTPBlock.AllowUIDs {
		seenUID[u] = struct{}{}
	}
	for _, name := range cfg.SMTPBlock.AllowUsers {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
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
	for id := range seenUID {
		cfg.SMTPBlock.AllowUIDs = append(cfg.SMTPBlock.AllowUIDs, id)
	}

	// Groups → GIDs
	seenGID := map[uint32]struct{}{}
	for _, g := range cfg.SMTPBlock.AllowGIDs {
		seenGID[g] = struct{}{}
	}
	for _, name := range cfg.SMTPBlock.AllowGroups {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if g, err := user.LookupGroup(name); err == nil {
			if gid64, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
				seenGID[uint32(gid64)] = struct{}{}
			}
		}
	}
	cfg.SMTPBlock.AllowGIDs = cfg.SMTPBlock.AllowGIDs[:0]
	for id := range seenGID {
		cfg.SMTPBlock.AllowGIDs = append(cfg.SMTPBlock.AllowGIDs, id)
	}
}

// Resolve outbound allow-list owners (usernames/groups) into numeric IDs in-place.
func resolveOutboundAllowOwners(cfg *cfgpkg.Config) {
	if cfg == nil {
		return
	}

	// Users → UIDs (always include root).
	seenUID := map[uint32]struct{}{0: {}}
	for _, u := range cfg.Outbound.AllowUIDs {
		seenUID[u] = struct{}{}
	}
	defaultUsers := []string{"cfm", "mailnull"}
	for _, name := range append(defaultUsers, cfg.Outbound.AllowUsers...) {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if u, err := user.Lookup(name); err == nil {
			if uid64, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
				seenUID[uint32(uid64)] = struct{}{}
			}
		}
	}
	cfg.Outbound.AllowUIDs = cfg.Outbound.AllowUIDs[:0]
	for id := range seenUID {
		cfg.Outbound.AllowUIDs = append(cfg.Outbound.AllowUIDs, id)
	}

	// Groups → GIDs.
	seenGID := map[uint32]struct{}{}
	for _, g := range cfg.Outbound.AllowGIDs {
		seenGID[g] = struct{}{}
	}
	defaultGroups := []string{"cfm", "mail"}
	for _, name := range append(defaultGroups, cfg.Outbound.AllowGroups...) {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if g, err := user.LookupGroup(name); err == nil {
			if gid64, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
				seenGID[uint32(gid64)] = struct{}{}
			}
		}
	}
	cfg.Outbound.AllowGIDs = cfg.Outbound.AllowGIDs[:0]
	for id := range seenGID {
		cfg.Outbound.AllowGIDs = append(cfg.Outbound.AllowGIDs, id)
	}
}

func sweepPendingDir(dir string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "upload_") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		logging.LogfCLAM("[clam] sweep removed stale temp path=%s age=%s",
			path, time.Since(info.ModTime()).Round(time.Second))
		_ = os.Remove(path)
	}
}
