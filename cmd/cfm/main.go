package main

import (
	"bufio"
	"bytes"
	agentpkg "cfm/internal/agent"
	"cfm/internal/blocklists"
	cfgpkg "cfm/internal/config"
	detpkg "cfm/internal/detectors"
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	"cfm/internal/logging"
	"cfm/internal/notify"
	status "cfm/internal/status"
	"cfm/internal/sysctl"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	// api server for debug and api endpoints //
	"cfm/internal/apiserver"

	nflog "cfm/internal/nflog"

	mmdb "cfm/internal/maxmindupdater"

	"cfm/internal/detectors/mysql"
	"cfm/internal/dnat"
	"cfm/internal/sslcollector"
	"cfm/internal/vhostmap"
	webdet "cfm/internal/webdetector"

	"cfm/internal/cli"
	"cfm/internal/dyndns"
	"cfm/internal/filewatch"
)

var (
	Version   = "dev"
	BuildTime = ""
)

// ----------------------------------------------------------------------------
// Backend abstraction
// ----------------------------------------------------------------------------

func getBackend() firewall.Backend {
	if _, ok := cli.LookPath("nft"); ok {
		return nft.New()
	}
	return nil
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
		cli.RunTest()
	case "block":
		os.Exit(cli.RunBlock(os.Args[2:], getBackend(), cfgDir()))
	case "unblock":
		os.Exit(cli.RunUnblock(os.Args[2:], getBackend(), cfgDir()))
	case "list":
		os.Exit(cli.RunList(os.Args[2:], getBackend()))
	case "allow":
		os.Exit(cli.RunAllow(os.Args[2:], getBackend(), cfgDir()))
	case "unallow":
		os.Exit(cli.RunUnallow(os.Args[2:], getBackend(), cfgDir()))
	case "allow-list":
		os.Exit(cli.RunAllowList(os.Args[2:], getBackend()))
	case "daemon":
		runDaemon(os.Args[2:])
	case "flush":
		os.Exit(cli.RunFlush(os.Args[2:], getBackend()))
	case "which", "search":
		os.Exit(cli.RunWhich(os.Args[2:], getBackend(), cfgDir()))
	case "asn":
		os.Exit(cli.RunASN(os.Args[2:]))
	case "htpasswd":
		os.Exit(cli.RunHtpasswd(os.Args[2:]))
	case "status":
		status.Run(os.Args[2:])
	case "reset":
		os.Exit(cli.RunReset(os.Args[2:], getBackend()))
	case "disable":
		os.Exit(cli.RunDisable(os.Args[2:], getBackend()))

	case "ssl", "sslcollector", "ssl-collector":
		sslcollector.RunCLI(os.Args[2:])

	case "dnat":
		os.Exit(dnat.RunCLI(os.Args[2:], getBackend()))

	case "webtop", "nginx-top", "httpd-top":
		addr := apiBaseURL()
		if err := webdet.RunWebTop(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "webtop error:", err)
			os.Exit(1)
		}

	case "mysqltop", "mysql-top", "mysql":
		addr := apiBaseURL()
		if err := mysql.RunMySQLTop(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "mysqltop error:", err)
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
	  cfm asn <AS12345> [--json] -- list announced prefixes for ASN
	  cfm htpasswd <username> [password] -- print username:{SHA}... for OpenResty auth_basic_user_file
	  cfm status [--json] [--timings] [--no-ttl] [--cache-ttl 5s]
  cfm disable -- disable and drop everything in nft
  cfm reset   -- empty all tables / sets

  cfm ssl stats [--json]
  cfm ssl scan  [--json]
  cfm ssl dump <host> [--json]
  cfm ssl refresh [--json]

  cfm dnat

  cfm webtop  <vhost> -- Live stats for specific vhost
  cfm mysqltop -- MySQL Live stats

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
	if cfgDir != "" {
		cli.WriteConfigState(cfgDir)
		logging.Logf("CFM Starting")
		logging.Logf("→ using config dir: %s", cfgDir)
	} else {
		logging.Logf("→ no config dir found (no -c / no CFM_CONFIG_DIR / no /etc/cfm / no ./configs). Running without file persistence.")
	}

	// Backend
	done := step("backend:getBackend")
	be := getBackend()
	done()
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
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
					for _, f := range feeds {
						keys = append(keys, f.Name)
					}
					_ = nb.PruneExternalFeeds(keys)
				}
			}
		}()
		defer close(blReloadCh)
	}
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
			// διαφοροποίηση key για IP vs CIDR
			key := ""
			if e.CIDR != "" {
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
			dur := durationFromEntryNow(e, now)
			if isAllow {
				if e.CIDR != "" {
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

				if e.CIDR != "" {
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
		entries, err := readEntriesFromFile(filePath)
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
			if e.CIDR != "" {
				key = "cidr|" + e.CIDR
			} else {
				key = "ip|" + e.IP.String()
			}
			if prev, ok := seenIgnore[key]; ok && prev == spec {
				continue
			}
			dur := durationFromEntryNow(e, now)
			if e.CIDR != "" {
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
	sslSockLc := sslcollector.NewSockLifecycle(sslcol)
	defer sslSockLc.Stop()

	// vhostmap
	vmapLc := vhostmap.NewLifecycle()
	defer vmapLc.Stop()

	// SMTP NFLOG snooper lifecycle (start-once, driven by config)
	smtpLc := nflog.NewSnoopLifecycle()

	// Ensure base data dirs exist with correct permissions
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/var/lib/cfm", 0o701},
		{"/var/lib/cfm/sslcollector", 0o701},
		{"/var/log/cfm", 0o700},
	} {
		_ = os.MkdirAll(d.path, d.mode)
		_ = os.Chmod(d.path, d.mode)
	}

	// ── Lifecycle managers ──────────────────────────────────────────────────────
	mmdbLc := mmdb.NewLifecycle()
	defer mmdbLc.Stop()

	govLc := mysql.NewGovernorLifecycle()

	// ── applySystemConfig ────────────────────────────────────────────────────────
	// Stateless: logging init, sysctl tweaks, SMTP owner resolution.
	applySystemConfig := func(cfg *cfgpkg.Config) {
		cfg.SystemTweaks.SetDefaults()
		logging.Init(&cfg.Logging)
		for _, ln := range cfg.Summary() {
			logging.Logf("[config] %s", ln)
		}
		resolveSMTPAllowOwners(cfg)
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
		go apiserver.Start(ctx, cfg, be, cfgDir, gov)

		_ = os.Setenv("CFM_DEBUG_HTTP_STARTED", "1")
		logging.Logf("[apiserver] http server on %s:%d", cfg.Debug.ListenAddress, cfg.Debug.Port)
	}

	// ── applyNFTRules ────────────────────────────────────────────────────────────
	// Stateless: flood rules, ports policy, SMTP block, reporter, NFLOG snooper.
	applyNFTRules := func(cfg *cfgpkg.Config) {
		nb, ok := be.(*nft.Backend)
		if !ok {
			return
		}
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

		if cfg.SMTPBlock.Enabled {
			if err := nb.ApplySMTPBlock(&cfg.SMTPBlock); err != nil {
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
			nb.SetReporter(&agentpkg.APIClient{BaseURL: cfg.API.URL, Token: cfg.API.AuthToken})
		}
		smtpLc.ApplyConfig(ctx, &cfg.SMTPBlock)
	}

	// ── onCFMConfChanged ─────────────────────────────────────────────────────────
	// Parses cfm.conf once when it changes, distributes to all subsystems.
	onCFMConfChanged := func() {
		if cfgDir == "" || confW == nil {
			return
		}
		b, ok := confW.Changed()
		if !ok {
			return
		}
		cfg, err := cli.LoadConfigWithAPIOverride(cfgDir, b)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cfm.conf parse error:", err)
			return
		}

		applySystemConfig(cfg)                            // logging, sysctl, SMTP owners
		mmdbLc.ApplyConfig(ctx, &cfg.MaxMind)             // MaxMind updater
		sslSockLc.ApplyConfig(ctx, &cfg.SSLCollectorSock) // SSL collector socket
		vmapLc.ApplyConfig(ctx, &cfg.VHostMap)            // VHost map
		agLc.ApplyConfig(cfg)                             // API agent
		applyDebugServer(cfg)                             // MySQL governor + debug HTTP (start-once)
		applyNFTRules(cfg)                                // nft: flood, ports, smtp, reporter, nflog
	}

	// ── Initial load ─────────────────────────────────────────────────────────────
	done = step("initial:loadAll")
	loadAll()
	done()

	// Start detectors BEFORE first onCFMConfChanged(), so applyDebugServer() can
	// see mysql_governor pending config.
	detpkg.SetFW(be)
	detpkg.Start(ctx, detpkg.Options{
		CfgPath: filepath.Join(cfgDir, "detectors.conf"),
		Sink:    detpkg.OutcomeLoggerSink{},
		FW:      be,
	})

	done = step("initial:onCFMConfChanged")
	onCFMConfChanged()
	done()

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

// entries parsing -----------------------------------------------------------

type fileEntry struct {
	IP    net.IP // single ip
	CIDR  string // subnet
	TTL   *time.Duration
	Until *time.Time
}

func readEntriesFromFile(path string) ([]fileEntry, error) {
	path = filepath.Clean(path)
	b, err := os.ReadFile(path) // #nosec G304 - callers pass constant filenames from a trusted config dir

	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []fileEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {

		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		// κόψε inline σχόλια: "value ... # comment"
		head := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		fields := strings.Fields(head)
		if len(fields) == 0 {
			continue
		}

		tok := fields[0]
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
	if e.Until != nil {
		rem := e.Until.Sub(now)
		if rem > 0 {
			return &rem
		}
		return nil
	}
	return e.TTL
}
