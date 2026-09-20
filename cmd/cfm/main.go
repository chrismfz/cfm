package main

import (
	"bytes"
	agentpkg "cfm/internal/agent"
	"cfm/internal/allowlist"
	"cfm/internal/blocklists"
	cfgpkg "cfm/internal/config"
	detpkg "cfm/internal/detectors"
	"cfm/internal/enrich"
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	"cfm/internal/firewall/nftlib"
	"cfm/internal/logging"
	"cfm/internal/lvecpu"
	"cfm/internal/mailtraffic"
	"cfm/internal/notify"
	"cfm/internal/panelauth"
	"cfm/internal/srcreportcli"
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
	"cfm/internal/kernsec"
	"cfm/internal/lsm"
	"cfm/internal/mailqcli"
	"cfm/internal/unblock"
)

var (
	Version   = "dev"
	BuildTime = ""
)

// ----------------------------------------------------------------------------
// Backend abstraction
// ----------------------------------------------------------------------------

func normalizeFirewallEngine(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func resolveFirewallEngine(cfg *cfgpkg.Config) (raw string, normalized string, source string) {
	if rawEnv := strings.TrimSpace(os.Getenv("CFM_FIREWALL_ENGINE")); rawEnv != "" {
		return rawEnv, normalizeFirewallEngine(rawEnv), "env"
	}
	if cfg != nil {
		if rawCfg := strings.TrimSpace(cfg.Firewall.Engine); rawCfg != "" {
			return rawCfg, normalizeFirewallEngine(rawCfg), "config"
		}
	}
	return "", "nft", "default"
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
	_, engine, _ := resolveFirewallEngine(nil)
	be, err := getBackend(engine)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logging.Logf("[startup] backend type=%T engine=%s", be, engine)
	return be
}

func tableExistsProbe(be firewall.Backend) func() bool {
	return func() bool {
		if _, engine, _ := resolveFirewallEngine(nil); engine == "nft" {
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
		// Wire a WAF cleaner that reaches the running daemon's admin API so a
		// CLI unblock also clears the OpenResty/Lua WAF planes (challenge/block
		// + per-IP shared-dict caches), not just the firewall/blocklist.
		unblock.SetWAFCleaner(unblock.NewHTTPWAFCleaner(apiBaseURL(), apiAuthToken()))
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
		clihttp.SetToken(apiAuthToken())
		os.Exit(cli.RunWhich(os.Args[2:], be, cfgDir(), apiBaseURL(), tableExistsProbe(be)))
	case "asn":
		os.Exit(cli.RunASN(os.Args[2:]))
	case "php-inventory", "php-inv":
		os.Exit(cli.RunPHPInventory(os.Args[2:]))
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
		// Set the apiserver base URL + admin token so status commands
		// can fetch the daemon's in-memory transition/probe state
		// (which is invisible to this CLI process otherwise).
		dnat.SetAPIBase(apiBaseURL())
		clihttp.SetToken(apiAuthToken())
		// Give the one-shot CLI the live config dir so `cfm dnat on` resolves
		// NFT_DNAT_PRIORITY from cfm.conf (the CLI backend carries no config;
		// only the daemon populates it). Without this the CLI ignored the file
		// and always applied the -99 default.
		dnat.SetConfigDir(cfgDir())
		os.Exit(dnat.RunCLI(os.Args[2:], mustBackend()))
	case "firewall":
		be := mustBackend()
		_, engine, source := resolveFirewallEngine(nil)
		os.Exit(cli.RunFirewall(os.Args[2:], be, cfgDir(), engine, source))

	case "webtop", "nginx-top", "httpd-top":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := webdet.RunWebTop(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "webtop error:", err)
			os.Exit(1)
		}

	case "bots", "bot-top":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := webdet.RunBots(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "bots error:", err)
			os.Exit(1)
		}

	case "mysqltop", "mysql-top", "mysql":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := mysql.RunMySQLTop(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "mysqltop error:", err)
			os.Exit(1)
		}

	case "mailtop", "mail-queue", "mailq":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := mailqcli.Run(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "mailtop error:", err)
			os.Exit(1)
		}

	case "health":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := healthcli.Run(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "health error:", err)
			os.Exit(1)
		}

	case "lve", "lvetop", "lve-top", "lve-cpu":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := lvecpu.RunCLI(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "lve error:", err)
			os.Exit(1)
		}

	case "detectors-srcresolve", "detectors-resolve", "srcresolve":
		addr := apiBaseURL()
		clihttp.SetToken(apiAuthToken())
		if err := srcreportcli.RunCLI(addr, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "detectors-srcresolve error:", err)
			os.Exit(1)
		}

	case "clam", "clamd", "clamav":
		// `cfm clam override|sigignore|infections …` hit the webdetector API,
		// so they need the API base URL + auth token, unlike the clamd-socket
		// subcommands handled by cli.RunClam. They live under `cfm clam` for
		// discoverability (next to status/enable/scan).
		if len(os.Args) >= 3 {
			runAPI := func(fn func(string, []string) error, label string) {
				clihttp.SetToken(apiAuthToken())
				if err := fn(apiBaseURL(), os.Args[3:]); err != nil {
					fmt.Fprintln(os.Stderr, label+" error:", err)
					os.Exit(1)
				}
				os.Exit(0)
			}
			switch os.Args[2] {
			case "override":
				runAPI(webdet.RunClamOverride, "clam override")
			case "sigignore":
				runAPI(webdet.RunClamSigIgnore, "clam sigignore")
			case "infections":
				runAPI(webdet.RunClamInfections, "clam infections")
			case "mode":
				// Per-vhost flips go to the API; `mode async|inline` (the
				// global default) falls through to cli.RunClam's cfm.conf path.
				if len(os.Args) >= 4 {
					switch os.Args[3] {
					case "add", "remove", "list":
						runAPI(webdet.RunClamMode, "clam mode")
					}
				}
			}
		}
		os.Exit(cli.RunClam(os.Args[2:], cfgDir()))

	case "debug":
		// Load the apiserver bearer token before dispatch — RunDebug
		// fetches /debug/pprof/* and /api/v1/* which require auth, and
		// without the token in clihttp's stash those fetches return 401.
		// Mirrors the webtop / mysqltop / health cases above.
		clihttp.SetToken(apiAuthToken())
		os.Exit(cli.RunDebug(os.Args[2:]))

	case "kernsec":
		os.Exit(kernsec.RunCLI(os.Args[2:]))

	case "lsm":
		lsm.CLIBuild = lsm.BuildMarker{Version: Version, BuildTime: BuildTime}
		os.Exit(lsm.RunCLI(os.Args[2:]))

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
  cfm which <IP|CIDR> [--json]   -- search <IP|CIDR> across nft, cfm.deny, csf, fail2ban, imunify360
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
  cfm firewall status [--verbose] [--json] [--strict]
  cfm firewall path [--hook prerouting] [--family inet] [--proto tcp] [--dport 443] [--json] [--strict]

  cfm webtop  <vhost> -- Live stats for specific vhost
  cfm bots             -- Webtop for bots only (UA-keyed, box-wide throttle/block); see "cfm bots help"
  cfm mysqltop -- MySQL Live stats
  cfm health                      -- local-node health summary (federation view planned)
  cfm health json                 -- machine-readable local snapshot
  cfm health watch --interval=2s  -- periodic one-line local snapshot output
  cfm health live                 -- TTY dashboard; non-TTY auto-falls back to watch

  cfm lve                         -- CloudLinux per-tenant CPU ranking (hottest first); non-CloudLinux hosts show nothing
  cfm lve top <N>                 -- top N tenants by CPU
  cfm lve --json                  -- raw JSON passthrough

  cfm detectors-srcresolve        -- per detector: does the daemon exist here, did resolution find its log source, and are we following it (alias: detectors-resolve)
  cfm detectors-srcresolve --wide -- + configured source keys; --json for combined JSON (source resolution + daemon coverage)

  cfm kernsec                     -- interactive TUI for kernel hardening audit (TTY); auto-falls back to text
  cfm kernsec live                -- force the TUI
  cfm kernsec text [--check]      -- plain-text audit; --check exits non-zero on WARN
  cfm kernsec status [--check]    -- alias for "text"
  cfm kernsec preview [...]       -- read-only diff: what 'apply' would select (filters: --tier --group --id --skip --force-id)
  cfm kernsec init                -- write default /etc/cfm/kernsec.conf if absent
  cfm kernsec apply [--dry-run]   -- write sysctl + boot-arg files, refresh bootloader, then apply runtime sysctls per-key with sysctl -w; prompts for irreversible-until-reboot/global-coredump risk; --check exits non-zero on drift
  cfm kernsec disable [--purge]   -- persistently disable kernsec (tier=0): strip managed boot args, empty managed sysctl; --purge removes conf entirely
  cfm kernsec monitor <action>    -- periodic drift-check systemd timer: enable | disable | remove | status

  cfm lsm                         -- alias for "cfm lsm status"
  cfm lsm status [--json --check] -- BPF LSM kernel preflight + per-policy state (read-only)
  cfm lsm preview                 -- read-only dry run: what would attach given /etc/cfm/lsm.conf + kernel
  cfm lsm probe                   -- briefly attach the BPF programs to verify the kernel accepts them, then detach (needs root)
  cfm lsm enable [--yes]          -- attach + pin BPF programs to /sys/fs/bpf/cfm (survives daemon restart); prompts when any policy is mode=enforce
  cfm lsm disable                 -- unpin + detach BPF programs
  cfm lsm init                    -- one-shot bring-up: preflight + enable + status (needs /etc/cfm/lsm.conf)

  cfm clam status                  -- pipeline + hook state, recent infections
  cfm clam enable | disable        -- master pipeline (CLAMD_ENABLED)
  cfm clam hook enable | disable   -- Lua upload interception only (CLI scan keeps working)
  cfm clam hook status
  cfm clam ping
  cfm clam version
  cfm clam scan <file-or-dir>

  cfm debug                          -- one-shot diagnostic bundle (pprof + /proc + logs + WAF state) → /tmp/cfm-debug/<ts>/
  cfm debug --duration 5m            -- extend the trace window
  cfm debug --quick                  -- short capture, skip log tails
  cfm debug --no-pprof               -- skip pprof (apiserver down)

Options (overall top):
  --limit N        rows for the main top table (default 10)
  --smin F         suspicious score threshold (default 0.60)
  --slimit N       rows under "Suspicious vhosts" (default 10)
  --json           output JSON of the main top table (suppresses the pretty table)

Config safety notes:
  - Avoid broad IGNORE_IPS/IGNORE_NETS (e.g., public cloud/customer CIDRs); they can bypass web and panel challenge decisions when shared challenge backend routing is enabled.


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

	// Ensure base data dirs exist with correct permissions BEFORE any
	// subsystem (sslcollector, lua deploy, panel-auth socket, etc.)
	// tries to write into them. Putting this at the very top of
	// runDaemon closes the brief root:root window that previously left
	// daemon-written files (eg /var/lib/cfm/sslcollector/dump.json)
	// unreadable to the cfm-group worker user — chown was happening
	// AFTER the daemon's first writes elsewhere in startup, races
	// possible with edge reloads.
	//
	// /var/lib/cfm/sslcollector is owned root:cfm 0770 so the OpenResty
	// worker (running as the cfm user) can read the cert snapshot there.
	// cfmGID is 0 when the cfm group does not exist yet
	// (install-openresty.sh not yet run); os.Chown with GID 0 is a
	// no-op — permissions stay root:root and the daemon logs a warning
	// when the socket server starts.
	cfmGID := sslcollector.CfmGroupID()
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{"/var/lib/cfm", 0o701},
		{"/var/lib/cfm/lua", 0o750},
		{"/var/lib/cfm/sslcollector", 0o770},
		// scanner dirs: root:cfm 0770. The Angie worker (cfm user)
		// writes upload spool files here via cfm_clamav.lua when the
		// request body is not already on disk as nginx's client body
		// temp. Without group-write the worker logs "[cfm_clamav]
		// cannot write temp: Permission denied" on every multipart
		// POST; the chown happens below alongside the other cfm-group
		// dirs.
		{"/var/lib/cfm/scanner", 0o770},
		{"/var/lib/cfm/scanner/pending", 0o770},
		{"/var/lib/cfm/scanner/infected", 0o770},
		{"/var/log/cfm", 0o700},
		// /var/run is tmpfs on systemd systems — recreate on every
		// daemon start. Without this the bridge socket (OPENRESTY_SOCK)
		// creation fails on boot. 0750 root:cfm: OpenResty/Angie workers
		// (cfm group) need to traverse in to reach sockets; no other
		// local user has a reason to list this dir. The chown to cfm gid
		// happens below alongside the other cfm-group dirs.
		{"/var/run/cfm", 0o750},
	} {
		_ = os.MkdirAll(d.path, d.mode)
		_ = os.Chmod(d.path, d.mode)
	}
	if cfmGID > 0 {
		_ = os.Chown("/var/lib/cfm/lua", 0, cfmGID)
		_ = os.Chown("/var/lib/cfm/sslcollector", 0, cfmGID)
		_ = os.Chown("/var/lib/cfm/scanner", 0, cfmGID)
		_ = os.Chown("/var/lib/cfm/scanner/pending", 0, cfmGID)
		_ = os.Chown("/var/lib/cfm/scanner/infected", 0, cfmGID)
		_ = os.Chown("/var/run/cfm", 0, cfmGID)
		// Chown the snapshot file if it already exists (eg written as
		// root:root before the cfm group was in place). Without this,
		// OpenResty (cfm user) cannot read the snapshot on startup
		// until it successfully writes a new one.
		_ = os.Chown("/var/lib/cfm/sslcollector/dump.json", 0, cfmGID)
		// nginx cache dirs: root:cfm 0770 so OpenResty workers (cfm
		// group) can write.
		for _, d := range []string{
			"/var/cache/nginx/cfm_static",
			"/var/cache/nginx/cfm_micro",
		} {
			_ = os.MkdirAll(d, 0o770)
			_ = os.Chmod(d, 0o770)
			_ = os.Chown(d, 0, cfmGID)
		}
	}

	// Process-wide persistent PTR cache (shared L2 for every Enricher). Best-
	// effort: if it can't be opened, enrichment falls back to per-Enricher
	// in-memory caches. Only the daemon enables it (the CLI stays in-memory).
	if err := enrich.EnablePersistentPTR("/var/lib/cfm/ptrcache.db"); err != nil {
		logging.Logf("[enrich] persistent PTR cache unavailable, using in-memory only: %v", err)
	}
	// Drain + close the PTR store on daemon shutdown. Registered before the
	// context/subsystem defers below, so (LIFO) it runs LAST — after every
	// subsystem has stopped writing to it.
	defer enrich.ShutdownPersistentPTR()

	// Mail Monitor traffic collector (tails the exim mainlog + syslog maillog
	// every minute into per-hour per-mailbox counters). Best-effort: if the
	// SQLite store can't be opened, the read endpoint just reports unavailable.
	// Only the daemon runs it (the CLI does not).
	if err := mailtraffic.Enable("/var/lib/cfm/mailtraffic.db"); err != nil {
		logging.Logf("[mailtraffic] disabled (store unavailable): %v", err)
	}
	defer mailtraffic.Shutdown()

	// Per-tenant CPU signal (CloudLinux LVE). Starts an in-memory sampler of
	// /proc/lve/list only on a CloudLinux host; a no-op everywhere else. Daemon
	// only.
	lvecpu.Enable()
	defer lvecpu.Shutdown()

	// Daemon context — created early so sslcollector (started right
	// below) and any other early-start subsystem can use it for their
	// background goroutines. The deferred cancel propagates to every
	// derived ctx when runDaemon returns.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// === SSL collector early-start ===
	// Start sslcollector BEFORE the firewall (backend, EnsureBase,
	// dyndns, blocklists, loadAll, detectors, applyXxx phases) so:
	//   - the disk snapshot is on disk within ~500ms of cfm start
	//     (was 11 seconds on hosts with 1k+ cert pairs)
	//   - the unix socket is bound within ~600ms (was 13 seconds)
	//   - the fsnotify watcher is live within ~700ms (was 13 seconds)
	// sslcollector has no firewall dependency: it scans /etc/letsencrypt,
	// /var/cpanel/ssl, /home/*/ssl etc. and serves /dumpall over a
	// unix socket. Putting it before EnsureBase costs ~500ms of delay
	// to backend setup — the kernel's pre-cfm rule state is the same
	// as t=0 either way, so the host is no less protected during that
	// window. The win: workers spawned by an angie/openresty reload
	// during cfm restart find snapshot+socket+watcher all ready,
	// instead of falling through to the self-signed fallback cert and
	// tripping HSTS in browsers (the original bug PR #883 began
	// addressing).
	sslcol := sslcollector.New(sslcollector.Config{
		Enabled:   true,
		CacheDir:  "/var/lib/cfm/sslcollector",
		StatEvery: 60 * time.Second,
		// Full filesystem rescan fallback. The fsnotify watcher now picks
		// up new domains/users within seconds (see internal/sslcollector/
		// watcher.go handleNewDir), so this is only a safety net for the
		// rare event the watcher misses (e.g. a brand-new /home* mount).
		// Kept at 1h — short enough to bound any miss, cheap enough to not
		// matter given the dynamic path carries steady-state discovery.
		DiscoveryEvery: 1 * time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxCertCache:   20000,
	})

	// Synchronous Refresh writes the snapshot to disk before any worker
	// from an in-flight edge reload tries to load_from_snapshot.
	// Uses context.Background() rather than the daemon ctx because
	// discoverPairs() (the actual filesystem walk) does not currently
	// honor ctx cancellation anyway — passing the daemon ctx would
	// have no effect on shutdown. If discoverPairs ever becomes
	// ctx-aware, switch this to ctx so SIGTERM can interrupt a slow
	// startup scan.
	//
	// The step() wrapper surfaces this scan's duration in the startup
	// log. On busy hosts (1000+ cert pairs scanning many /home/*/ssl
	// directories) the synchronous scan can take multiple seconds and
	// blocks backend setup — without the wrapper there is no visible
	// line saying "sslcollector took 3s", and operators chasing slow
	// startup have to guess.
	doneSSL := step("initial:sslcollector.Refresh")
	_ = sslcol.Refresh(context.Background())
	doneSSL()
	st := sslcol.Stats()
	logging.Logf("[sslcollector] pairs=%d exact_hosts=%d wildcards=%d files=%d src=%v",
		st.UniquePairs, st.ExactHosts, st.WildcardZones, st.KnownFiles, st.BySource)

	// Background loop for ongoing refresh + fsnotify watcher.
	go func() {
		if err := sslcol.Run(ctx); err != nil && ctx.Err() == nil {
			logging.Logf("[sslcollector] stopped: %v", err)
		}
	}()

	logging.Logf("[sslcollector] started")

	// Bind the sslcollector unix socket NOW with the config we already
	// parsed at the top of runDaemon. Without this early call the
	// socket would not bind until applyCFMConfigRemaining at the end
	// of startup — 13+ seconds late on busy hosts. The matching call
	// inside applyCFMConfigRemaining (later in this function) stays
	// as a no-op-on-first-start path that picks up operator edits to
	// /etc/cfm/cfm.conf.
	//
	// engineCfg is nil only when /etc/cfm/cfm.conf is absent or fails
	// to parse. In that case we skip the early bind and rely on the
	// later applyCFMConfigRemaining path — but that path is itself
	// gated by loadCFMConfigIfChanged() returning ok=true, which
	// requires a successful parse. So on a host with truly broken
	// cfm.conf the socket simply does not bind during this daemon
	// lifetime: same behavior as before this commit (pre-existing
	// limitation), surfaced here only because the gate is now visible
	// at the top of startup. Operators with parse errors will see the
	// usual "cfm.conf parse error" line and need to fix the config.
	sslSockLc := sslcollector.NewSockLifecycle(sslcol, filepath.Join(cfgDir, "cfm.conf"))
	defer sslSockLc.Stop()
	if engineCfg != nil {
		sslSockLc.ApplyConfig(ctx, &engineCfg.SSLCollectorSock)
	}

	rawEngine, engine, engineSource := resolveFirewallEngine(engineCfg)
	logging.Logf("[startup] firewall engine raw=%q normalized=%q source=%s", rawEngine, engine, engineSource)

	// Backend
	done := step("backend:getBackend")
	be, err := getBackend(engine)
	done()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logging.Logf("[startup] backend type=%T engine=%s", be, engine)

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

		// Fast path for cfm.deny: reconcile the permanent host entries in bulk nft
		// transactions instead of forking nft twice per IP in the loop below (the
		// single most expensive startup step on a large block list). Whatever it
		// applies is marked seen so the loop then handles only the remainder —
		// CIDRs, TTL'd entries and the allow list stay per-IP. See
		// bulkPreapplyDenyHosts; backends without the bulk reconcile fall through.
		if !isAllow {
			if bb, ok := be.(manualBulkBlocker); ok {
				bulkPreapplyDenyHosts(entries, seenBlock, bb)
			}
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

	// loadAll applies cfm.allow / cfm.deny / cfm.ignore, but only the files
	// selected by the do* flags (and only when their contents changed). The
	// scoping matters at boot: the heavy cfm.deny apply (one nft element add per
	// blocked IP — the single most expensive startup step on a busy host) is
	// deferred to the very end of startup so the edge-critical subsystems
	// (sslcollector, apiserver, ingest socket, nginx bridge, challenge) never
	// wait behind it, while the cheap, protective cfm.allow / cfm.ignore load
	// early. filewatch.Changed() primes its baseline the first time it is
	// called, so every file must be covered exactly once during boot
	// (allow+ignore early, deny late); the tick loop then calls
	// loadAll(true, true, true) every tick.
	loadAll := func(doAllow, doDeny, doIgnore bool) {
		if cfgDir == "" {
			return
		}

		// decide what changed (and avoid reapplying both if only one changed)
		var allowChanged, denyChanged, ignChanged bool

		if doAllow && allowW != nil {
			if _, ch := allowW.Changed(); ch {
				allowChanged = true
			}
		}
		if doDeny && denyW != nil {
			if _, ch := denyW.Changed(); ch {
				denyChanged = true
			}
		}
		if doIgnore && ignW != nil {
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
	// Fingerprint-policy pull → webdetector enforcement store (master plan E3
	// node slice): the agent Runner pulls the armed per-fingerprint policies
	// from cfm-web (same channel/creds as the heartbeat) and this sink swaps
	// the snapshot into the package-level store the /nginx/fppolicy bridge
	// lookup answers from. Enforcement posture (FP_POLICY / FP_POLICY_ALLOW_FPS)
	// is applied separately from detectors.conf at webdetector registration.
	agLc.SetFingerprintPolicySink(func(rows []agentpkg.FingerprintPolicyRow) {
		ps := make([]webdet.FingerprintPolicy, 0, len(rows))
		for _, row := range rows {
			ps = append(ps, webdet.FingerprintPolicy{
				ID:        row.Fingerprint,
				Kind:      row.Kind,
				Action:    row.Action,
				ExpiresAt: row.ExpiresAt,
			})
		}
		webdet.SetFingerprintPolicies(ps)
	})

	// (ctx, sslcol, sslSockLc moved to top of runDaemon — see the
	// "SSL collector early-start" block right after cfm.conf is parsed.
	// They're created BEFORE backend setup so the snapshot/socket/
	// watcher are ready in <1s instead of 11-13s on busy hosts. The
	// matching sslSockLc.ApplyConfig in applyCFMConfigRemaining stays
	// as a no-op-on-first-start path that picks up operator edits.)

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

	go func() {
		if err := panelauth.Serve(ctx, "/var/run/cfm-auth.sock"); err != nil && ctx.Err() == nil {
			logging.Logf("[panel-auth] stopped: %v", err)
		}
	}()

	// SMTP NFLOG snooper lifecycle (start-once, driven by config)
	smtpLc := nflog.NewSnoopLifecycle()

	// Outbound Abuse Sentinel lifecycle (phase 1: observe + warn)
	outboundLc := outbound.NewLifecycle()

	// cfm-lsm daemon-side adoption lifecycle. Reads /etc/cfm/lsm.conf
	// and the operator's pre-pinned BPF state at /sys/fs/bpf/cfm/
	// (created by `cfm lsm enable`) and drains events into the
	// notify pipeline. Does not auto-pin — explicit operator action.
	lsmLc := lsm.NewLifecycle(lsm.BuildMarker{Version: Version, BuildTime: BuildTime})
	defer lsmLc.Stop()

	// (state-dir mkdir+chown moved to the top of runDaemon — see the
	// block right after cfm.conf is parsed. Keeping it there ensures
	// every subsystem that writes into /var/lib/cfm finds correct
	// permissions on first write, instead of racing with the chown
	// that previously happened here.)

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
				ScanScope:   cfg.Clam.ScanScope,
				SigIgnore:   cfg.Clam.SigIgnore,

				ScanMode:      cfg.Clam.ScanMode,
				InlineTimeout: cfg.Clam.InlineTimeout,
				InlineDryRun:  cfg.Clam.InlineDryRun,
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

			logging.LogfCLAM("[clam] enabled network=%s address=%s timeout=%s workers=%d queue=%d pending=%s infected=%s nginx_hook=%v",
				cfg.Clam.Network, cfg.Clam.Address, cfg.Clam.Timeout,
				cfg.Clam.MaxWorkers, cfg.Clam.QueueSize,
				cfg.Clam.PendingDir, cfg.Clam.InfectedDir, cfg.Clam.NginxHookEnabled)
		} else {
			detpkg.SetClamManager(nil)
			detpkg.ResetClamBridgeWireState()
			logging.LogfCLAM("[clam] disabled")
		}

		// Render the cfm_clamav.lua hook switch every reload, even when
		// the master pipeline is disabled. The Lua hook should also be
		// off when CLAMD_ENABLED=false — there is nothing for it to
		// notify, so we squash both flags together for the Lua side.
		// Angie picks up the new file via loadfile() in cfm.lua on the
		// next worker init / cycle; no SIGHUP needed.
		hookEnabled := cfg.Clam.Enabled && cfg.Clam.NginxHookEnabled
		const clamavLuaConfigPath = "/var/lib/cfm/lua/cfm_clamav_config.lua"
		inlineTimeoutMs := int(cfg.Clam.InlineTimeout / time.Millisecond)
		if err := sslcollector.WriteClamavLuaConfig(clamavLuaConfigPath, hookEnabled, cfg.Clam.ScanDefault, cfg.Clam.ScanMode, inlineTimeoutMs, cfmGID); err != nil {
			logging.LogfCLAM("[clam] cfm_clamav_config.lua write failed path=%s err=%v", clamavLuaConfigPath, err)
		} else {
			logging.LogfCLAM("[clam] cfm_clamav_config.lua written path=%s enabled=%v scan_default=%v scan_mode=%s", clamavLuaConfigPath, hookEnabled, cfg.Clam.ScanDefault, cfg.Clam.ScanMode)
		}
		// Mirror the same policy into the webdetector package so the
		// vhost-controls API reports the effective per-vhost scan state
		// consistently with what the edge enforces.
		webdet.SetClamScanPolicy(hookEnabled, cfg.Clam.ScanDefault, cfg.Clam.ScanMode == "inline")

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
		// ldflags sets main.Version but not runtime/debug BuildInfo, so plumb it
		// explicitly for the MCP server's initialize result.
		apiserver.DaemonVersion = Version
		go apiserver.Start(ctx, cfg, be, cfgDir, gov, sslcol)

		_ = os.Setenv("CFM_DEBUG_HTTP_STARTED", "1")
		logging.Logf("[apiserver] http server on %s:%d", apiserver.HTTPBindAddr(cfg.Debug.ListenAddress), cfg.Debug.Port)
	}

	// ── applyNFTRules ────────────────────────────────────────────────────────────
	// Stateless: flood rules, ports policy, SMTP block, reporter, NFLOG snooper.
	applyNFTRules := func(cfg *cfgpkg.Config) {
		if capsBE, ok := be.(firewall.CapabilityReporter); ok {
			caps := capsBE.Capabilities()
			logging.Logf("[startup] backend capabilities: ports_inbound=%t portscan_sets=%t new_state_drop_fallback=%t",
				caps.PortsPolicyInboundRules, caps.PortscanTrackingSets, caps.NewStateDropFallback)
		}

		logging.Logf("[daemon] === Begin ApplyFloodRules ===")
		if err := be.ApplyFloodRules(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "flood rules apply error:", err)
		}
		logging.Logf("[daemon] === End ApplyFloodRules ===")

		logging.Logf("[daemon] === Begin ApplyPortsPolicy ===")
		logging.Logf("[ports] applying policy...")
		if err := be.ApplyPortsPolicy(&cfg.Ports); err != nil {
			fmt.Fprintln(os.Stderr, "apply ports policy error:", err)
		}
		logging.Logf("[daemon] === End ApplyPortsPolicy ===")

		// ApplyPortsPolicy rewrites the default-drop rules at the end of the
		// input chain. Re-assert the scoped `ct status dnat` accepts that
		// `cfm dnat on` / `cfm dnat cpanel on` installed so DNAT-translated
		// traffic to listener ports (e.g. 9080/9043/12082..) continues to be
		// accepted without needing those ports in TCP_IN.
		if err := be.EnsureDNATAccepts(); err != nil {
			fmt.Fprintln(os.Stderr, "ensure dnat accepts error:", err)
		}
		if on, _, perr := be.PanelDNATStatus(); perr == nil && on {
			if changes, err := be.EnsurePanelDNATAccepts(); err != nil {
				fmt.Fprintln(os.Stderr, "ensure panel dnat accepts error:", err)
			} else if len(changes) > 0 {
				for _, ch := range changes {
					logging.Logf("[ports] panel dnat reassert: %s", ch)
				}
			}
		}

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

		// cfm-lsm: adopt pinned BPF state if /sys/fs/bpf/cfm/ exists
		// AND /etc/cfm/lsm.conf has enabled=true. Start-once; no
		// auto-pin. The operator runs `cfm lsm enable` to activate
		// (which writes the pinned state); the daemon picks it up
		// here on the next reload tick.
		//
		// Also re-invoked unconditionally from the main tick loop —
		// lsm.conf is independent of cfm.conf, so an operator who
		// flips `enabled = false → true` in lsm.conf without touching
		// cfm.conf would otherwise wait until the next cfm.conf edit
		// (or daemon restart) for the lifecycle to notice.
		lsmLc.ApplyConfig(ctx)
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

	// ── Initial load (allow + ignore only) ───────────────────────────────────────
	// cfm.allow is a safety-net (protects management IPs from autoblock) and both
	// files are cheap, so they load up front. The heavy cfm.deny apply is deferred
	// to the end of startup — see "deferred deny load" just before the tick loop —
	// so edge-critical services are never held hostage by a large block list.
	done = step("initial:loadAll(allow+ignore)")
	loadAll(true, false, true)
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

	// cfm.ignore is already applied (and its watcher primed) by the initial
	// loadAll(allow+ignore) above, so there is no separate re-apply here — the
	// old unconditional applyIgnoreFile at this point was a redundant second
	// parse+apply of the same file on every boot.
	if os.Getenv("CFM_DEBUG") == "1" {
		fmt.Printf("Starting MAD COW FIREWALL v2 Moooooooh Maf|[]z05 rulez\n")
	}

	stopProcessBaseline := startProcessBaseline(ctx)
	defer stopProcessBaseline()

	logging.Logf("cfm daemon starting (tick=%s). Ctrl+C to exit.\n", interval.String())

	// DNAT failsafe: if the edge proxy stops serving (TCP listener down or
	// /__ssl_debug Lua broken) while DNAT is ON, turn it OFF; when the edge
	// recovers, the failsafe self-heals back to ON because intent is sticky.
	// RestoreOnStartup honors the persisted intent so a reboot doesn't drop
	// DNAT silently: it waits for the edge to be ready before re-enabling.
	go dnat.RestoreOnStartup(ctx, dnat.ScopeWeb, be)
	go dnat.RestoreOnStartup(ctx, dnat.ScopeCPanel, be)
	dnat.StartFailSafe(ctx, be)
	dnat.StartPanelFailSafe(ctx, be)

	// On cold boot the edge service (angie/openresty) starts long before
	// cfm and its workers seed an empty cert store. After our sslcollector
	// is bound and has loaded at least one cert, reload the edge once so
	// init_worker_by_lua_block re-runs against the now-ready snapshot.
	// No-op if disabled via env or if the edge started after us.
	sslcollector.NudgeEdgeOnFirstReady(ctx, sslcol)

	// ── Deferred deny load ───────────────────────────────────────────────────────
	// cfm.deny is applied LAST, once every edge-critical subsystem (sslcollector,
	// apiserver, ingest socket, nginx bridge, challenge) and the DNAT failsafe /
	// edge nudge above are already up. On a busy host with a large block list this
	// per-IP nft apply is the single most expensive startup step, and nothing
	// above depends on the block sets being populated: EnsureBase already
	// installed the enforcement chains, and block_v4/v6 simply fill in here.
	//
	// Trade-off, by design: on a normal service restart the kernel nft sets
	// persist, so there is NO enforcement gap. On a COLD boot / reboot / after
	// `cfm reset` the sets start empty, so for the duration of this apply
	// (seconds, up to tens of seconds on a large list — until the batching
	// follow-up lands) cfm.deny is not yet enforced at L3 while the services are
	// already up. cfm.deny is a blanket all-ports `@block_v4 drop`, so this gap
	// is NOT edge-only — a denied IP can also reach sshd/exim/dovecot/etc., which
	// have no WAF/challenge in front. What IS already up by this point: the
	// general firewall (ports policy, flood/connlimit/hardening applied by
	// applyNFTRules above), plus the detectors, which re-block any source that
	// actively re-offends in the window. That reactive net does NOT cover the
	// quiet part of cfm.deny (manually-curated bans, slow-and-low sources that
	// won't trip a detector in time) — those stay unenforced until this apply
	// lands, which happens within the window above. This is the accepted cost of
	// not holding the edge (and the rest of startup) hostage to the block list.
	// (Idempotent per-IP apply, so re-running on a restart where the sets are
	// already populated is safe.)
	done = step("initial:loadAll(deny)")
	loadAll(false, true, false)
	done()

	// ── Main tick loop ───────────────────────────────────────────────────────────
	t := time.NewTicker(*interval)
	defer t.Stop()
	for range t.C {
		reloadBlocklists()        // only if cfm.blocklists changed
		loadAll(true, true, true) // only if cfm.allow / cfm.deny / cfm.ignore changed
		onCFMConfChanged()        // only if cfm.conf changed

		// cfm-lsm activation is gated by /etc/cfm/lsm.conf, which is
		// independent of cfm.conf — so the cfm.conf-only path above
		// would miss a fresh `enabled = true` until cfm.conf itself
		// gets touched. ApplyConfig is start-once internally (cheap
		// no-op when the lifecycle is already activated), so calling
		// it every tick is safe.
		lsmLc.ApplyConfig(ctx)

		// Drive the sslcollector socket's autonomous respawn every tick. Unlike
		// the subsystems above, sslSockLc.ApplyConfig runs only on a cfm.conf
		// change (onCFMConfChanged), so a socket server that exited unexpectedly
		// — a mid-life Serve error or a transient boot-time bind failure — would
		// otherwise never self-heal until an operator touched cfm.conf. Tick is a
		// cheap no-op when the socket is healthy/disabled and does no token I/O
		// (that stays in ApplyConfig); it only restarts a dead server (F28).
		sslSockLc.Tick(ctx)

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
