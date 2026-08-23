package dnat

import (
	"cfm/internal/firewall"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type unixSockProbe struct {
	Exists          bool
	IsSocket        bool
	WritableByGroup bool
	Connectable     bool
	Err             string
}

var panelDecisionBackendLastErr string
var panelDecisionBackendLastErrAt time.Time

func probeUnixSocket(path string) unixSockProbe {
	out := unixSockProbe{}
	st, err := os.Stat(path)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	out.Exists = true
	out.IsSocket = st.Mode()&os.ModeSocket != 0
	out.WritableByGroup = st.Mode().Perm()&0o020 != 0
	if !out.IsSocket {
		out.Err = "not a unix socket"
		return out
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		out.Err = err.Error()
		panelDecisionBackendLastErr = fmt.Sprintf("socket=%s error=%s", path, out.Err)
		panelDecisionBackendLastErrAt = time.Now().UTC()
		return out
	}
	out.Connectable = true
	_ = conn.Close()
	return out
}

type fileProbe struct {
	Path             string
	Exists           bool
	ReadableByRoot   bool
	ReadableByWorker string
	WorkerErr        string
}

type socketProbeDetailed struct {
	Path                string
	Exists              bool
	IsSocket            bool
	GroupWritable       bool
	ConnectableByRoot   bool
	ConnectableByWorker string
	WorkerErr           string
	Err                 string
}

func isRoot() bool { return os.Geteuid() == 0 }

func detectWorkerUser() string {
	for _, env := range []string{"OPENRESTY_USER", "NGINX_WORKER_USER", "WORKER_USER"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	for _, p := range []string{"/etc/nginx/nginx.conf", "/usr/local/openresty/nginx/conf/nginx.conf", "/etc/angie/angie.conf"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "user ") {
				fields := strings.Fields(strings.TrimSuffix(line, ";"))
				if len(fields) >= 2 {
					return fields[1]
				}
			}
		}
	}
	return "cfm"
}

func runAsUser(userName string, cmd ...string) (bool, string) {
	if len(cmd) == 0 {
		return false, "empty cmd"
	}
	if !isRoot() {
		return false, "not tested as worker user (need root)"
	}
	args := append([]string{"-u", userName, "--"}, cmd...)
	out, err := exec.Command("runuser", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	return true, ""
}

func probeReadable(path, worker string) fileProbe {
	fp := fileProbe{Path: path, ReadableByWorker: "not tested"}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		fp.Exists = true
	} else {
		return fp
	}
	if f, err := os.Open(path); err == nil {
		fp.ReadableByRoot = true
		_ = f.Close()
	}
	ok, err := runAsUser(worker, "test", "-r", path)
	if strings.HasPrefix(err, "not tested") {
		fp.ReadableByWorker = err
		return fp
	}
	if ok {
		fp.ReadableByWorker = "true"
	} else {
		fp.ReadableByWorker = "false"
		fp.WorkerErr = err
	}
	return fp
}

func probeSocketDetailed(path, worker string) socketProbeDetailed {
	sp := socketProbeDetailed{Path: path, ConnectableByWorker: "not tested"}
	st, err := os.Stat(path)
	if err != nil {
		sp.Err = err.Error()
		return sp
	}
	sp.Exists = true
	sp.IsSocket = st.Mode()&os.ModeSocket != 0
	sp.GroupWritable = st.Mode().Perm()&0o020 != 0
	if !sp.IsSocket {
		sp.Err = "not a unix socket"
		return sp
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		sp.ConnectableByRoot = true
		_ = conn.Close()
	} else {
		sp.Err = err.Error()
	}
	ok, werr := runAsUser(worker, "sh", "-lc", "exec 3<>"+path)
	if strings.HasPrefix(werr, "not tested") {
		sp.ConnectableByWorker = werr
		return sp
	}
	if ok {
		sp.ConnectableByWorker = "true"
	} else {
		sp.ConnectableByWorker = "false"
		sp.WorkerErr = werr
	}
	return sp
}
func workerInCFMGroup() bool {
	u, err := user.Lookup("cfm")
	if err != nil {
		return false
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, gid := range ids {
		g, err := user.LookupGroupId(gid)
		if err == nil && g.Name == "cfm" {
			return true
		}
	}
	return false
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

type webDNATProbeError struct {
	addr string
	err  error
}

func (e webDNATProbeError) Error() string {
	return e.err.Error()
}

func newWebDNATFailSafeTarget(backend firewall.Backend) (dnatFailSafeTarget, bool) {
	if backend == nil {
		return dnatFailSafeTarget{}, false
	}

	// keep these aligned with RunCLI defaults
	family := "inet"
	table := "cfm_redirect"

	interval := time.Duration(getenvInt("CFM_DNAT_FAILSAFE_INTERVAL_MS", 2000)) * time.Millisecond
	failNeed := getenvInt("CFM_DNAT_FAILSAFE_CONSECUTIVE_FAILS", 3)
	recoverOK := getenvInt("CFM_DNAT_FAILSAFE_RECOVER_OK", 5)

	probe := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ok, reason := probeEdgeHealthy(ctx, ScopeWeb, WebEdgePorts())
		if ok {
			return nil
		}
		return webDNATProbeError{addr: reason, err: errProbeFailed}
	}

	return dnatFailSafeTarget{
		Name:             "web",
		LogPrefix:        "[dnat:failsafe]",
		Interval:         interval,
		FailureThreshold: failNeed,
		StatusCheck: func() (bool, error) {
			return backend.DNATStatus(family, table)
		},
		HealthProbe: probe,
		Cleanup: func(_ int, probeErr error) {
			_ = backend.DNATOff(family, table)
			reason := ""
			if webErr, ok := probeErr.(webDNATProbeError); ok && webErr.addr != "" {
				reason = webErr.addr
			} else if probeErr != nil {
				reason = probeErr.Error()
			}
			LogTransition(ScopeWeb, "OFF", "failsafe-off", reason)
		},
		IntentCheck: func() bool {
			enabled, present := LoadIntent(ScopeWeb)
			return present && enabled
		},
		RecoverThreshold: recoverOK,
		Recover: func(_ int) {
			// Re-read ports so a runtime env change is honored on recover
			// instead of pinning to whatever was active at daemon start.
			hp := getenvInt("HTTP_PORT", 9080)
			hsp := getenvInt("HTTPS_PORT", 9043)
			if err := backend.DNATOn(family, table, hp, hsp); err != nil {
				LogTransition(ScopeWeb, "OFF", "failsafe-recover", fmt.Sprintf("enable failed: %v", err))
				return
			}
			LogTransition(ScopeWeb, "ON", "failsafe-recover", "")
		},
	}, true
}

var errProbeFailed = fmt.Errorf("probe failed")

func boolOnOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

// StartFailSafe runs a simple DNAT watchdog:
//   - If DNAT is ON and edge proxy ports are not listening for N consecutive checks,
//     it disables DNAT (fail-open) and logs the reason.
//   - DNAT stays OFF until manually re-enabled.
//
// No config needed: it watches the same ports used by DNAT (defaults: 9080/9043).
func StartFailSafe(ctx context.Context, backend firewall.Backend) {
	target, ok := newWebDNATFailSafeTarget(backend)
	if !ok {
		return
	}
	startDNATFailSafe(ctx, target)
}

// RunCLI implements:
//
//	cfm dnat        -> report (ON/OFF + rules if ON + explanation)
//	cfm dnat on     -> enable
//	cfm dnat off    -> disable
//
// Returns an exit code (0 ok, 1 error, 2 usage).
func RunCLI(args []string, backend firewall.Backend) int {
	if backend == nil {
		fmt.Fprintln(os.Stderr, "dnat: backend does not support DNAT")
		return 1
	}

	fs := flag.NewFlagSet("dnat", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	family := fs.String("family", "inet", "nftables family (default: inet)")
	table := fs.String("table", "cfm_redirect", "nftables table (default: cfm_redirect)")

	defHTTP := getenvInt("HTTP_PORT", 9080)
	defHTTPS := getenvInt("HTTPS_PORT", 9043)
	httpPort := fs.Int("http-port", defHTTP, "DNAT target port for tcp/80 (env HTTP_PORT)")
	httpsPort := fs.Int("https-port", defHTTPS, "DNAT target port for tcp+udp/443 (env HTTPS_PORT)")
	defPrio := getenvInt("NFT_DNAT_PRIORITY", NFTDNATPriority)
	priority := fs.Int("priority", defPrio, "DNAT prerouting priority (default: -99)")

	sub := "" // default = report
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		help()
		return 2
	}

	if sub == "cpanel" {
		return runPanelCLI(fs.Args(), backend)
	}
	if sub == "bypass" {
		return runBypassCLI(fs.Args(), firewall.DNATBypassScopeWeb, backend)
	}
	if sub == "help" || sub == "-h" || sub == "--help" {
		help()
		return 0
	}
	switch sub {
	case "on":
		if err := os.Setenv("NFT_DNAT_PRIORITY", strconv.Itoa(*priority)); err != nil {
			fmt.Fprintln(os.Stderr, "dnat on failed:", err)
			return 1
		}
		if err := backend.DNATOn(*family, *table, *httpPort, *httpsPort); err != nil {
			fmt.Fprintln(os.Stderr, "dnat on failed:", err)
			return 1
		}
		if err := PersistIntent(ScopeWeb, true); err != nil {
			fmt.Fprintln(os.Stderr, "dnat on: warning: persist intent:", err)
		}
		LogTransition(ScopeWeb, "ON", "manual", "")
		fmt.Printf("DNAT: ON  (priority %d, tcp/80->:%d, tcp+udp/443->:%d)\n", *priority, *httpPort, *httpsPort)
		// DNATOn installs the scoped `ct status dnat` accepts internally; report
		// them the way `cfm dnat cpanel on` reports its scoped accepts so the
		// operator can confirm the listener ports were opened without needing
		// them in TCP_IN (and gets a loud warning if they were not).
		printWebDNATAcceptsOnEnable(backend, *httpPort, *httpsPort)
		return 0

	case "off":
		if err := backend.DNATOff(*family, *table); err != nil {
			fmt.Fprintln(os.Stderr, "dnat off failed:", err)
			return 1
		}
		if err := PersistIntent(ScopeWeb, false); err != nil {
			fmt.Fprintln(os.Stderr, "dnat off: warning: persist intent:", err)
		}
		LogTransition(ScopeWeb, "OFF", "manual", "")
		fmt.Println("DNAT: OFF")
		return 0

	case "":
		// report
	default:
		fmt.Fprintln(os.Stderr, "dnat: unknown subcommand:", sub)
		help()
		return 2
	}

	enabled, err := backend.DNATStatus(*family, *table)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnat status failed:", err)
		return 1
	}

	fmt.Printf("DNAT table: %s %s\n", *family, *table)
	edgeTarget := dnatTargetLabel(detectEdgeService())
	if enabled {
		fmt.Printf("State: ON  (priority %d, tcp/80->:%d, tcp+udp/443->:%d)\n\n", getenvInt("NFT_DNAT_PRIORITY", NFTDNATPriority), *httpPort, *httpsPort)
		fmt.Println("Current rules:")
		s, err := backend.DNATShow(*family, *table)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dnat show failed:", err)
			return 1
		}
		fmt.Print(s)
		if !strings.HasSuffix(s, "\n") {
			fmt.Println()
		}
		// Scoped input-chain accepts that make the DNAT redirect actually
		// reachable. `cfm dnat on` opens the listener ports here (not in
		// TCP_IN); surfacing their state lets an operator tell a missing CFM
		// rule apart from an upstream drop when the site is unreachable.
		// Resolve against the ports ACTUALLY installed in the redirect table
		// (`s`), not the CLI/env defaults — otherwise a box running DNAT on
		// custom listener ports would see false ABSENT warnings.
		accHTTP, accHTTPS := *httpPort, *httpsPort
		if h, hs, ok := firewall.ParseDNATListenerPorts(s); ok {
			accHTTP, accHTTPS = h, hs
		}
		if states, ok := webDNATAcceptStates(backend, accHTTP, accHTTPS); ok {
			fmt.Println()
			fmt.Println("Scoped DNAT accepts (inet cfm/input) — open the listener ports WITHOUT needing them in TCP_IN:")
			for _, st := range states {
				fmt.Printf("  %s: %s\n", st.mapping(), webDNATAcceptStateLabel(st.State))
			}
		}
	} else {
		fmt.Println("State: OFF")
	}

	if intentEnabled, present := LoadIntent(ScopeWeb); present {
		fmt.Printf("Persisted intent: %s (file=%s)\n", boolOnOff(intentEnabled), IntentPath(ScopeWeb))
	} else {
		fmt.Printf("Persisted intent: <none> (file=%s)\n", IntentPath(ScopeWeb))
	}
	// Transition + probe live in the daemon's process memory; fetch
	// them over the apiserver. When the daemon or apiserver is down
	// daemonSnapshot returns the zero value and these lines are
	// suppressed (same as before).
	snap := daemonSnapshot(ScopeWeb)
	if pr := snap.LastProbe; !pr.At.IsZero() {
		if pr.OK {
			fmt.Printf("Last health probe: ok at %s\n", pr.At.Format(time.RFC3339))
		} else {
			fmt.Printf("Last health probe: fail at %s reason=%q\n", pr.At.Format(time.RFC3339), pr.Reason)
		}
	}
	if lt := snap.LastTransition; !lt.At.IsZero() {
		if lt.Reason == "" {
			fmt.Printf("Last transition: %s state=%s action=%s\n", lt.At.Format(time.RFC3339), lt.State, lt.Action)
		} else {
			fmt.Printf("Last transition: %s state=%s action=%s reason=%q\n", lt.At.Format(time.RFC3339), lt.State, lt.Action, lt.Reason)
		}
	}

	fmt.Println()
	fmt.Println("Explanation:")
	fmt.Printf("  - ON  : creates a NAT prerouting table that DNATs tcp/80 and tcp+udp/443 to %s.\n", edgeTarget)
	fmt.Println("  - OFF : deletes that DNAT table, returning traffic handling to the normal path.")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  cfm dnat on   [--http-port 9080] [--https-port 9043] [--priority -99]")
	fmt.Println("  priority -99:")
	fmt.Println("    Imunify/WebShield-first fallback mode. Imunify at -100 can DNAT matched traffic first; CFM catches the rest.")
	fmt.Println("  priority -101:")
	fmt.Println("    CFM-first mode. CFM catches web traffic before Imunify/WebShield.")
	fmt.Println("  cfm dnat off")

	worker := detectWorkerUser()
	bridgeSock := probeSocketDetailed("/var/run/cfm/cfm_nginx.sock", worker)
	ingestSock := probeSocketDetailed("/run/cfm/ingest.sock", worker)
	sslCollectorSock := probeSocketDetailed("/var/run/sslcollector.sock", worker)
	bridgeToken := probeReadable("/var/lib/cfm/lua/cfm_bridge_token.lua", worker)
	clearanceLua := probeReadable("/var/lib/cfm/lua/cfm_clearance.lua", worker)
	panelOn, _, _ := panelStatusWithBackend(backend)
	fmt.Printf("cPanel DNAT enabled: %t\n", panelOn)
	fmt.Printf("Worker user detected: %s\n", worker)
	fmt.Printf("Bridge token file: exists=%t root_readable=%t worker_readable=%s\n", bridgeToken.Exists, bridgeToken.ReadableByRoot, bridgeToken.ReadableByWorker)
	if bridgeToken.WorkerErr != "" {
		fmt.Printf("Bridge token worker read error: %s\n", bridgeToken.WorkerErr)
	}
	fmt.Printf("Clearance Lua file: exists=%t root_readable=%t worker_readable=%s\n", clearanceLua.Exists, clearanceLua.ReadableByRoot, clearanceLua.ReadableByWorker)
	if clearanceLua.WorkerErr != "" {
		fmt.Printf("Clearance Lua worker read error: %s\n", clearanceLua.WorkerErr)
	}
	fmt.Printf("Bridge socket (/var/run/cfm/cfm_nginx.sock): exists=%t socket=%t root_connectable=%t worker_connectable=%s group_write=%t\n", bridgeSock.Exists, bridgeSock.IsSocket, bridgeSock.ConnectableByRoot, bridgeSock.ConnectableByWorker, bridgeSock.GroupWritable)
	if bridgeSock.Err != "" {
		fmt.Printf("Bridge socket status: FAIL (%s)\n", bridgeSock.Err)
	}
	if bridgeSock.Err != "" {
		fmt.Printf("Decision backend: DEGRADED (last error: socket=/var/run/cfm/cfm_nginx.sock error=%s at %s)\n", bridgeSock.Err, time.Now().UTC().Format(time.RFC3339))
	} else if panelDecisionBackendLastErr != "" {
		fmt.Printf("Decision backend: DEGRADED (last error: %s at %s)\n", panelDecisionBackendLastErr, panelDecisionBackendLastErrAt.Format(time.RFC3339))
	} else {
		fmt.Println("Decision backend: OK")
	}
	fmt.Printf("Ingest socket (/run/cfm/ingest.sock): exists=%t socket=%t connectable=%t group_write=%t\n", ingestSock.Exists, ingestSock.IsSocket, ingestSock.ConnectableByRoot, ingestSock.GroupWritable)
	if ingestSock.Err != "" {
		fmt.Printf("Ingest socket status: FAIL (%s)\n", ingestSock.Err)
	}
	fmt.Printf("SSL collector socket (/var/run/sslcollector.sock): exists=%t socket=%t connectable=%t group_write=%t\n", sslCollectorSock.Exists, sslCollectorSock.IsSocket, sslCollectorSock.ConnectableByRoot, sslCollectorSock.GroupWritable)
	if sslCollectorSock.Err != "" {
		fmt.Printf("SSL collector socket status: FAIL (%s)\n", sslCollectorSock.Err)
	}
	fmt.Printf("Worker user in cfm group: %t\n", workerInCFMGroup())
	return 0
}

func dnatTargetLabel(edgeService string) string {
	label := "CFM edge proxy ports"
	if edgeService == "" {
		return label
	}
	return fmt.Sprintf("%s (%s)", label, edgeService)
}

func detectEdgeService() string {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}

	for _, ent := range procEntries {
		if !ent.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(ent.Name()); err != nil {
			continue
		}

		pidPath := filepath.Join("/proc", ent.Name())
		if service := normalizeEdgeService(readProcValue(filepath.Join(pidPath, "comm"))); service != "" {
			return service
		}
		if service := normalizeEdgeService(readProcValue(filepath.Join(pidPath, "cmdline"))); service != "" {
			return service
		}
	}

	return ""
}

func readProcValue(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " ")))
}

func normalizeEdgeService(s string) string {
	if s == "" {
		return ""
	}
	if strings.Contains(s, "openresty") || strings.Contains(s, "/openresty/") {
		return "openresty"
	}
	if strings.Contains(s, "angie") {
		return "angie"
	}
	if strings.Contains(s, "nginx") {
		return "nginx"
	}
	return ""
}

func help() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  cfm dnat                  (show ON/OFF + rules + explanation)")
	fmt.Fprintln(os.Stderr, "  cfm dnat on               (enable web DNAT: 80/443 -> openresty)")
	fmt.Fprintln(os.Stderr, "  cfm dnat off              (disable web DNAT)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel ...       (manage the cPanel panel DNAT chain; see `cfm dnat cpanel help`)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  cfm dnat bypass list             (show source IPs exempted from web DNAT)")
	fmt.Fprintln(os.Stderr, "  cfm dnat bypass add    <IP|CIDR> (exempt this source from web DNAT)")
	fmt.Fprintln(os.Stderr, "  cfm dnat bypass remove <IP|CIDR> (re-subject this source to web DNAT)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Bypass list file: /etc/cfm/cfm.dnat_bypass")
	fmt.Fprintln(os.Stderr, "Bypass changes take effect immediately if DNAT is on; otherwise on next `cfm dnat on`.")
}

func runPanelCLI(args []string, backend firewall.Backend) int {
	if len(args) > 0 && args[0] == "help" {
		panelHelp()
		return 0
	}
	if len(args) >= 2 && args[0] == "challenge" {
		fmt.Fprintln(os.Stderr, "DEPRECATION: `cfm dnat cpanel challenge on|off` is deprecated and will be removed in a future release; use `cfm dnat cpanel on` or `cfm dnat cpanel off`.")
		switch args[1] {
		case "on":
			args = append([]string{"on"}, args[2:]...)
		case "off":
			args = append([]string{"off"}, args[2:]...)
		default:
			fmt.Fprintf(os.Stderr, "dnat cpanel: unknown deprecated challenge shortcut %q (use: cfm dnat cpanel on|off|status)\n", args[1])
			panelHelp()
			return 2
		}
	}
	// `cfm dnat cpanel bypass …` is a peer subcommand to on/off/status; it
	// edits /etc/cfm/cfm.dnat_cpanel_bypass and (when cpanel DNAT is on)
	// re-renders the panel DNAT table. Handled before the on/off arg
	// normalisation since the bypass mini-CLI has its own positional layout.
	if len(args) > 0 && args[0] == "bypass" {
		return runBypassCLI(args[1:], firewall.DNATBypassScopeCpanel, backend)
	}
	args, err := normalizePanelArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		panelHelp()
		return 2
	}
	fs := flag.NewFlagSet("dnat cpanel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.String("mode", "auto", "mode")
	priority := fs.Int("priority", -101, "priority")
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	if sub == "on" {
		for _, a := range args {
			if a == "--help" || a == "-h" {
				panelOnHelp()
				return 0
			}
		}
	}
	if err := fs.Parse(args); err != nil {
		panelHelp()
		return 2
	}
	selected := *mode
	if selected == "auto" {
		if len(detectedImunifyMappings()) > 0 {
			selected = "chain-imunify"
		} else {
			selected = "direct-cpsrvd"
		}
	}
	if selected == "fallback" && *priority == -101 {
		*priority = -99
	}
	switch sub {
	case "on":
		// Intent is persisted only AFTER the full pipeline (listener
		// reload, nft DNAT, allowlist accepts) succeeds. Writing it up
		// front meant a mid-pipeline failure or the rollback branch left
		// intent=ON on disk; RestoreOnStartup would then silently
		// re-install DNAT on the next daemon restart, undoing the
		// rollback. Any failure path below returns without touching the
		// intent file, so the on-disk state is consistent with what was
		// actually applied.
		if err := applyPanelChallengeModeToPaths("forced", panelListenerChallengeConfigPaths); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on failed:", err)
			return 1
		}
		if err := reloadPanelListenerService(); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on failed:", err)
			return 1
		}
		setPanelFirewallHealth("OK", "", true)
		if err := panelOnWithBackend(backend, *priority); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on failed:", err)
			return 1
		}
		fmt.Println("Phase 1/2 (DNAT): OK")
		changes, err := ensurePanelAllowlistWithBackend(backend)
		if err != nil {
			setPanelFirewallHealth("FAILED", err.Error(), true)
			_ = backend.PanelDNATOff()
			setPanelFirewallHealth("PARTIAL", err.Error()+"; remediation: cfm dnat cpanel on", true)
			fmt.Fprintln(os.Stderr, "dnat cpanel on firewall failed:", err)
			return 1
		}
		setPanelFirewallHealth("OK", "", true)
		if err := persistPanelChallengeEnabled(true); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on: warning: persist intent:", err)
		}
		// Persist the operator-chosen priority so failsafe-recover and
		// RestoreOnStartup re-apply this exact value instead of falling
		// back to the -101 default.
		if err := PersistPanelPriority(*priority); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on: warning: persist priority:", err)
		}
		LogTransition(ScopeCPanel, "ON", "manual", fmt.Sprintf("mode=%s priority=%d", selected, *priority))
		fmt.Printf("DNAT cpanel: ON (mode=%s priority=%d)\n", selected, *priority)
		fmt.Println("Phase 2/2 (firewall): OK")
		if len(changes) == 0 {
			fmt.Println("Firewall: no changes")
		} else {
			for _, ch := range changes {
				fmt.Println("Firewall:", ch)
			}
		}
		return 0
	case "off":
		res, err := panelOffWithBackend(backend)
		changes := res.FirewallChanges
		if err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel off firewall failed:", err)
			return 1
		}
		LogTransition(ScopeCPanel, "OFF", "manual", "")
		fmt.Println("DNAT cpanel: OFF")
		for _, ch := range changes {
			fmt.Println("Firewall:", ch)
		}
		return 0
	case "status":
		on, rules, _ := panelStatusWithBackend(backend)
		fmt.Println("DNAT table: inet cfm_panel_redirect")
		if on {
			fmt.Printf("State: ON\nSelected priority: %d\nSelected mode: %s\n", *priority, selected)
		} else {
			fmt.Println("State: OFF")
		}
		panelMode, luaLoaded, modePath := panelListenerGuardStateFromPaths(orderedPanelListenerConfigPaths())
		if panelMode == "unknown" {
			if persisted := loadPersistedPanelChallengeMode(); persisted != "" {
				panelMode = persisted
			} else {
				panelMode = defaultPanelChallengeMode
			}
		}
		panelLuaPath := panelLuaGuardPath()
		panelLua := checkPanelLuaGuard(panelLuaPath)
		panelDecision := probePanelDecisionEndpoint(orderedPanelListenerConfigPaths())
		onProfile := buildPanelChallengeStatus(panelChallengeEnabledMode, panelMode, luaLoaded)
		offProfile := buildPanelChallengeStatus(panelChallengeDisabledMode, panelChallengeDisabledMode, luaLoaded)
		_ = offProfile // status always resolves both ON and OFF policy profiles.
		policyActive := on && onProfile.Enforced
		fmt.Printf("DNAT cpanel state: %s\n", map[bool]string{true: "ON", false: "OFF"}[on])
		fmt.Printf("Policy: %s\n", map[bool]string{true: "active", false: "inactive"}[policyActive])
		if modePath != "" {
			fmt.Printf("Policy active file: %s\n", modePath)
		}
		if onProfile.MismatchCause != "" && on {
			fmt.Printf("WARNING: policy runtime/config mismatch (%s)\n", onProfile.MismatchCause)
		}
		fmt.Printf("Panel Lua guard loaded: %t\n", luaLoaded)
		fmt.Printf("Panel Lua guard path: %s\n", panelLua.Path)
		fmt.Printf("Panel Lua exists: %t\n", panelLua.Exists)
		fmt.Printf("Panel Lua readable: %t\n", panelLua.Readable)
		if panelLua.Path != "" {
			workerReadable, workerErr := panelLuaReadableByWorker(panelLua.Path)
			fmt.Printf("Panel Lua readable by worker(cfm): %t\n", workerReadable)
			if workerErr != "" {
				fmt.Printf("Panel Lua worker read check error: %s\n", workerErr)
			}
		}
		fmt.Printf("Panel Lua load check: %s\n", panelLua.LoadState)
		if panelLua.LoadError != "" && !(panelDecision.Status == "OK" && strings.Contains(panelLua.LoadError, "cfm_panel_selftest hook is missing")) {
			fmt.Printf("Panel Lua load check error: %s\n", panelLua.LoadError)
		}
		fmt.Printf("Panel decision endpoint: %s\n", panelDecision.Status)
		if panelDecision.Path != "" {
			fmt.Printf("Panel decision endpoint file: %s\n", panelDecision.Path)
		}
		if panelDecision.Detail != "" {
			fmt.Printf("Panel decision endpoint detail: %s\n", panelDecision.Detail)
		}
		if onProfile.EffectiveMode == panelChallengeEnabledMode && panelDecision.Status == "MISSING" {
			fmt.Println("WARNING: policy is active, but /__cfm_panel_decide is missing; panel challenge cannot work until listener config is corrected and reloaded.")
		}
		fw := panelFirewallStateWithBackend(backend)
		h := getPanelFirewallHealth()
		fsState := getPanelFailSafeState()
		fmt.Printf("Firewall state: %s\n", h.State)
		fmt.Printf("Panel failsafe enabled: %t\n", fsState.Enabled)
		fmt.Printf("Panel failsafe consecutive failures: %d\n", fsState.ConsecutiveFails)
		if !fsState.LastActionAt.IsZero() {
			fmt.Printf("Panel failsafe last action: %s\n", fsState.LastActionAt.Format(time.RFC3339))
		}
		if fsState.LastActionReason != "" {
			fmt.Printf("Panel failsafe last reason: %s\n", fsState.LastActionReason)
		}
		if h.LastReason != "" {
			fmt.Printf("Firewall last failure: %s\n", h.LastReason)
		}
		if intentEnabled, present := LoadIntent(ScopeCPanel); present {
			fmt.Printf("Persisted intent: %s (file=%s)\n", boolOnOff(intentEnabled), IntentPath(ScopeCPanel))
		} else {
			fmt.Printf("Persisted intent: <none> (file=%s)\n", IntentPath(ScopeCPanel))
		}
		// Transition + probe live in the daemon's process memory;
		// fetch them over the apiserver. Zero value when the daemon
		// or apiserver is unreachable, in which case both lines are
		// suppressed by the guards below.
		snap := daemonSnapshot(ScopeCPanel)
		if pr := snap.LastProbe; !pr.At.IsZero() {
			if pr.OK {
				fmt.Printf("Last health probe: ok at %s\n", pr.At.Format(time.RFC3339))
			} else {
				fmt.Printf("Last health probe: fail at %s reason=%q\n", pr.At.Format(time.RFC3339), pr.Reason)
			}
		}
		if lt := snap.LastTransition; !lt.At.IsZero() {
			if lt.Reason == "" {
				fmt.Printf("Last transition: %s state=%s action=%s\n", lt.At.Format(time.RFC3339), lt.State, lt.Action)
			} else {
				fmt.Printf("Last transition: %s state=%s action=%s reason=%q\n", lt.At.Format(time.RFC3339), lt.State, lt.Action, lt.Reason)
			}
		}
		fmt.Printf("Detected Imunify mappings: %s\n", strings.Join(detectedImunifyMappings(), ", "))
		fmt.Println("Active panel mappings: 2082->12082, 2083->12083, 2086->12086, 2087->12087, 2095->12095, 2096->12096, 2222->12222")
		if on {
			fmt.Println("Generated nft rules:")
			fmt.Print(rules)
		}
		for _, tp := range panelTargetPorts {
			fmt.Printf("Port %d listener=%s firewall=%s\n", tp, panelListenerState(tp), fw[tp])
		}
		if selected == "fallback" && len(detectedImunifyMappings()) > 0 {
			fmt.Println("WARNING: fallback mode is not a complete panel exploit guard when Imunify already redirects panel ports.")
		}
		bridgeSock := probeUnixSocket("/var/run/cfm/cfm_nginx.sock")
		ingestSock := probeUnixSocket("/run/cfm/ingest.sock")
		fmt.Printf("Bridge socket (/var/run/cfm/cfm_nginx.sock): exists=%t socket=%t connectable=%t group_write=%t\n", bridgeSock.Exists, bridgeSock.IsSocket, bridgeSock.Connectable, bridgeSock.WritableByGroup)
		if bridgeSock.Err != "" {
			fmt.Printf("Bridge socket status: FAIL (%s)\n", bridgeSock.Err)
		}
		if bridgeSock.Err != "" {
			fmt.Printf("Decision backend: DEGRADED (last error: socket=/var/run/cfm/cfm_nginx.sock error=%s at %s)\n", bridgeSock.Err, time.Now().UTC().Format(time.RFC3339))
		} else if panelDecisionBackendLastErr != "" {
			fmt.Printf("Decision backend: DEGRADED (last error: %s at %s)\n", panelDecisionBackendLastErr, panelDecisionBackendLastErrAt.Format(time.RFC3339))
		} else {
			fmt.Println("Decision backend: OK")
		}
		fmt.Printf("Ingest socket (/run/cfm/ingest.sock): exists=%t socket=%t connectable=%t group_write=%t\n", ingestSock.Exists, ingestSock.IsSocket, ingestSock.Connectable, ingestSock.WritableByGroup)
		if ingestSock.Err != "" {
			fmt.Printf("Ingest socket status: FAIL (%s)\n", ingestSock.Err)
		}
		sslCollectorSock := probeUnixSocket("/var/run/sslcollector.sock")
		fmt.Printf("SSL collector socket (/var/run/sslcollector.sock): exists=%t socket=%t connectable=%t group_write=%t\n", sslCollectorSock.Exists, sslCollectorSock.IsSocket, sslCollectorSock.Connectable, sslCollectorSock.WritableByGroup)
		if sslCollectorSock.Err != "" {
			fmt.Printf("SSL collector socket status: FAIL (%s)\n", sslCollectorSock.Err)
		}
		fmt.Printf("Worker user in cfm group: %t\n", workerInCFMGroup())
		return 0
	default:
		panelHelp()
		return 2
	}
}

func normalizePanelArgs(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "mode=") {
			out = append(out, "--mode", strings.TrimPrefix(a, "mode="))
			continue
		}
		if strings.HasPrefix(a, "priority=") {
			out = append(out, "--priority", strings.TrimPrefix(a, "priority="))
			continue
		}
		if strings.HasPrefix(a, "challenge=") {
			fmt.Fprintln(os.Stderr, "DEPRECATION: `challenge=` is deprecated and ignored; `cfm dnat cpanel on` now always enables challenge mode.")
			continue
		}
		if strings.HasPrefix(a, "--challenge") {
			fmt.Fprintln(os.Stderr, "DEPRECATION: `--challenge` is deprecated and ignored; `cfm dnat cpanel on` now always enables challenge mode.")
			continue
		}
		if strings.Contains(a, "=") && !strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("dnat cpanel: unsupported key=value argument %q; use mode=, priority=, or --flags", a)
		}
		out = append(out, a)
	}
	return out, nil
}

func panelHelp() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel status [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99]")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel on     [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99]")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel off")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel bypass list             (show source IPs exempted from cPanel panel DNAT)")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel bypass add    <IP|CIDR> (exempt this source from cPanel panel DNAT)")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel bypass remove <IP|CIDR> (re-subject this source to cPanel panel DNAT)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands: status, on, off, bypass")
	fmt.Fprintln(os.Stderr, "Modes: auto, chain-imunify, direct-cpsrvd, fallback")
	fmt.Fprintln(os.Stderr, "Priority guidance: -101 (CFM-first), -99 (Imunify-first)")
	fmt.Fprintln(os.Stderr, "Challenge behavior: cfm dnat cpanel on always enables forced challenge mode.")
	fmt.Fprintln(os.Stderr, "Bypass list file: /etc/cfm/cfm.dnat_cpanel_bypass")
	fmt.Fprintln(os.Stderr, "Bypass use case: cluster nodes and cPanel-to-cPanel WHM Transfer Tool source hosts whose")
	fmt.Fprintln(os.Stderr, "  rsync stream (whm_xfer_download-ssl) needs direct cpsrvd access without panel filtering.")
	fmt.Fprintln(os.Stderr, "Migration: deprecated `cfm dnat cpanel challenge on|off` and `--challenge` are accepted for one release cycle with warnings.")
	fmt.Fprintln(os.Stderr, "Argument formats: --mode direct-cpsrvd or mode=direct-cpsrvd (same for priority)")
}

func panelOnHelp() {
	fmt.Fprintln(os.Stdout, "Usage: cfm dnat cpanel on [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99]")
	fmt.Fprintln(os.Stdout, "Modes: auto, chain-imunify, direct-cpsrvd, fallback")
	fmt.Fprintln(os.Stdout, "Priority guidance: -101 (CFM-first), -99 (Imunify-first)")
	fmt.Fprintln(os.Stdout, "Challenge behavior: ON always applies forced challenge mode.")
	fmt.Fprintln(os.Stdout, "Examples: --mode direct-cpsrvd, mode=direct-cpsrvd, --priority -101, priority=-101")
}
