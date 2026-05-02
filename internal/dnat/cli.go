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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cfm/internal/logging"
)

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

// StartFailSafe runs a simple DNAT watchdog:
//   - If DNAT is ON and edge proxy ports are not listening for N consecutive checks,
//     it disables DNAT (fail-open) and logs the reason.
//   - DNAT stays OFF until manually re-enabled.
//
// No config needed: it watches the same ports used by DNAT (defaults: 9080/9043).
func StartFailSafe(ctx context.Context, backend firewall.Backend) {
	if backend == nil {
		return
	}

	// keep these aligned with RunCLI defaults
	family := "inet"
	table := "cfm_redirect"
	httpPort := getenvInt("HTTP_PORT", 9080)
	httpsPort := getenvInt("HTTPS_PORT", 9043)

	// simple, stable defaults
	every := 2 * time.Second
	failNeed := 3
	dialTimeout := 300 * time.Millisecond

	addrHTTP := fmt.Sprintf("127.0.0.1:%d", httpPort)
	addrHTTPS := fmt.Sprintf("127.0.0.1:%d", httpsPort)

	t := time.NewTicker(every)
	go func() {
		defer t.Stop()

		failCount := 0
		var lastErr error
		var lastWhich string

		check := func(addr string) error {
			c, err := net.DialTimeout("tcp", addr, dialTimeout)
			if err != nil {
				return err
			}
			_ = c.Close()
			return nil
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				on, err := backend.DNATStatus(family, table)
				if err != nil {
					// don't flap on nft errors; just log occasionally
					logging.Logf("[dnat:failsafe] status check failed: %v", err)
					continue
				}
				if !on {
					// DNAT is off -> do nothing, no auto-on
					failCount = 0
					lastErr = nil
					lastWhich = ""
					continue
				}

				// DNAT is ON -> both ports must be listening
				if err := check(addrHTTPS); err != nil {
					failCount++
					lastErr = err
					lastWhich = addrHTTPS
				} else if err := check(addrHTTP); err != nil {
					failCount++
					lastErr = err
					lastWhich = addrHTTP
				} else {
					failCount = 0
					lastErr = nil
					lastWhich = ""
					continue
				}

				if failCount >= failNeed {
					// confirm still on, then fail-open
					if on2, _ := backend.DNATStatus(family, table); on2 {
						_ = backend.DNATOff(family, table)
						if lastErr != nil {
							logging.Logf("[dnat:failsafe] DNAT OFF (ports not listening; last=%s err=%v)", lastWhich, lastErr)
						} else {
							logging.Logf("[dnat:failsafe] DNAT OFF (ports not listening)")
						}
					}
					// stay off; reset counter so we don't spam
					failCount = 0
					lastErr = nil
					lastWhich = ""
				}
			}
		}
	}()
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
		fmt.Printf("DNAT: ON  (priority %d, tcp/80->:%d, tcp+udp/443->:%d)\n", *priority, *httpPort, *httpsPort)
		return 0

	case "off":
		if err := backend.DNATOff(*family, *table); err != nil {
			fmt.Fprintln(os.Stderr, "dnat off failed:", err)
			return 1
		}
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
	} else {
		fmt.Println("State: OFF")
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
	fmt.Fprintln(os.Stderr, "  cfm dnat        (show ON/OFF + rules + explanation)")
	fmt.Fprintln(os.Stderr, "  cfm dnat on     (enable DNAT)")
	fmt.Fprintln(os.Stderr, "  cfm dnat off    (disable DNAT)")
}

func runPanelCLI(args []string, backend firewall.Backend) int {
	if len(args) > 0 && args[0] == "help" {
		panelHelp()
		return 0
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
	challenge := fs.String("challenge", "guard-only", "challenge")
	challengeSource := "default"
	for _, raw := range args {
		if strings.HasPrefix(raw, "--challenge") || strings.HasPrefix(raw, "challenge=") {
			challengeSource = "CLI flag"
		}
	}
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
	if !isSupportedPanelChallengeMode(*challenge) {
		fmt.Fprintf(os.Stderr, "dnat cpanel: unsupported challenge mode %q (supported: %s)\n", *challenge, strings.Join(supportedPanelChallengeModes, ", "))
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
		if err := persistPanelChallengeMode(*challenge); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on failed:", err)
			return 1
		}
		setPanelFirewallHealth("OK", "", true)
		if err := panelOn(*priority); err != nil {
			fmt.Fprintln(os.Stderr, "dnat cpanel on failed:", err)
			return 1
		}
		fmt.Println("Phase 1/2 (DNAT): OK")
		changes, err := ensurePanelAllowlist()
		if err != nil {
			setPanelFirewallHealth("FAILED", err.Error(), true)
			_ = execCommand("nft", "delete", "table", "inet", "cfm_panel_redirect").Run()
			setPanelFirewallHealth("PARTIAL", err.Error()+"; remediation: cfm dnat cpanel on", true)
			fmt.Fprintln(os.Stderr, "dnat cpanel on firewall failed:", err)
			return 1
		}
		setPanelFirewallHealth("OK", "", true)
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
		h := getPanelFirewallHealth()
		if err := exec.Command("nft", "delete", "table", "inet", "cfm_panel_redirect").Run(); err != nil {
		}
		changes, err := removePanelAllowlist()
		if err != nil {
			setPanelFirewallHealth("FAILED", err.Error(), h.Attempted)
			fmt.Fprintln(os.Stderr, "dnat cpanel off firewall failed:", err)
			return 1
		}
		setPanelFirewallHealth("OK", "", h.Attempted)
		fmt.Println("DNAT cpanel: OFF")
		for _, ch := range changes {
			fmt.Println("Firewall:", ch)
		}
		return 0
	case "status":
		on, rules, _ := panelStatus()
		fmt.Println("DNAT table: inet cfm_panel_redirect")
		if on {
			fmt.Printf("State: ON\nSelected priority: %d\nSelected mode: %s\n", *priority, selected)
		} else {
			fmt.Println("State: OFF")
		}
		panelMode, luaLoaded := panelListenerGuardState()
		if panelMode == "unknown" {
			if persisted := loadPersistedPanelChallengeMode(); persisted != "" {
				panelMode = persisted
				challengeSource = "runtime state"
			} else {
				panelMode = defaultPanelChallengeMode
				challengeSource = "default"
			}
		} else {
			challengeSource = "active listener config"
		}
		panelLuaPath := panelLuaGuardPath()
		panelLua := checkPanelLuaGuard(panelLuaPath)
		fmt.Printf("Challenge mode: %s\n", panelMode)
		fmt.Printf("Challenge mode source: %s\n", challengeSource)
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
		if panelLua.LoadError != "" {
			fmt.Printf("Panel Lua load check error: %s\n", panelLua.LoadError)
		}
		fw := panelFirewallState()
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
			out = append(out, "--challenge", strings.TrimPrefix(a, "challenge="))
			continue
		}
		if strings.Contains(a, "=") && !strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("dnat cpanel: unsupported key=value argument %q; use mode=, priority=, challenge=, or --flags", a)
		}
		out = append(out, a)
	}
	return out, nil
}

func panelHelp() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  cfm dnat cpanel status [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99] [--challenge %s]\n", strings.Join(supportedPanelChallengeModes, "|"))
	fmt.Fprintf(os.Stderr, "  cfm dnat cpanel on     [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99] [--challenge %s]\n", strings.Join(supportedPanelChallengeModes, "|"))
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel off")
	fmt.Fprintln(os.Stderr, "  cfm dnat cpanel help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands: status, on, off")
	fmt.Fprintln(os.Stderr, "Modes: auto, chain-imunify, direct-cpsrvd, fallback")
	fmt.Fprintln(os.Stderr, "Priority guidance: -101 (CFM-first), -99 (Imunify-first)")
	fmt.Fprintf(os.Stderr, "Challenge options: %s (default: %s)\n", strings.Join(supportedPanelChallengeModes, ", "), defaultPanelChallengeMode)
	fmt.Fprintln(os.Stderr, "Argument formats: --mode direct-cpsrvd or mode=direct-cpsrvd (same for priority/challenge)")
}

func panelOnHelp() {
	fmt.Fprintf(os.Stdout, "Usage: cfm dnat cpanel on [--mode auto|chain-imunify|direct-cpsrvd|fallback] [--priority -101|-99] [--challenge %s]\n", strings.Join(supportedPanelChallengeModes, "|"))
	fmt.Fprintln(os.Stdout, "Modes: auto, chain-imunify, direct-cpsrvd, fallback")
	fmt.Fprintln(os.Stdout, "Priority guidance: -101 (CFM-first), -99 (Imunify-first)")
	fmt.Fprintf(os.Stdout, "Challenge options: %s (default: %s)\n", strings.Join(supportedPanelChallengeModes, ", "), defaultPanelChallengeMode)
	fmt.Fprintf(os.Stdout, "Examples: --mode direct-cpsrvd, mode=direct-cpsrvd, --priority -101, priority=-101, --challenge %s\n", defaultPanelChallengeMode)
}
