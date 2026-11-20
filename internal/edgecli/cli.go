// Package edgecli is `cfm edge`: one command for the in-path edge proxy.
//
// It owns no logic of its own. The subcommands are the existing ones under a
// name that says what they are about:
//
//	cfm edge on|off|bypass …   = cfm dnat on|off|bypass …   (80/443 -> the edge)
//	cfm edge web               = cfm dnat                   (the full web DNAT report)
//	cfm edge panel …           = cfm dnat cpanel …          (alias: cfm edge cpanel)
//	cfm edge realip …          = cfm realip …
//	cfm edge ipv6 [status]     = cfm-edge-listen-v6.sh status
//
// and a bare `cfm edge` prints one summary of all of them, read-only. `cfm
// dnat` and `cfm realip` stay as they are (scripts and the installers call
// them; the remediation hints say `cfm edge`).
package edgecli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"cfm/internal/dnat"
	"cfm/internal/edgeengine"
	"cfm/internal/firewall"
	"cfm/internal/originrealip"
)

// ListenV6Script is the IPv6 listen decision script the packages install.
var ListenV6Script = "/usr/share/cfm/scripts/cfm-edge-listen-v6.sh"

// deps are the seams the tests replace; production wires them in Run.
type deps struct {
	out     io.Writer
	errOut  io.Writer
	summary func() dnat.Summary
	dnat    func(args []string) int
	realip  func(args []string) int
	verdict func(edgeInFront bool) (ok bool, text string)
	ipv6    func() ([]string, error)
	check   func(window int) ([]byte, error)
	setIPv6 func(value string, renderArgs []string) int
}

// Run is `cfm edge`. The firewall backend is built only for the routes that
// read or change DNAT: `cfm edge realip|ipv6|help` work where it cannot be
// (no nft binary), as `cfm realip` does. A nil backend gives the summary
// UNKNOWN DNAT lines and the rest of the picture.
func Run(args []string, backend func() firewall.Backend) int {
	d := deps{
		out:     os.Stdout,
		errOut:  os.Stderr,
		summary: func() dnat.Summary { return dnat.CollectSummary(backend()) },
		dnat:    func(a []string) int { return dnat.RunCLI(a, backend()) },
		realip:  originrealip.RunCLI,
		verdict: func(edgeInFront bool) (bool, string) {
			return originrealip.Verdict(originrealip.ProbeSystem(""), edgeInFront)
		},
		ipv6:  ipv6Status,
		check: fetchEdgeHealth,
	}
	d.setIPv6 = func(value string, renderArgs []string) int { return setIPv6(d, value, renderArgs) }
	return run(args, d)
}

func run(args []string, d deps) int {
	sub, rest := "", args
	if len(args) > 0 {
		sub, rest = args[0], args[1:]
	}
	switch sub {
	case "", "status":
		if len(rest) > 0 {
			fmt.Fprintf(d.errOut, "edge: %s takes no arguments\n", sub)
			return 2
		}
		return printSummary(d)
	case "on", "off", "bypass":
		return d.dnat(args)
	case "web":
		// The full `cfm dnat` report (rules, accepts, sockets, tokens).
		if len(rest) > 0 {
			fmt.Fprintln(d.errOut, "edge: web takes no arguments (use cfm edge on|off)")
			return 2
		}
		return d.dnat(nil)
	case "panel", "cpanel":
		return d.dnat(append([]string{"cpanel"}, rest...))
	case "realip":
		return d.realip(rest)
	case "ipv6":
		return runIPv6(rest, d)
	case "check":
		return runCheck(rest, d)
	case "help", "-h", "--help":
		fmt.Fprint(d.out, usage)
		return 0
	default:
		fmt.Fprintf(d.errOut, "edge: unknown subcommand %q\n\n%s", sub, usage)
		return 2
	}
}

const usage = `Usage:
  cfm edge [status]                the edge at a glance (engine, web and panel DNAT, IPv6, origin real-IP)
  cfm edge on                      put the edge in the path: DNAT 80/443 to it (= cfm dnat on; same flags)
  cfm edge off                     take it out: the origin serves 80/443 directly (= cfm dnat off)
  cfm edge web                     the full web DNAT report (= cfm dnat)
  cfm edge bypass list|add|remove  sources that skip the web DNAT (= cfm dnat bypass …)
  cfm edge panel [status|on|off|bypass …]
                                   the panel ports through the edge (= cfm dnat cpanel …; alias: cfm edge cpanel)
  cfm edge realip [status|fix]     does the origin log the visitor, not 127.0.0.1 (= cfm realip …)
  cfm edge ipv6 [status]           the IPv6 listen decision of every installed engine (docs/edge-ipv6.md)
  cfm edge ipv6 on [engine] | off  lift / set the EDGE_LISTEN_V6 kill switch, then render (RELOADS a running edge)
  cfm edge check [--json] [--window N]
                                   the edge's health checks, as the MCP edge_health tool (docs/edge-health.md)

"on" and "off" move traffic, they never start or stop the edge service.
`

func printSummary(d deps) int {
	s := d.summary()
	w := d.out
	rc := 0

	fmt.Fprintln(w, "Edge")
	switch {
	case s.Ambiguous:
		fmt.Fprintf(w, "  Engine:      WARNING: more than one of %s is active; exactly one should be active and enabled\n", edgeengine.NameList())
	case s.ActiveEdge == "":
		fmt.Fprintln(w, "  Engine:      none active")
	case !s.EdgeRunning:
		fmt.Fprintf(w, "  Engine:      %s (enabled, NOT running)\n", s.ActiveEdge)
	default:
		fmt.Fprintf(w, "  Engine:      %s (running)\n", s.ActiveEdge)
	}

	switch {
	case s.WebErr != nil:
		fmt.Fprintf(w, "  Web DNAT:    UNKNOWN (%v)\n", s.WebErr)
		rc = 1
	case s.WebOn:
		fromConfig := ""
		if s.WebFromConfig {
			fromConfig = " (configured values: the live chain could not be read)"
		}
		fmt.Fprintf(w, "  Web DNAT:    ON   priority %d, tcp/80 -> :%d, tcp+udp/443 -> :%d%s%s\n", s.WebPriority, s.HTTPPort, s.HTTPSPort, fromConfig, bypassNote(s.WebBypass))
	default:
		fmt.Fprintf(w, "  Web DNAT:    OFF  (the origin serves 80/443 directly)%s\n", bypassNote(s.WebBypass))
	}
	if pr := s.LastProbe; !pr.At.IsZero() {
		if pr.OK {
			fmt.Fprintf(w, "               last health probe ok at %s\n", pr.At.Format(time.RFC3339))
		} else {
			fmt.Fprintf(w, "               last health probe FAILED at %s: %s\n", pr.At.Format(time.RFC3339), pr.Reason)
		}
	}

	switch {
	case s.PanelErr != nil:
		fmt.Fprintf(w, "  Panel DNAT:  UNKNOWN (%v)\n", s.PanelErr)
		rc = 1
	case s.PanelOn:
		saved := ""
		if s.PanelFromSaved {
			saved = " (saved value: the live chain could not be parsed)"
		}
		mode := ""
		if s.PanelMode != "" {
			mode = ", mode " + s.PanelMode
		}
		fmt.Fprintf(w, "  Panel DNAT:  ON   priority %d%s%s%s\n", s.PanelPriority, saved, mode, bypassNote(s.PanelBypass))
	default:
		fmt.Fprintf(w, "  Panel DNAT:  OFF%s\n", bypassNote(s.PanelBypass))
	}

	lines, err := d.ipv6()
	lines = activeEngineLines(lines, s.ActiveEdge)
	switch {
	case err != nil:
		fmt.Fprintf(w, "  IPv6 listen: UNKNOWN (%v)\n", err)
		rc = 1
	case len(lines) == 0:
		fmt.Fprintln(w, "  IPv6 listen: no edge engine found")
	default:
		for i, l := range lines {
			label := "  IPv6 listen: "
			if i > 0 {
				label = "               "
			}
			fmt.Fprintln(w, label+l)
		}
	}

	// The origin's trust matters as soon as traffic is sent to an edge, running
	// or not: with DNAT on and the edge down, "n/a, no edge in front" would
	// contradict the DNAT lines above.
	// An unknown DNAT state or an ambiguous engine counts as "in front" too:
	// "n/a, no edge" must never print for something it could not read.
	ok, text := d.verdict(s.EdgeRunning || s.WebOn || s.PanelOn || s.Ambiguous || s.WebErr != nil || s.PanelErr != nil)
	mark := "OK  "
	if !ok {
		mark = "WARN"
	}
	fmt.Fprintf(w, "  Origin:      %s %s\n", mark, strings.TrimPrefix(text, "Origin real-IP: "))

	// What needs a look.
	var notes []string
	if s.WebErr == nil {
		if s.WebOn && !s.EdgeRunning && !s.Ambiguous {
			notes = append(notes, "web DNAT is ON but no edge engine runs: 80/443 go to an edge that is not there")
		}
		if !s.WebOn && s.WebIntent == "on" {
			notes = append(notes, "web DNAT is OFF but its saved intent is ON: the daemon's failsafe puts it back once the edge answers (cfm edge off clears the intent)")
		}
	}
	if s.PanelErr == nil {
		if s.PanelOn && !s.EdgeRunning && !s.Ambiguous {
			notes = append(notes, "panel DNAT is ON but no edge engine runs: the panel ports go to an edge that is not there")
		}
		if !s.PanelOn && s.PanelIntent == "on" {
			notes = append(notes, "panel DNAT is OFF but its saved intent is ON: the daemon's failsafe puts it back (cfm edge panel off clears the intent)")
		}
	}
	// IPv6 the host can do but the running edge does not listen on: the next
	// step, in order (server3, 2026-11-20). The Origin line already warns
	// when the ::1 trust is missing; this names what to run.
	if s.EdgeRunning && err == nil {
		for _, l := range lines {
			if !ipv6Available(l) {
				continue
			}
			step := "cfm edge ipv6 on (it reloads the edge and confirms the listen)"
			if !ok {
				step = "cfm edge realip fix first (the origin must trust the edge's 127.0.0.1 and ::1), then cfm edge ipv6 on"
			}
			notes = append(notes, "the host can do IPv6 but the edge listens on IPv4 only: "+step)
			break
		}
	}
	if s.WebBypass < 0 || s.PanelBypass < 0 {
		rc = 1
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range notes {
			fmt.Fprintln(w, "  ! "+n)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "More: cfm edge check | cfm edge web | cfm edge panel | cfm edge ipv6 | cfm edge realip | cfm edge help")
	return rc
}

// ipv6Available: an engine's status line (cfm-edge-listen-v6.sh status) says
// the host can do IPv6 and nothing forbids it, yet its listen files are not
// there. The script's wording is the contract; TestIPv6AvailablePhrases pins
// it to the script.
func ipv6Available(line string) bool {
	if !strings.HasSuffix(strings.TrimSpace(line), "files present: no") {
		return false
	}
	return strings.Contains(line, "an edge start never turns it on") || strings.Contains(line, ": wants IPv6 (")
}

// activeEngineLines keeps the IPv6 line of the engine that runs (the script
// reports every installed one: "OpenResty: …", "Angie: …", "cfm-edge: …");
// with none active, or no line for it, all of them. `cfm edge ipv6` prints
// them all.
func activeEngineLines(lines []string, active string) []string {
	if active == "" {
		return lines
	}
	var mine []string
	found := false
	for _, l := range lines {
		switch engineOfLine(l) {
		case strings.ToLower(active):
			mine = append(mine, l)
			found = true
		case "":
			// Not an engine's line (a WARNING about EDGE_LISTEN_V6, say): keep it.
			mine = append(mine, l)
		}
	}
	if !found {
		return lines
	}
	return mine
}

// engineOfLine is the engine a status line is about ("openresty", "angie",
// "cfm-edge"), or "" when it names none.
func engineOfLine(l string) string {
	name, _, ok := strings.Cut(l, ":")
	if !ok {
		return ""
	}
	if p, ok := edgeengine.Lookup(strings.ToLower(name)); ok {
		return p.Name
	}
	return ""
}

func bypassNote(n int) string {
	switch {
	case n < 0:
		return "; bypass list unreadable"
	case n == 0:
		return ""
	default:
		return fmt.Sprintf("; %d bypass source(s)", n)
	}
}

// ipv6Status runs the IPv6 listen script's read-only `status` and returns its
// per-engine lines without the script's log prefix.
func ipv6Status() ([]string, error) {
	if _, err := os.Stat(ListenV6Script); err != nil {
		return nil, fmt.Errorf("%s not found", ListenV6Script)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "sh", ListenV6Script, "status") // #nosec G204 -- fixed packaged script path
	cmd.Env = scriptEnv()
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	lines := ipv6Lines(out.String())
	if err != nil {
		return lines, fmt.Errorf("%s status: %w", ListenV6Script, err)
	}
	return lines, nil
}

func ipv6Lines(out string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "CFM edge IPv6 listen: "))
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
