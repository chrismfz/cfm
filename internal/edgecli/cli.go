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
// dnat` and `cfm realip` stay as they are: scripts, docs and remediation
// hints call them.
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
	verdict func() (ok bool, text string)
	ipv6    func() ([]string, error)
}

// Run is `cfm edge`.
func Run(args []string, backend firewall.Backend) int {
	return run(args, deps{
		out:     os.Stdout,
		errOut:  os.Stderr,
		summary: func() dnat.Summary { return dnat.CollectSummary(backend) },
		dnat:    func(a []string) int { return dnat.RunCLI(a, backend) },
		realip:  originrealip.RunCLI,
		verdict: func() (bool, string) {
			return originrealip.Verdict(originrealip.ProbeSystem(""), originrealip.EdgeActive())
		},
		ipv6: ipv6Status,
	})
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
		if len(rest) > 1 || (len(rest) == 1 && rest[0] != "status") {
			fmt.Fprintln(d.errOut, "edge: ipv6 supports only `status` so far (turning it on/off: EDGE_LISTEN_V6 in cfm.conf, then sh "+ListenV6Script+" render; docs/edge-ipv6.md)")
			return 2
		}
		lines, err := d.ipv6()
		for _, l := range lines {
			fmt.Fprintln(d.out, l)
		}
		if err != nil {
			fmt.Fprintln(d.errOut, "edge: ipv6 status:", err)
			return 1
		}
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(d.out, usage)
		return 0
	default:
		fmt.Fprintf(d.errOut, "edge: unknown subcommand %q\n\n%s", sub, usage)
		return 2
	}
}

const usage = `Usage:
  cfm edge                         the edge at a glance (engine, web and panel DNAT, IPv6, origin real-IP)
  cfm edge on                      put the edge in the path: DNAT 80/443 to it (= cfm dnat on; same flags)
  cfm edge off                     take it out: the origin serves 80/443 directly (= cfm dnat off)
  cfm edge web                     the full web DNAT report (= cfm dnat)
  cfm edge bypass list|add|remove  sources that skip the web DNAT (= cfm dnat bypass …)
  cfm edge panel [status|on|off|bypass …]
                                   the panel ports through the edge (= cfm dnat cpanel …; alias: cfm edge cpanel)
  cfm edge realip [status|fix]     does the origin log the visitor, not 127.0.0.1 (= cfm realip …)
  cfm edge ipv6 [status]           the IPv6 listen decision of every installed engine (docs/edge-ipv6.md)

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
	default:
		fmt.Fprintf(w, "  Engine:      %s (active)\n", s.ActiveEdge)
	}

	switch {
	case s.WebErr != nil:
		fmt.Fprintf(w, "  Web DNAT:    UNKNOWN (%v)\n", s.WebErr)
		rc = 1
	case s.WebOn:
		fmt.Fprintf(w, "  Web DNAT:    ON   priority %d, tcp/80 -> :%d, tcp+udp/443 -> :%d%s\n", s.WebPriority, s.HTTPPort, s.HTTPSPort, bypassNote(s.WebBypass))
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
		fmt.Fprintf(w, "  Panel DNAT:  ON   priority %d%s\n", s.PanelPriority, bypassNote(s.PanelBypass))
	default:
		fmt.Fprintf(w, "  Panel DNAT:  OFF%s\n", bypassNote(s.PanelBypass))
	}

	lines, err := d.ipv6()
	lines = activeEngineLines(lines, s.ActiveEdge)
	switch {
	case err != nil:
		fmt.Fprintf(w, "  IPv6 listen: UNKNOWN (%v)\n", err)
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

	ok, text := d.verdict()
	mark := "OK  "
	if !ok {
		mark = "WARN"
	}
	fmt.Fprintf(w, "  Origin:      %s %s\n", mark, strings.TrimPrefix(text, "Origin real-IP: "))

	// What needs a look.
	var notes []string
	if s.WebErr == nil {
		if s.WebOn && s.ActiveEdge == "" && !s.Ambiguous {
			notes = append(notes, "web DNAT is ON but no edge engine is active: 80/443 go to an edge that is not running")
		}
		if !s.WebOn && s.WebIntent == "on" {
			notes = append(notes, "web DNAT is OFF but its saved intent is ON: the failsafe puts it back once the edge answers (cfm edge off clears the intent)")
		}
	}
	if s.PanelErr == nil && !s.PanelOn && s.PanelIntent == "on" {
		notes = append(notes, "panel DNAT is OFF but its saved intent is ON (cfm edge panel off clears the intent)")
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range notes {
			fmt.Fprintln(w, "  ! "+n)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "More: cfm edge web | cfm edge panel | cfm edge ipv6 | cfm edge realip | cfm edge help")
	return rc
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
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), strings.ToLower(active)+":") {
			mine = append(mine, l)
		}
	}
	if len(mine) == 0 {
		return lines
	}
	return mine
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
