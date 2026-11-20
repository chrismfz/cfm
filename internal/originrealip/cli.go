package originrealip

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"cfm/internal/edgeengine"
)

const usage = `cfm edge realip (also: cfm realip) — does the origin web server see visitors' real IPs behind the CFM edge?

  cfm edge realip [status] [--json]   show the origin's real-IP trust (read-only)
  cfm edge realip fix [--dry-run]     add the trust where it is missing, then config-test
                                      and gracefully reload the origin (rolled back on failure)

The edge proxies to the origin from 127.0.0.1. Without the origin trusting the
loopback, its access logs and PHP's REMOTE_ADDR read 127.0.0.1. fix writes:
  cPanel Apache       /etc/apache2/conf.d/cfm-remoteip.conf
  DirectAdmin Apache  a marked block in /etc/httpd/conf/extra/httpd-includes.conf
  Debian/EL Apache    conf-enabled/ or conf.d/cfm-remoteip.conf
  cPanel ea-nginx     /etc/nginx/conf.d/server-includes/cfm-realip.conf (every site server{})
  DirectAdmin nginx   a marked block in /etc/nginx/nginx-includes.conf
  nginx               /etc/nginx/conf.d/cfm-realip.conf
  DirectAdmin OpenLiteSpeed  the allow list (and useIpInProxyHeader) in /etc/openlitespeed,
                      and the same file in custombuild/custom/openlitespeed/conf/ (kept
                      by rewrite_confs); graceful restart, restored if it does not come back
LiteSpeed Enterprise, plain OpenLiteSpeed and NGM are reported with the manual step.
Only the loopback is ever trusted, never the server's public IP.

Exit status: status 0 = fine (or no edge in front), 1 = the edge is in front and
the origin logs 127.0.0.1 (or ::1 for IPv6 visitors, or the edge cannot turn
IPv6 on for want of the ::1 trust); fix 0 = trusted afterwards, 1 = not (see the message).
`

// edgeUnits are the CFM edge engines; one active means the edge fronts the origin.
var edgeUnits = edgeengine.Names()

// EdgeActive reports whether a CFM edge engine is running on this host.
func EdgeActive() bool {
	for _, u := range edgeUnits {
		if _, err := runCmd(probeTimeout, "systemctl", "is-active", "--quiet", u); err == nil {
			return true
		}
	}
	return false
}

// RunCLI is `cfm realip`.
func RunCLI(args []string) int {
	return runCLI(args, os.Stdout, system, EdgeActive)
}

func runCLI(args []string, w io.Writer, l layout, edgeActive func() bool) int {
	sub := "status"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	flags := map[string]bool{}
	for _, a := range args {
		flags[a] = true
	}
	switch sub {
	case "help", "-h", "--help":
		fmt.Fprint(w, usage)
		return 0
	case "status":
		p := l.probe("")
		edge := edgeActive()
		if flags["--json"] {
			_ = json.NewEncoder(w).Encode(map[string]any{"edge_active": edge, "probe": p, "ok": p.Trusted || !edge})
		} else {
			fmt.Fprintln(w, StatusLine(p, edge))
		}
		if p.Trusted || !edge {
			return 0
		}
		return 1
	case "fix":
		pl := l.plan(l.probe(""))
		fmt.Fprintf(w, "origin: panel=%s stack=%s\n", pl.Probe.Panel, pl.Probe.Stack)
		switch pl.Action {
		case ActionNone:
			fmt.Fprintln(w, "  OK: "+pl.Reason)
			return 0
		case ActionManual:
			fmt.Fprintln(w, "  manual step needed: "+pl.Reason)
			return 1
		}
		where := pl.Path
		if pl.Managed {
			where = "a marked block in " + pl.Path
		}
		if flags["--dry-run"] {
			if len(pl.Writes) > 0 {
				for _, fw := range pl.Writes {
					fmt.Fprintf(w, "  would write %s:\n%s", fw.Path, indent(fw.Content))
				}
				return 0
			}
			fmt.Fprintf(w, "  would write %s:\n%s", where, indent(pl.Content))
			return 0
		}
		if err := Apply(pl, w); err != nil {
			fmt.Fprintln(w, "  FAILED: "+err.Error())
			return 1
		}
		after := l.probe("")
		fmt.Fprintln(w, StatusLine(after, true))
		if !after.Trusted {
			return 1
		}
		return 0
	case "v6-bindcheck":
		// Internal (scripts/cfm-edge-listen-v6.sh): not in the usage text.
		return v6BindCheck(args, w)
	default:
		fmt.Fprintf(w, "unknown subcommand %q\n\n%s", sub, usage)
		return 2
	}
}

// StatusLine is the one-line verdict `cfm realip` prints.
func StatusLine(p Probe, edgeActive bool) string {
	ok, text := Verdict(p, edgeActive)
	if ok {
		return "OK   " + text
	}
	return "WARN " + text
}

// Verdict is the verdict shared by `cfm realip` and `cfm health`: fine (trusted,
// or no CFM edge in front) or not, and the sentence saying so.
func Verdict(p Probe, edgeActive bool) (ok bool, text string) {
	switch {
	case p.Trusted && p.Warning != "":
		return true, fmt.Sprintf("Origin real-IP: %s/%s trusts the edge via %s (%s), header %s; WARNING: %s", p.Panel, p.Stack, p.Directive, p.Source, p.Header, p.Warning)
	case p.Trusted:
		return true, fmt.Sprintf("Origin real-IP: %s/%s trusts the edge via %s (%s), header %s", p.Panel, p.Stack, p.Directive, p.Source, p.Header)
	case !edgeActive:
		return true, fmt.Sprintf("Origin real-IP: n/a, no CFM edge in front of the %s/%s origin", p.Panel, p.Stack)
	case p.Stack == StackUnknown:
		return false, "Origin real-IP: " + p.Note
	case p.v6Only && !p.EdgeIPv6Listening:
		return false, fmt.Sprintf("Origin real-IP: %s/%s %s, so the edge does not listen on IPv6 (run: cfm edge realip fix, then cfm edge ipv6 on; docs/edge-ipv6.md)", p.Panel, p.Stack, p.Note)
	case p.v6Only && p.UntrustedServers > 0 && p.UntrustedServers < p.Servers:
		return false, fmt.Sprintf("Origin real-IP: %s/%s %s, so those sites log ::1 for every IPv6 visitor (run: cfm edge realip fix)", p.Panel, p.Stack, p.Note)
	case p.v6Only:
		return false, fmt.Sprintf("Origin real-IP: %s/%s %s, so it logs ::1 for every IPv6 visitor (run: cfm edge realip fix)", p.Panel, p.Stack, p.Note)
	case p.UntrustedServers > 0 && p.UntrustedServers < p.Servers:
		return false, fmt.Sprintf("Origin real-IP: %s/%s %s, so those sites log 127.0.0.1 instead of the visitor (run: cfm edge realip fix)", p.Panel, p.Stack, p.Note)
	default:
		return false, fmt.Sprintf("Origin real-IP: %s/%s %s, so it logs 127.0.0.1 for every visitor (run: cfm edge realip fix)", p.Panel, p.Stack, p.Note)
	}
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("      " + line + "\n")
	}
	return b.String()
}
