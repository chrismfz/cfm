package edgecli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cfm/internal/clihttp"
)

// apiBase is the daemon API `cfm edge check` asks (set by main, as for
// `cfm dnat`'s daemon state).
var apiBase string

// SetAPIBase sets the daemon API base URL (e.g. http://127.0.0.1:6060).
func SetAPIBase(u string) { apiBase = strings.TrimRight(u, "/") }

// checkTimeout bounds one edge-health call: the daemon tails the edge logs
// and runs the engine's `-v`, which takes seconds on a busy node.
var checkTimeout = 60 * time.Second

// edgeHealthReport is the part of /api/v1/system/edge-health
// (system.edge_health.v1, internal/apiserver/edge_health_endpoint.go) the
// CLI prints; --json prints the whole body as it came.
type edgeHealthReport struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error"`
	Engine   string `json:"engine"`
	Version  string `json:"version"`
	Overall  string `json:"overall"`
	Findings []struct {
		Check    string `json:"check"`
		Severity string `json:"severity"`
		Summary  string `json:"summary"`
		Next     string `json:"next"`
	} `json:"findings"`
}

// fetchEdgeHealth GETs the daemon's edge-health report (admin-only: the CLI's
// token from cfm.conf, as every other CLI call to the daemon).
func fetchEdgeHealth(window int) ([]byte, error) {
	if apiBase == "" {
		return nil, fmt.Errorf("no daemon API address configured")
	}
	u := apiBase + "/api/v1/system/edge-health"
	if window > 0 {
		u += "?" + url.Values{"window": {strconv.Itoa(window)}}.Encode()
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := clihttp.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the daemon API at %s (is cfm running?): %w", apiBase, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read the edge-health report: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the daemon answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

const checkUsage = `Usage: cfm edge check [--json] [--window N]
  The edge's health checks (the MCP edge_health tool, docs/edge-health.md):
  engine version traps, origin 421 / premature-close storms, origin keepalive,
  a CDN caching the challenge, origin real IP, web DNAT order.
  --window N   access-log lines to scan (the daemon's default when omitted)
  --json       the daemon's report as it came
Exit status: 0 all ok, 1 a warn / unknown / critical finding or no report.
`

func runCheck(args []string, d deps) int {
	asJSON, window := false, 0
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--json":
			asJSON = true
		case a == "--window" && i+1 < len(args):
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				fmt.Fprintf(d.errOut, "edge check: --window wants a positive number, not %q\n", args[i+1])
				return 2
			}
			window, i = n, i+1
		case a == "help" || a == "-h" || a == "--help":
			fmt.Fprint(d.out, checkUsage)
			return 0
		default:
			fmt.Fprintf(d.errOut, "edge check: unexpected argument %q\n\n%s", a, checkUsage)
			return 2
		}
	}
	body, err := d.check(window)
	if err != nil {
		fmt.Fprintln(d.errOut, "edge check:", err)
		return 1
	}
	var rep edgeHealthReport
	if err := json.Unmarshal(body, &rep); err != nil {
		fmt.Fprintln(d.errOut, "edge check: unreadable report:", err)
		return 1
	}
	if asJSON {
		_, _ = d.out.Write(body)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Fprintln(d.out)
		}
	} else {
		printCheck(d, rep)
	}
	// An unknown must never read as OK: only an explicit "ok" exits 0.
	if !rep.OK || rep.Overall != "ok" {
		return 1
	}
	return 0
}

func printCheck(d deps, rep edgeHealthReport) {
	w := d.out
	if !rep.OK {
		msg := rep.Error
		if msg == "" {
			msg = "the daemon reported no result"
		}
		fmt.Fprintf(w, "Edge health: UNKNOWN (%s)\n", msg)
		return
	}
	engine := rep.Engine
	if engine == "" {
		engine = "no edge engine found"
	} else if rep.Version != "" {
		engine += " " + rep.Version
	}
	overall := rep.Overall
	if overall == "" {
		overall = "unknown"
	}
	fmt.Fprintf(w, "Edge health: %s   (%s)\n", strings.ToUpper(overall), engine)
	width := 0
	for _, f := range rep.Findings {
		if len(f.Check) > width {
			width = len(f.Check)
		}
	}
	for _, f := range rep.Findings {
		sev := f.Severity
		if sev == "" {
			sev = "unknown"
		}
		label := sev
		if sev != "ok" {
			label = strings.ToUpper(sev)
		}
		fmt.Fprintf(w, "  %-8s %-*s  %s\n", label, width, f.Check, f.Summary)
		if sev != "ok" && f.Next != "" {
			fmt.Fprintf(w, "  %-8s %-*s  next: %s\n", "", width, "", f.Next)
		}
	}
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "  (no checks reported)")
	}
}
