package edgecli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cfm/internal/clihttp"
	"cfm/internal/dnat"
)

// apiBase is the daemon API `cfm edge check` asks: the one main gives
// `cfm dnat` (dnat.SetAPIBase), never a second copy. A seam for tests.
var apiBase = dnat.APIBase

// maxReport bounds the report read; a larger one is an error, not a silent cut.
const maxReport = 8 << 20

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
	base := strings.TrimRight(apiBase(), "/")
	if base == "" {
		return nil, fmt.Errorf("no daemon API address configured")
	}
	u := base + "/api/v1/system/edge-health"
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
		if errors.Is(err, context.DeadlineExceeded) {
			// The daemon is up but still scanning the edge logs.
			return nil, fmt.Errorf("the daemon did not answer within %s (a large --window scans more of the edge logs; try a smaller one)", checkTimeout)
		}
		return nil, fmt.Errorf("cannot reach the daemon API at %s (is cfm running?): %w", base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReport+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("the daemon did not finish the report within %s (try a smaller --window)", checkTimeout)
		}
		return nil, fmt.Errorf("read the edge-health report (%s): %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the daemon answered %s: %s", resp.Status, clip(strings.TrimSpace(string(body)), 512))
	}
	if len(body) > maxReport {
		return nil, fmt.Errorf("the edge-health report is larger than %d MB", maxReport>>20)
	}
	return body, nil
}

const checkUsage = `Usage: cfm edge check [--json] [--window N]
  The edge's health checks (the MCP edge_health tool, docs/edge-health.md):
  engine version traps, origin 421 / premature-close storms, origin keepalive,
  a CDN caching the challenge, origin real IP, web DNAT order.
  --window N   access-log lines to scan (default 50000, the daemon caps it at 500000)
  --json       the daemon's report as it came
Exit status: 0 all ok; 1 a warn / unknown / critical finding, or no report
(a resolved 421 storm still in the log tail stays warn until it scrolls out);
2 a usage error.
`

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Back off to a rune boundary: never split a multi-byte character.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func runCheck(args []string, d deps) int {
	asJSON, window := false, 0
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--json":
			asJSON = true
		case a == "--window" || strings.HasPrefix(a, "--window="):
			v, ok := strings.CutPrefix(a, "--window=")
			if !ok {
				if i+1 >= len(args) {
					fmt.Fprintln(d.errOut, "edge check: --window wants a number")
					return 2
				}
				v, i = args[i+1], i+1
			}
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				fmt.Fprintf(d.errOut, "edge check: --window wants a positive number, not %q\n", v)
				return 2
			}
			window = n
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
	// An unknown must never read as OK: only an explicit "ok" exits 0, and
	// every finding must agree (the daemon derives overall from them; a
	// report where they disagree is not trusted).
	if !rep.OK || rep.Overall != "ok" {
		return 1
	}
	for _, f := range rep.Findings {
		if f.Severity != "ok" {
			return 1
		}
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
