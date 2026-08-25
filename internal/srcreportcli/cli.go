// Package srcreportcli implements `cfm detectors-srcresolve` (alias
// `detectors-resolve`): one command answering, per detector, the three
// questions of the rollout preview — does the watched DAEMON exist on this
// host (daemon coverage), did resolution FIND a source for it, and are we
// actually FOLLOWING it for logs/audit. It joins two read-only endpoints:
// GET /api/v1/detectors/source-resolution (the dry-run source resolver — the
// same planners the daemon's registers use) and GET /api/v1/detectors/coverage
// (daemon-vs-detector reality check). Probes run server-side; nothing starts
// or changes.
package srcreportcli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"cfm/internal/clihttp"
)

type row struct {
	Section      string            `json:"section"`
	Type         string            `json:"type"`
	Enabled      bool              `json:"enabled"`
	Engine       string            `json:"engine"`
	Configured   map[string]string `json:"configured"`
	Kind         string            `json:"kind"`
	Target       string            `json:"target"`
	Reason       string            `json:"reason"`
	Provisional  bool              `json:"provisional"`
	WouldDisable bool              `json:"would_disable"`
	Note         string            `json:"note"`
}

type response struct {
	OK          bool      `json:"ok"`
	GeneratedAt time.Time `json:"generated_at"`
	Rows        []row     `json:"rows"`
	Error       string    `json:"error"`
}

// covUnit / covType mirror /api/v1/detectors/coverage `types` rows
// (detector_coverage_endpoint.go, schema detectors.coverage.v1).
type covUnit struct {
	Unit   string `json:"unit"`
	Found  bool   `json:"found"`
	Active bool   `json:"active"`
}

type covType struct {
	Type        string    `json:"type"`
	DaemonAware bool      `json:"daemon_aware"`
	Verdict     string    `json:"verdict"` // ok | gap | disabled | dormant | absent | na
	Note        string    `json:"note"`
	Units       []covUnit `json:"units"`
}

type covSummary struct {
	TypesTotal int `json:"types_total"`
	OK         int `json:"ok"`
	Gaps       int `json:"gaps"`
	Disabled   int `json:"disabled"`
	Dormant    int `json:"dormant"`
	Absent     int `json:"absent"`
	EventOnly  int `json:"event_driven"`
}

type coverageResponse struct {
	OK      bool       `json:"ok"`
	Summary covSummary `json:"summary"`
	Types   []covType  `json:"types"`
	Error   string     `json:"error"`
}

// RunCLI is the entrypoint for `cfm detectors-srcresolve`.
//
//	cfm detectors-srcresolve           # table: daemon presence + resolved source + why
//	cfm detectors-srcresolve --json    # combined JSON (source resolution + coverage)
//	cfm detectors-srcresolve --wide    # + configured source keys, untrimmed notes
func RunCLI(baseURL string, args []string) error {
	rawJSON, wide := false, false
	for _, a := range args {
		switch a {
		case "--json":
			rawJSON = true
		case "--wide", "-w":
			wide = true
		case "help", "-h", "--help":
			printHelp()
			return nil
		default:
			return fmt.Errorf("detectors-srcresolve: unknown argument %q (try --json, --wide, help)", a)
		}
	}

	srcRaw, err := getJSON(baseURL + "/api/v1/detectors/source-resolution")
	if err != nil {
		return fmt.Errorf("detectors-srcresolve: %w", err)
	}
	// Coverage is the complementary half; its failure degrades the output
	// (daemon column reads "?") instead of sinking the command.
	covRaw, covErr := getJSON(baseURL + "/api/v1/detectors/coverage")

	if rawJSON {
		out := map[string]json.RawMessage{"source_resolution": srcRaw}
		if covErr == nil {
			out["coverage"] = covRaw
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		if covErr != nil {
			fmt.Fprintf(os.Stderr, "coverage unavailable: %v\n", covErr)
		}
		return nil
	}

	var resp response
	if err := json.Unmarshal(srcRaw, &resp); err != nil {
		return fmt.Errorf("detectors-srcresolve: bad response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("detectors-srcresolve: %s", resp.Error)
	}
	var cov coverageResponse
	haveCov := false
	if covErr == nil {
		if err := json.Unmarshal(covRaw, &cov); err == nil && cov.OK {
			haveCov = true
		}
	}

	covByType := map[string]covType{}
	if haveCov {
		for _, t := range cov.Types {
			covByType[strings.ToLower(t.Type)] = t
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SECTION\tON\tDAEMON\tSOURCE\tTARGET\tWHY")
	for _, r := range resp.Rows {
		on := "yes"
		if !r.Enabled {
			on = "no"
		}
		kind := r.Kind
		switch {
		case r.WouldDisable:
			kind = "self-disable"
		case r.Provisional:
			kind += " (provisional)"
		}
		daemon := "?"
		if haveCov {
			daemon = daemonCell(covByType[strings.ToLower(r.Type)])
		}
		why := r.Reason
		if r.Note != "" {
			if why != "" {
				why += " · "
			}
			why += r.Note
		}
		if !wide {
			why = clip(why, 80)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Section, on, daemon, kind, r.Target, why)
		if wide && len(r.Configured) > 0 {
			keys := make([]string, 0, len(r.Configured))
			for k := range r.Configured {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var kvs []string
			for _, k := range keys {
				kvs = append(kvs, k+"="+r.Configured[k])
			}
			fmt.Fprintf(tw, "\t\t\t\t\tconfigured: %s\n", clip(strings.Join(kvs, " "), 110))
		}
	}

	// Coverage-only rows: a daemon that RUNS here while nothing in the config
	// watches it (verdict gap), or watches it while it is absent (dormant),
	// for types that produced no source-resolution row at all — the
	// "forgot the ftp detector" case must not stay invisible. Guarded by
	// haveCov: a payload we decided not to trust must not feed rows either.
	if haveCov {
		for _, t := range coverageExtras(resp.Rows, cov.Types) {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				t.Type+" (not in config)", "—", daemonCell(t), "—", "",
				clip(strings.ToUpper(t.Verdict)+": "+t.Note, 80))
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if haveCov {
		s := cov.Summary
		// Two distinct denominators, kept separate so they reconcile: config
		// sections (rows above) vs detector TYPES (the coverage breakdown,
		// which spans types with no config section).
		fmt.Printf("\n%d config sections · %d detector types: %d ok", len(resp.Rows), s.TypesTotal, s.OK)
		if s.Gaps > 0 {
			fmt.Printf(" · %d GAP (daemon runs, nothing watches it)", s.Gaps)
		}
		if s.Dormant > 0 {
			fmt.Printf(" · %d dormant (watched, daemon absent)", s.Dormant)
		}
		if s.Disabled > 0 {
			fmt.Printf(" · %d disabled", s.Disabled)
		}
		fmt.Printf(" · %d absent", s.Absent)
		if s.EventOnly > 0 {
			fmt.Printf(" · %d event-driven", s.EventOnly)
		}
		fmt.Printf(" · generated %s · dry run, nothing changed\n",
			resp.GeneratedAt.Format(time.RFC3339))
	} else {
		fmt.Printf("\n%d sections · generated %s · dry run, nothing changed\n",
			len(resp.Rows), resp.GeneratedAt.Format(time.RFC3339))
		// Explain the "?" DAEMON cells whenever coverage was not usable —
		// transport error or an undecodable/not-ok payload alike.
		if covErr != nil {
			fmt.Fprintf(os.Stderr, "daemon coverage unavailable: %v\n", covErr)
		} else {
			fmt.Fprintln(os.Stderr, "daemon coverage unavailable: unusable response from /api/v1/detectors/coverage")
		}
	}
	return nil
}

// daemonCell renders the DAEMON column: which watched unit exists/runs on
// this host, per the coverage probe. Empty covType (unknown to coverage) and
// event-driven types render as "—".
func daemonCell(t covType) string {
	if t.Type == "" || !t.DaemonAware {
		return "—"
	}
	var found string
	for _, u := range t.Units {
		if u.Active {
			return u.Unit + " (active)"
		}
		if u.Found && found == "" {
			found = u.Unit
		}
	}
	if found != "" {
		return found + " (stopped)"
	}
	return "absent"
}

// coverageExtras returns coverage types worth a row of their own: verdict gap
// or dormant with NO section in the source-resolution report (types with
// sections already carry their coverage in the DAEMON column).
func coverageExtras(rows []row, types []covType) []covType {
	seen := map[string]bool{}
	for _, r := range rows {
		seen[strings.ToLower(r.Type)] = true
	}
	var out []covType
	for _, t := range types {
		if seen[strings.ToLower(t.Type)] {
			continue
		}
		if t.Verdict == "gap" || t.Verdict == "dormant" {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// getJSON fetches one endpoint and returns its body, requiring HTTP 200.
func getJSON(url string) (json.RawMessage, error) {
	resp, err := clihttp.Get(url)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w\n(is cfm daemon running?)", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, clip(strings.TrimSpace(string(body)), 200))
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("non-JSON response from %s", url)
	}
	return body, nil
}

// clip truncates to at most n runes (not bytes — reasons/notes carry
// multibyte punctuation, and a byte slice could split a rune mid-sequence).
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func printHelp() {
	fmt.Println(`cfm detectors-srcresolve — detector source + daemon coverage preview (alias: detectors-resolve)

One dry-run table answering, per detector: does the watched DAEMON exist on
this host, did resolution FIND a log source for it, and are we FOLLOWING it.
Read-only; probes run server-side, nothing changes.

  cfm detectors-srcresolve          table view
  cfm detectors-srcresolve --wide   + configured source keys, untrimmed notes
  cfm detectors-srcresolve --json   combined JSON (source_resolution + coverage)

Columns:
  DAEMON <unit> (active|stopped) | absent | —   what the coverage probe found
         ("—" = event-driven detector, no daemon concept; "?" = coverage unavailable)
  SOURCE journal|file|docker    resolved source kind
         as-configured          explicit keys / package-internal resolution used verbatim
         self-disable           section would disable itself (daemon absent here)
         (provisional)          blind historical default; self-heals when the source appears

Extra rows "<type> (not in config)" surface coverage verdicts with no config
section: GAP = the daemon RUNS here but nothing watches it (the forgotten-ftp
case); dormant = watched but the daemon is absent. The trailing summary counts
ok/GAP/dormant/disabled/absent across all detector types.`)
}
