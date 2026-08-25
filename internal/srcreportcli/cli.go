// Package srcreportcli implements `cfm detectors-srcresolve` (alias
// `detectors-resolve`): the per-section dry run of the shared detector
// source resolver — which journald unit / log file / docker container each
// section would tail on this host, and why. Fetches
// GET /api/v1/detectors/source-resolution from the daemon (the same planners
// the registers use; probes run live, nothing starts or changes).
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

// RunCLI is the entrypoint for `cfm detectors-srcresolve`.
//
//	cfm detectors-srcresolve           # table: section → resolved source + why
//	cfm detectors-srcresolve --json    # raw JSON passthrough
//	cfm detectors-srcresolve --wide    # include configured keys + full notes
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

	url := baseURL + "/api/v1/detectors/source-resolution"
	httpResp, err := clihttp.Get(url)
	if err != nil {
		return fmt.Errorf("detectors-srcresolve: cannot reach %s: %w\n(is cfm daemon running?)", url, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return fmt.Errorf("detectors-srcresolve: HTTP %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}

	if rawJSON {
		var raw json.RawMessage
		if err := json.NewDecoder(httpResp.Body).Decode(&raw); err != nil {
			return fmt.Errorf("detectors-srcresolve: decode: %w", err)
		}
		b, _ := json.MarshalIndent(raw, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	var resp response
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return fmt.Errorf("detectors-srcresolve: bad response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("detectors-srcresolve: %s", resp.Error)
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SECTION\tON\tSOURCE\tTARGET\tWHY")
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
		why := r.Reason
		if r.Note != "" {
			if why != "" {
				why += " · "
			}
			why += r.Note
		}
		if !wide {
			why = clip(why, 88)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Section, on, kind, r.Target, why)
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
			fmt.Fprintf(tw, "\t\t\t\tconfigured: %s\n", clip(strings.Join(kvs, " "), 110))
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Printf("\n%d sections · generated %s · dry run (probes ran; nothing changed)\n",
		len(resp.Rows), resp.GeneratedAt.Format(time.RFC3339))
	return nil
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
	fmt.Println(`cfm detectors-srcresolve — dry-run detector source resolution (alias: detectors-resolve)

Shows, per detectors.conf section, which log source (journald unit / file /
docker container) would be tailed on THIS host and why — the same resolution
the daemon performs at detector start. Read-only; probes run, nothing changes.

  cfm detectors-srcresolve          table view
  cfm detectors-srcresolve --wide   + configured source keys, untrimmed notes
  cfm detectors-srcresolve --json   raw JSON

Row vocabulary:
  SOURCE journal|file|docker   resolved source kind
         as-configured         explicit keys / package-internal resolution used verbatim
         self-disable          section would disable itself (MTA absent here)
         (provisional)         blind historical default; self-heals when the source appears
  Engine srcresolve rows come from the shared resolver; ftpd/modsec/mysql/
  webdetector still use their own autodetect (see their startup logs).`)
}
