// internal/cli/which.go
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"cfm/internal/clihttp"
	"cfm/internal/firewall"
	ipquery "cfm/internal/ipquery"
	"cfm/internal/locate"
)

// RunWhich implements `cfm which|search <IP|CIDR>`: a read-only,
// multi-source lookup across nft, cfm.deny, csf, fail2ban and
// imunify360 (sources that aren't installed are reported as skipped).
//
// For a single IP it also appends a best-effort "CFM detection history"
// section (WAF / challenge / autoblock events the daemon recorded for that IP),
// which answers "why / from where" a ban originated — the piece the enforcement
// sources can't tell you when the nft entry carries no comment. It reaches the
// daemon over clihttp; if the daemon is unreachable the local lookup still
// stands and the section is reported as unavailable.
func RunWhich(args []string, be firewall.Backend, cfgDir, baseURL string, tableExists func() bool) int {
	fs := flag.NewFlagSet("which", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm which <IP|CIDR> [--json]")
		return 2
	}

	arg := fs.Arg(0)

	if be != nil && (tableExists == nil || !tableExists()) {
		if err := be.EnsureBase(); err != nil {
			fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
			return 1
		}
	}

	res, err := locate.FindWithTimeout(arg, locate.Options{
		BE:        be,
		ConfigDir: cfgDir,
	}, 20*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	// Detection-history "why / from where" only makes sense for a single IP
	// (the history is keyed by exact IP, not a CIDR).
	var hist *histSummary
	if net.ParseIP(arg) != nil {
		hist = fetchDetectionHistory(baseURL, arg)
	}

	if *asJSON {
		type whichJSON struct {
			*locate.Result
			DetectionHistory *histSummary `json:"detection_history,omitempty"`
		}
		b, _ := json.MarshalIndent(whichJSON{Result: res, DetectionHistory: hist}, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	suffix := ipquery.EnrichSuffix(cfgDir, arg)

	if len(res.Locations) == 0 {
		fmt.Println("(no matches)")
	} else {
		fmt.Printf("Matches for %s%s:\n", arg, suffix)
		for _, l := range res.Locations {
			line := fmt.Sprintf(" - %s via %s %s [%s]", l.Action, l.Source, l.List, l.Match)
			if l.Feed != "" {
				line += fmt.Sprintf(" (feed: %s)", l.Feed)
			}
			if l.Reason != "" {
				line += " — " + l.Reason
			}
			fmt.Println(line)
		}
	}

	if len(res.Skipped) > 0 {
		srcs := make([]string, 0, len(res.Skipped))
		for s := range res.Skipped {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs)
		for _, s := range srcs {
			fmt.Printf("(skipped: %s — %s)\n", s, res.Skipped[s])
		}
	}

	renderDetectionHistory(hist)
	return 0
}

// ── detection-history correlation ("why / from where") ─────────────────────────

type histEvent struct {
	EventType string `json:"event_type"`
	Reason    string `json:"reason"`
	Host      string `json:"host"`
	TsUTC     string `json:"ts_utc"`
}

type histGroup struct {
	EventType  string `json:"event_type"`
	Reason     string `json:"reason,omitempty"`
	Count      int    `json:"count"`
	LastUTC    string `json:"last_utc,omitempty"`
	SampleHost string `json:"sample_host,omitempty"`
}

type histSummary struct {
	Total       int         `json:"total"`
	Groups      []histGroup `json:"groups,omitempty"`
	Unavailable bool        `json:"unavailable,omitempty"`
	Note        string      `json:"note,omitempty"`
}

// fetchDetectionHistory GETs the durable detection events for one IP over
// clihttp (best-effort). A missing/unreachable daemon yields an Unavailable
// summary rather than an error, so the local `which` lookup is never blocked.
func fetchDetectionHistory(baseURL, ip string) *histSummary {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/history/events?enrich=1&limit=500&ip=" + url.QueryEscape(ip)
	resp, err := clihttp.Get(u)
	if err != nil {
		return &histSummary{Unavailable: true, Note: "cfm daemon not reachable"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &histSummary{Unavailable: true, Note: fmt.Sprintf("history endpoint HTTP %d", resp.StatusCode)}
	}
	var body struct {
		Rows []histEvent `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return &histSummary{Unavailable: true, Note: "history decode error"}
	}
	return summarizeHistory(body.Rows)
}

// summarizeHistory groups events by (event_type, reason) with counts, the latest
// timestamp and a sample host. Pure — unit-tested. An empty result is itself the
// answer: no WAF/detector/challenge event means a manual or blocklist ban.
func summarizeHistory(rows []histEvent) *histSummary {
	s := &histSummary{Total: len(rows)}
	if len(rows) == 0 {
		s.Note = "no CFM detection events for this IP — not a WAF/detector/challenge action (a manual `cfm block` or an imported blocklist ban)"
		return s
	}
	type agg struct {
		count int
		last  string
		host  string
	}
	m := map[string]*agg{}
	for _, e := range rows {
		key := e.EventType + "\x00" + e.Reason
		a := m[key]
		if a == nil {
			a = &agg{}
			m[key] = a
		}
		a.count++
		if e.TsUTC > a.last { // RFC3339 sorts lexically
			a.last = e.TsUTC
		}
		if a.host == "" && e.Host != "" {
			a.host = e.Host
		}
	}
	for key, a := range m {
		i := strings.IndexByte(key, 0)
		s.Groups = append(s.Groups, histGroup{
			EventType: key[:i], Reason: key[i+1:], Count: a.count, LastUTC: a.last, SampleHost: a.host,
		})
	}
	sort.Slice(s.Groups, func(i, j int) bool {
		if s.Groups[i].Count != s.Groups[j].Count {
			return s.Groups[i].Count > s.Groups[j].Count
		}
		if s.Groups[i].EventType != s.Groups[j].EventType {
			return s.Groups[i].EventType < s.Groups[j].EventType
		}
		return s.Groups[i].Reason < s.Groups[j].Reason
	})
	return s
}

func renderDetectionHistory(hist *histSummary) {
	if hist == nil {
		return
	}
	fmt.Println()
	switch {
	case hist.Unavailable:
		fmt.Printf("CFM detection history (why / from where): unavailable — %s\n", hist.Note)
	case hist.Total == 0:
		fmt.Println("CFM detection history (why / from where): (none)")
		fmt.Println("  → not a WAF/detector/challenge action — a manual `cfm block` or an imported blocklist ban")
	default:
		fmt.Printf("CFM detection history (why / from where): %d events\n", hist.Total)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  EVENT\tREASON\tCOUNT\tLAST(UTC)\tSAMPLE HOST")
		for _, g := range hist.Groups {
			fmt.Fprintf(w, "  %s\t%s\t%d\t%s\t%s\n", g.EventType, g.Reason, g.Count, g.LastUTC, g.SampleHost)
		}
		w.Flush()
	}
}
