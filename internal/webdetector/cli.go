// internal/webdetector/cli.go
package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// ---- sorting helpers ----
func sortShortRows(rows []ShortRow, key string) {
	key = strings.ToLower(strings.TrimSpace(key))
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case "rps", "":
			return a.RPS > b.RPS
		case "2xx":
			return a.R2xx > b.R2xx
		case "3xx":
			return a.R3xx > b.R3xx
		case "4xx":
			return a.R4xx > b.R4xx
		case "5xx":
			return a.R5xx > b.R5xx
		case "uniq", "unique", "uniqip":
			return a.UniqueIPs > b.UniqueIPs
		case "err", "err%":
			return a.ErrRatio > b.ErrRatio
		case "rt", "rt_avg", "lat", "latency":
			return a.ProcAvgSec > b.ProcAvgSec
                case "score":
                        return a.Score > b.Score
                case "bot", "bot%":
                        return a.BotRatio > b.BotRatio
                case "ua", "ua_div", "uadiv":
                        return a.UADiversity > b.UADiversity
		}
		// fallback
		return a.RPS > b.RPS
	})
}

// topShortCLIResponse ταιριάζει με το JSON που γυρίζει το /top-short.
type topShortCLIResponse struct {
	WindowSec      float64    `json:"window_sec"`
	LongHorizonSec float64    `json:"long_horizon_sec"`
	Rows           []ShortRow `json:"rows"`
}

// longTopCLIResponse για το /webdet/long-top.
type longTopCLIResponse struct {
        LongHorizonSec float64         `json:"long_horizon_sec"`
        Rows           []SuspiciousRow `json:"rows"`
}

// small help printer for cfm webtop
func printWebTopHelp() {
	fmt.Println(" Usage:")
	fmt.Println("  cfm webtop                     # summary view (short window + suspicious)")
	fmt.Println("  cfm webtop <vhost>             # drilldown into a single vhost")
	fmt.Println("  cfm webtop top [N]             # show top N vhosts by RPS (default 20)")
	fmt.Println("  cfm webtop --limit 15 --sort 5xx")
	fmt.Println("  cfm webtop top 20 rt")
	fmt.Println("  cfm webtop hot [N]         # global hot IPs (short window)")
        fmt.Println("  cfm webtop long [N]             # long-window top by score (no minScore)")
	fmt.Println()
	fmt.Println("Sort keys: rps, 2xx, 3xx, 4xx, 5xx, uniq, err, rt, bot, ua_div, score")
        fmt.Println("------------")

}

// RunWebTop is the CLI entrypoint for `cfm webtop`.
// baseURL is something like "http://127.0.0.1:9070".
func RunWebTop(baseURL string, args []string) error {



    // Ειδικό mode: hot IPs (short window)
    if len(args) > 0 && args[0] == "hot" {
        limit := 20
        if len(args) > 1 {
            if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
                limit = n
            } else {
                return fmt.Errorf("invalid hot limit: %s", args[1])
            }
        }
        return runHotIPs(baseURL, limit)
    }

    // Ειδικό mode: long window top-by-score
    if len(args) > 0 && args[0] == "long" {
        limit := 20
        if len(args) > 1 {
            if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
                limit = n
            } else {
                return fmt.Errorf("invalid long limit: %s", args[1])
            }
        }
        return runLongTop(baseURL, limit)
    }


	// Help modes: cfm webtop help / -h / --help
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			printWebTopHelp()
			return nil
		}
	}

	// Parsing:
	var (
		limit   int
		sortKey string
		host    string
		inTop   bool
	)

	i := 0
	for i < len(args) {
		a := args[i]

		// "top" or "top 10"
		if a == "top" {
			inTop = true
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					limit = n
					i += 2
					continue
				}
			}
			i++
			continue
		}

		if strings.HasPrefix(a, "top=") {
			inTop = true
			n, err := strconv.Atoi(strings.TrimPrefix(a, "top="))
			if err != nil {
				return fmt.Errorf("invalid top= value")
			}
			limit = n
			i++
			continue
		}

		// --limit / -n
		if a == "--limit" || a == "-n" {
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a number", a)
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				return fmt.Errorf("invalid limit")
			}
			limit = n
			inTop = true
			i += 2
			continue
		}
		if strings.HasPrefix(a, "--limit=") {
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--limit="))
			if err != nil {
				return fmt.Errorf("invalid --limit=")
			}
			limit = n
			inTop = true
			i++
			continue
		}

		// sort
		if a == "--sort" {
			if i+1 >= len(args) {
				return fmt.Errorf("--sort needs a key")
			}
			sortKey = args[i+1]
			inTop = true
			i += 2
			continue
		}
		if strings.HasPrefix(a, "--sort=") {
			sortKey = strings.TrimPrefix(a, "--sort=")
			inTop = true
			i++
			continue
		}

		// If none matched, it must be a host (drilldown)
// --- sort shortcut for: cfm webtop top 10 rt ---
if inTop && sortKey == "" && host == "" {
    // If argument looks like a valid sort key -> treat as sort
    low := strings.ToLower(a)
    switch low {
    case "rps", "2xx", "3xx", "4xx", "5xx", "uniq", "uniqip", "unique", "err", "err%", "rt", "rt_avg", "lat", "latency","score":
        sortKey = low
        i++
        continue
    }
}

// Otherwise treat as host (drilldown)
if host == "" {
    host = a
    i++
    continue
}

return fmt.Errorf("unexpected arg: %s", a)


	}

	// host mode cannot mix with top mode
	if host != "" && inTop {
		return fmt.Errorf("cannot combine top/limit/sort with a vhost name")
	}

	// default top N when user typed "top" with no number
	if inTop && limit == 0 {
		limit = 20
	}

	if host != "" {
		return runTopDrilldown(baseURL, host)
	}

	// No host => summary/top mode
	if inTop {
		return runTopSummaryExt(baseURL, limit, sortKey)
	}
	// plain "cfm webtop"
	return runTopSummary(baseURL)
}

// legacy simple summary (no limit/sort) – now just a wrapper
func runTopSummary(baseURL string) error {
	return runTopSummaryExt(baseURL, 0, "")
}

// new extended summary with limit/sort
func runTopSummaryExt(baseURL string, limit int, sortKey string) error {
	topURL := baseURL + "/api/v1/webdet/top-short"
	resp, err := http.Get(topURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var payload topShortCLIResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	rows := payload.Rows

	// sort if needed
	sortShortRows(rows, sortKey)

	// apply limit
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	// HEADER
	hdr := fmt.Sprintf("[webtop] short window=%.0fs, long horizon≈%.0fs",
		payload.WindowSec, payload.LongHorizonSec)
	if limit > 0 {
		key := sortKey
		if key == "" {
			key = "rps"
		}
		hdr += fmt.Sprintf(" (top %d by %s)", limit, key)
	}
	fmt.Println(hdr)

	// reuse the common printer
	return printWebShort(baseURL, rows, payload)
}

func runTopDrilldown(baseURL, host string) error {
	u := baseURL + "/api/v1/webdet/drilldown?host=" + url.QueryEscape(host)
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	var short HostDetail
	if b, ok := payload["short"]; ok {
		_ = json.Unmarshal(b, &short)
	}

        fmt.Printf("[%s] window=%.0fs total=%d direct=%.1f%% bots=%.1f%% rt_avg=%.3fs short_score=%.2f\n",
                short.Host, short.WindowSec, short.TotalReq,
                short.DirectPct, short.BotPct, short.ProcAvgSec,
                short.ShortScore)

        fmt.Printf("  ua_div=%.3f (unique=%d) path_div=%.3f (unique=%d) post_ratio=%.3f\n",
                short.UADiversity, short.UniqueUAs,
                short.PathDiversity, short.UniquePaths,
                short.PostRatio)

        if len(short.ShortReasons) > 0 {
                fmt.Printf("Short-window reasons: %s\n", strings.Join(short.ShortReasons, ","))
        }


	fmt.Println("Top IPs:")

	// Αν έχουμε enrichment, χρησιμοποιούμε το enriched view (όπως στο παλιό httpd-top).
	if len(short.EnrichedTopIPs) > 0 {
		for i, row := range short.EnrichedTopIPs {
			ip := row["ip"]
			count := row["count"]
			ptr := row["ptr"]
			asn := row["asn"]      // π.χ. "216285"
			asnNm := row["asn_name"] // π.χ. "Myip Networks G.p."
			cc := row["country"]  // π.χ. "GR"

			// parse count για να ταιριάζει με xN formatting
			n, _ := strconv.Atoi(count)

			// π.χ. "titan.myip.gr  AS216285 Myip Networks G.p.  GR"
			parts := make([]string, 0, 3)
			if ptr != "" {
				parts = append(parts, ptr)
			}
			if asn != "" || asnNm != "" {
				// βάλε prefix AS μόνο αν έχουμε νούμερο
				asField := asn
				if asField != "" && !strings.HasPrefix(asField, "AS") {
					asField = "AS" + asField
				}
				parts = append(parts, strings.TrimSpace(asField+" "+asnNm))
			}
			if cc != "" {
				parts = append(parts, cc)
			}
			extra := ""
			if len(parts) > 0 {
				extra = "  " + strings.Join(parts, "  ")
			}

			fmt.Printf("  %2d %-15s x%-5d%s\n", i+1, ip, n, extra)
		}
	} else {
		// Fallback στο απλό view αν για κάποιο λόγο δεν έχουμε enrichment.
		for i, kv := range short.TopIPs {
			fmt.Printf("  %2d %-15s x%-5d\n", i+1, kv.Key, kv.Count)
		}
	}

	fmt.Println("Top Agents:")
	for i, kv := range short.TopAgents {
		fmt.Printf("  %2d %s (x%d)\n", i+1, kv.Key, kv.Count)
	}
	fmt.Println("Top Referrers:")
	for i, kv := range short.TopReferrers {
		fmt.Printf("  %2d %s (x%d)\n", i+1, kv.Key, kv.Count)
	}
	fmt.Println("Top Paths:")
	for i, kv := range short.TopPaths {
		fmt.Printf("  %2d %s (x%d)\n", i+1, kv.Key, kv.Count)
	}

	if b, ok := payload["long"]; ok {
		var lr SuspiciousRow
		if err := json.Unmarshal(b, &lr); err == nil {
			fmt.Println()
			fmt.Println("Long-window summary (trend):")
			fmt.Printf("  host=%s score=%.2f reasons=%s rps=%.2f 3xx=%.2f 4xx=%.2f 5xx=%.2f uniqIP=%d err=%.1f%%\n",
				lr.Host, lr.Score, joinReasons(lr.Reasons), lr.RPS, lr.R3xx, lr.R4xx, lr.R5xx, lr.UniqueIPs, lr.ErrRatio*100)
		}
	}

	return nil
}

func joinReasons(r []string) string {
	if len(r) == 0 {
		return "-"
	}
	if len(r) == 1 {
		return r[0]
	}
	return strings.Join(r, ",")
}

// printWebShort prints the main RPS table + TOTAL + suspicious section.
func printWebShort(baseURL string, rows []ShortRow, payload topShortCLIResponse) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

        fmt.Fprintln(w, "HOST\tRPS\t2xx\t3xx\t4xx\t5xx\t401\t403\t404\t499\tuniqIP\terr%\trt_avg\tscore\tbot%\tua_div\tpath_div\tpost%")

	var totRPS, tot2, tot3, tot4, tot5, tot401, tot403, tot404, tot499 float64
	var totUniq int
	var rtN, rtD float64

        for _, r := range rows {
                fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\t%.3f\t%.2f\t%.1f\t%.3f\t%.3f\t%.1f\n",
                        r.Host, r.RPS, r.R2xx, r.R3xx, r.R4xx, r.R5xx,
                        r.R401, r.R403, r.R404, r.R499,
                        r.UniqueIPs, r.ErrRatio*100, r.ProcAvgSec, r.Score,
                        r.BotRatio*100,      // bot%
                        r.UADiversity,       // raw (0–1-ish)
                        r.PathDiversity,     // raw
                        r.PostRatio*100,     // %
                )

		totRPS += r.RPS
		tot2 += r.R2xx
		tot3 += r.R3xx
		tot4 += r.R4xx
		tot5 += r.R5xx
		tot401 += r.R401
		tot403 += r.R403
		tot404 += r.R404
		tot499 += r.R499
		totUniq += r.UniqueIPs

		if r.RPS > 0 && r.ProcAvgSec > 0 {
			rtN += r.ProcAvgSec * r.RPS
			rtD += r.RPS
		}
	}

	if len(rows) > 0 {
		errPct := 0.0
		if totRPS > 0 {
			errPct = (tot4 + tot5 + tot499) / totRPS * 100
		}
		rtAvg := 0.0
		if rtD > 0 {
			rtAvg = rtN / rtD
		}

                fmt.Fprintf(w,
                        "TOTAL\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\t%.3f\t-\t-\t-\t-\t-\n",
                        totRPS, tot2, tot3, tot4, tot5, tot401, tot403, tot404, tot499,
                        totUniq, errPct, rtAvg)

	}

	w.Flush()

	// Suspicious block (long window), same as before
	susURL := baseURL + "/api/v1/webdet/suspicious"
	resp2, err := http.Get(susURL)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	var sus []SuspiciousRow
	if err := json.NewDecoder(resp2.Body).Decode(&sus); err != nil {
		return err
	}

	if len(sus) > 0 {
		fmt.Println()
		fmt.Println("---- Suspicious vhosts (long window) ----")
		w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w2, "HOST\tSCORE\tREASONS\tRPS\t3xx\t4xx\t5xx\tuniqIP\terr%")
		for _, s := range sus {
			fmt.Fprintf(w2, "%s\t%.2f\t%s\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\n",
				s.Host, s.Score, joinReasons(s.Reasons),
				s.RPS, s.R3xx, s.R4xx, s.R5xx,
				s.UniqueIPs, s.ErrRatio*100)
		}
		w2.Flush()
	}
	return nil
}




// runHotIPs καλεί /hot-ips και τυπώνει global "ζεστά" IPs.
func runHotIPs(baseURL string, limit int) error {
    u := fmt.Sprintf("%s/api/v1/webdet/hot-ips?limit=%d", baseURL, limit)
    resp, err := http.Get(u)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var rows []HotIPRow
    if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
        return err
    }

    fmt.Printf("[webtop hot] top %d hot IPs (short window aggregate)\n", limit)

    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "IP\txReqs\tvhosts\tPTR\tASN\tCC")

    for _, r := range rows {
        asField := ""
        if r.ASN != "" {
            asField = "AS" + r.ASN
            if r.ASNName != "" {
                asField += " " + r.ASNName
            }
        }
        fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\t%s\n",
            r.IP, r.Req, r.Vhosts, r.PTR, asField, r.Country)
    }

    w.Flush()
    return nil
}



// runLongTop καλεί /long-top και τυπώνει long-window scored rows.
func runLongTop(baseURL string, limit int) error {
        u := fmt.Sprintf("%s/api/v1/webdet/long-top?limit=%d", baseURL, limit)
        resp, err := http.Get(u)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        var payload longTopCLIResponse
        if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
                return err
        }

        rows := payload.Rows

        fmt.Printf("[webtop long] horizon≈%.0fs (top %d by score)\n",
                payload.LongHorizonSec, limit)

        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        fmt.Fprintln(w, "HOST\tSCORE\tRPS\t3xx\t4xx\t5xx\tuniqIP\terr%\tauth401%\thotIPs\tbot%\tua_div\tpath_div\tpost%")

        for _, r := range rows {
                fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\t%.1f\t%d\t%.1f\t%.3f\t%.3f\t%.1f\n",
                        r.Host,
                        r.Score,
                        r.RPS,
                        r.R3xx,
                        r.R4xx,
                        r.R5xx,
                        r.UniqueIPs,
                        r.ErrRatio*100,
                        r.Auth401Ratio*100,
                        r.HotIPs,
                        r.BotRatio*100,
                        r.UADiversity,
                        r.PathDiversity,
                        r.PostRatio*100,
                )
        }
        w.Flush()
        return nil
}
