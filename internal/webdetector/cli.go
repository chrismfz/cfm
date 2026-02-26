// internal/webdetector/cli.go
package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net"
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

// ipShortCLIResponse για το /webdet/ip-short.
type ipShortCLIResponse struct {
        WindowSec      float64     `json:"window_sec"`
        LongHorizonSec float64     `json:"long_horizon_sec"`
        Short          []IPSignals `json:"short"`
        Long           []IPSignals `json:"long"`
}


// small help printer for cfm webtop
func printWebTopHelp() {
	fmt.Println(" Usage:")
	fmt.Println("  cfm webtop                     # summary view (short window + suspicious)")
	fmt.Println("  cfm webtop <vhost>             # drilldown into a single vhost")
	fmt.Println("  cfm webtop top [N]             # show top N vhosts by RPS (default 20)")
	fmt.Println("  cfm webtop --limit 15 --sort 5xx")
	fmt.Println("  cfm webtop top 20 rt")
        fmt.Println("  cfm webtop long [N]             # long-window top by score (no minScore)")
        fmt.Println("  cfm webtop ip [N]               # global IP view (top IPs by score)")
        fmt.Println("  cfm webtop ip <IP>              # drilldown specific IP")
        fmt.Println("  cfm webtop challenge            # active vhost challenge list")
        fmt.Println("  cfm webtop challenge host <H>   # vhost details + recent events")
        fmt.Println("  cfm webtop challenge events [N] # last N challenge events")
	fmt.Println("  cfm webtop analyze <ip|host>    # offline drilldown from TSV log")

	fmt.Println()
	fmt.Println("Sort keys: rps, 2xx, 3xx, 4xx, 5xx, uniq, err, rt, bot, ua_div, score")
        fmt.Println("------------")

}

// RunWebTop is the CLI entrypoint for `cfm webtop`.
// baseURL is something like "http://127.0.0.1:9070".
func RunWebTop(baseURL string, args []string) error {

    // 🔥 Offline analyze mode: cfm webtop analyze <ip>|<host>
    if len(args) > 0 && args[0] == "analyze" {
        if len(args) < 2 {
            return fmt.Errorf("usage: cfm webtop analyze <ip|host>")
        }
        target := args[1]

        // Πρώτα δοκιμάζουμε αν μοιάζει για IP.
        if net.ParseIP(target) != nil {
            return runAnalyzeIP(baseURL, target)
        }
        // consider it a  vhost
        return runAnalyzeHost(baseURL, target)
    }



    // Ειδικά modes: IP-top (hot / ip-top) & long window
    if len(args) > 0 {
        switch args[0] {
        case "hot", "ip-top":
            limit := 20
            if len(args) > 1 {
                if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
                    limit = n
                } else {
                    return fmt.Errorf("invalid IP limit: %s", args[1])
                }
            }
            return runIPTop(baseURL, limit)

        case "long":
            limit := 20
            if len(args) > 1 {
                if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
                    limit = n
                } else {
                    return fmt.Errorf("invalid long limit: %s", args[1])
                }
            }
            return runLongTop(baseURL, limit)

        case "challenge":
            // cfm webtop challenge
            // cfm webtop challenge host <H>
            // cfm webtop challenge events [N]
            return runChallengeWebTop(baseURL, args[1:])

        }
    }

    // Ειδικό mode: IP (aliases: ip, ips)
    // ip / ips χωρίς δεύτερο arg → IP-top default 20
    // ip / ips + αριθμός        → IP-top με limit
    // ip / ips + κάτι άλλο      → drilldown για αυτή την IP
    if len(args) > 0 && (args[0] == "ip" || args[0] == "ips") {
        if len(args) == 1 {
            // cfm webtop ip  → IP-top (όπως πριν)
            return runIPTop(baseURL, 20)
        }

        // δοκίμασε αν είναι αριθμός (limit)
        if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
            return runIPTop(baseURL, n)
        }

        // αλλιώς θεώρησέ το ως IP για drilldown
        return runIPDrilldown(baseURL, args[1])
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



func runIPTop(baseURL string, limit int) error {
        u := fmt.Sprintf("%s/api/v1/webdet/ip-short?limit=%d", baseURL, limit)
        resp, err := http.Get(u)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        var payload ipShortCLIResponse
        if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
                return err
        }

        rowsShort := payload.Short
        rowsLong  := payload.Long

        if limit > 0 {
                if len(rowsShort) > limit {
                        rowsShort = rowsShort[:limit]
                }
                if len(rowsLong) > limit {
                        rowsLong = rowsLong[:limit]
                }
        }

        fmt.Printf("[webtop ip] short window=%.0fs, long horizon≈%.0fs (top %d by ip_score)\n",
                payload.WindowSec, payload.LongHorizonSec, limit)

        // ---- Short window πίνακας ----
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        fmt.Fprintln(w, "IP\tSCORE\tRPS\txReqs\tvhosts\tPTR\tASN\tCC\tREASONS\tACTION")

        for _, r := range rowsShort {
                asField := ""
                if r.ASN != "" {
                        asField = "AS" + r.ASN
                        if r.ASNName != "" {
                                asField += " " + r.ASNName
                        }
                }

                cc := r.Country

                action := "-"
                if len(r.Proposals) > 0 {
                        p := r.Proposals[0]
                        if p.TTLSeconds > 0 {
                                action = fmt.Sprintf("%s(%ds)", p.Action, p.TTLSeconds)
                        } else {
                                action = p.Action
                        }
                }

                fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
                        r.IP,
                        r.Score,
                        r.RPS,
                        r.Req,
                        r.Vhosts,
                        r.PTR,
                        asField,
                        cc,
                        joinReasons(r.Reasons),
                        action,
                )
        }
        w.Flush()

        // ---- Long window πίνακας (αν έχουμε) ----
        if len(rowsLong) > 0 {
                fmt.Println()
                fmt.Println("---- IP long window (EMA over long horizon) ----")
                w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
                fmt.Fprintln(w2, "IP\tSCORE\tRPS\txReqs\tvhosts\tPTR\tASN\tCC\tREASONS\tACTION")

                for _, r := range rowsLong {
                        asField := ""
                        if r.ASN != "" {
                                asField = "AS" + r.ASN
                                if r.ASNName != "" {
                                        asField += " " + r.ASNName
                                }
                        }

                        cc := r.Country

                        action := "-"
                        if len(r.Proposals) > 0 {
                                p := r.Proposals[0]
                                if p.TTLSeconds > 0 {
                                        action = fmt.Sprintf("%s(%ds)", p.Action, p.TTLSeconds)
                                } else {
                                        action = p.Action
                                }
                        }

                        fmt.Fprintf(w2, "%s\t%.2f\t%.2f\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
                                r.IP,
                                r.Score,
                                r.RPS,
                                r.Req,
                                r.Vhosts,
                                r.PTR,
                                asField,
                                cc,
                                joinReasons(r.Reasons),
                                action,
                        )
                }
                w2.Flush()
        }

        return nil
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


        // Feature dump για ML / debug
        fmt.Printf("  features: median_ip_rps=%.3f bytes_rps=%.1f hot_ips=%d ip_skew=%.2f failure_idx=%.2f ua_entropy=%.2f path_entropy=%.2f\n",
                short.MedianPerIPRPS,
                short.BytesRPS,
                short.HotIPs,
                short.IPSkew,
                short.FailureIndex,
                short.UAEntropy,
                short.PathEntropy,
        )



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

// shortReason χαρτογραφεί τα verbose reason IDs σε πιο μικρά labels για CLI.
func shortReason(r string) string {
        switch r {
        case "auth401_bruteforce_like":
                return "401_brute"
        case "high_error_ratio":
                return "high_err"
        case "many_bot_user_agents":
                return "bot_UA"
        case "post_heavy_login_abuse_like":
                return "POST_abuse"
        default:
                return r
        }
}

// joinReasons: dedup + χρήση shortReason ώστε τα reasons να είναι μικρά και χωρίς διπλά.
func joinReasons(rs []string) string {
        if len(rs) == 0 {
            return "-"
        }
        seen := make(map[string]struct{})
        out := make([]string, 0, len(rs))
        for _, r := range rs {
                s := shortReason(r)
                if _, ok := seen[s]; ok {
                        continue
                }
                seen[s] = struct{}{}
                out = append(out, s)
        }
        return strings.Join(out, ",")
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

fmt.Fprintln(w2, "HOST\tSCORE\tREASONS\tRPS\t3xx\t4xx\t5xx\tuniqIP\terr%\tauth401%\thotIPs\tbot%\tua_div\tpath_div\tpost%")
for _, s := range sus {
    fmt.Fprintf(w2, "%s\t%.2f\t%s\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\t%.1f\t%d\t%.1f\t%.3f\t%.3f\t%.1f\n",
        s.Host,
        s.Score,
        joinReasons(s.Reasons),
        s.RPS,
        s.R3xx,
        s.R4xx,
        s.R5xx,
        s.UniqueIPs,
        s.ErrRatio*100,
        s.Auth401Ratio*100,
        s.HotIPs,
        s.BotRatio*100,
        s.UADiversity,
        s.PathDiversity,
        s.PostRatio*100,
    )
		}
		w2.Flush()
	}
	return nil
}



// runIPDrilldown καλεί /ip-drilldown και τυπώνει per-IP σύνοψη.
func runIPDrilldown(baseURL, ip string) error {
    u := fmt.Sprintf("%s/api/v1/webdet/ip-drilldown?ip=%s", baseURL, url.QueryEscape(ip))
    resp, err := http.Get(u)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var d IPDetail
    if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
        return err
    }


fmt.Printf("[ip %s] window=%.0fs total=%d vhosts=%d rps=%.2f\n",
    d.IP, d.WindowSec, d.Req, d.Vhosts, d.RPS)

if d.LongHorizonSec > 0 && d.LongReq > 0 {
    fmt.Printf("  long: horizon≈%.0fs total≈%d vhosts≈%d rps≈%.2f score=%.2f reasons=%s\n",
        d.LongHorizonSec,
        d.LongReq,
        d.LongVhosts,
        d.LongRPS,
        d.LongScore,
        joinReasons(d.LongReasons),
    )
} else if d.LongHorizonSec > 0 {
    fmt.Printf("  long: horizon≈%.0fs (no EMA traffic yet for this IP)\n", d.LongHorizonSec)
}



    if d.PTR != "" || d.ASN != "" || d.ASNName != "" || d.Country != "" {
        asField := d.ASN
        if asField != "" && !strings.HasPrefix(asField, "AS") {
            asField = "AS" + asField
        }

        parts := make([]string, 0, 3)
        if d.PTR != "" {
            parts = append(parts, d.PTR)
        }
        if asField != "" || d.ASNName != "" {
            parts = append(parts, strings.TrimSpace(asField+" "+d.ASNName))
        }
        if d.Country != "" {
            parts = append(parts, d.Country)
        }

        if len(parts) > 0 {
            fmt.Println("  " + strings.Join(parts, "  "))
        }
    }

    if len(d.Hosts) > 0 {
        fmt.Println("Top vhosts:")
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        fmt.Fprintln(w, "VHOST\txReqs\t%")
        for _, kv := range d.Hosts {
            pct := 0.0
            if d.Req > 0 {
                pct = 100 * float64(kv.Count) / float64(d.Req)
            }
            fmt.Fprintf(w, "%s\t%d\t%.1f\n", kv.Key, kv.Count, pct)
        }
        w.Flush()
    }

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



// runAnalyzeIP καλεί το /analyze-ip (offline log scan) και τυπώνει vhost breakdown.
func runAnalyzeIP(baseURL, ip string) error {
    u := fmt.Sprintf("%s/api/v1/webdet/analyze-ip?ip=%s", baseURL, url.QueryEscape(ip))
    resp, err := http.Get(u)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        var msg map[string]string
        _ = json.NewDecoder(resp.Body).Decode(&msg)
        if e, ok := msg["error"]; ok && e != "" {
            return fmt.Errorf("analyze-ip error: %s", e)
        }
        return fmt.Errorf("analyze-ip HTTP %s", resp.Status)
    }

    var res AnalyzeIPResult
    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return err
    }

    f, l := formatAnalyzeRange(res.FirstTS, res.LastTS)

    fmt.Printf("[analyze ip %s] total=%d vhosts=%d\n", res.IP, res.TotalReq, len(res.VhostCnt))
    fmt.Printf("  range: %s  →  %s (from TSV log)\n", f, l)

    if len(res.VhostCnt) == 0 {
        fmt.Println("  (no matches in log)")
        return nil
    }

    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "VHOST\txReqs")
    for _, kv := range res.VhostCnt {
        fmt.Fprintf(w, "%s\t%d\n", kv.Key, kv.Count)
    }
    w.Flush()

    return nil
}

// runAnalyzeHost καλεί το /analyze-host (offline log scan) και τυπώνει IP breakdown.
func runAnalyzeHost(baseURL, host string) error {
    u := fmt.Sprintf("%s/api/v1/webdet/analyze-host?host=%s", baseURL, url.QueryEscape(host))
    resp, err := http.Get(u)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        var msg map[string]string
        _ = json.NewDecoder(resp.Body).Decode(&msg)
        if e, ok := msg["error"]; ok && e != "" {
            return fmt.Errorf("analyze-host error: %s", e)
        }
        return fmt.Errorf("analyze-host HTTP %s", resp.Status)
    }

    var res AnalyzeHostResult
    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return err
    }

    f, l := formatAnalyzeRange(res.FirstTS, res.LastTS)

    fmt.Printf("[analyze host %s] total=%d ips=%d\n", res.Host, res.TotalReq, len(res.IPCnt))
    fmt.Printf("  range: %s  →  %s (from TSV log)\n", f, l)

    if len(res.IPCnt) == 0 {
        fmt.Println("  (no matches in log)")
        return nil
    }


   // 🔥 Αν έχουμε enrichment, δείξε view τύπου "Top IPs" με PTR/ASN/CC.
    if len(res.EnrichedIPs) > 0 {
        fmt.Println("Top IPs:")

        for i, row := range res.EnrichedIPs {
            ip := row["ip"]
            count := row["count"]
            ptr := row["ptr"]
            asn := row["asn"]
            asnNm := row["asn_name"]
            cc := row["country"]

            n, _ := strconv.Atoi(count)

            parts := make([]string, 0, 3)
            if ptr != "" {
                parts = append(parts, ptr)
            }
            if asn != "" || asnNm != "" {
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

        return nil
    }

    // Fallback: παλιό απλό table IP + xReqs
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "IP\txReqs")
    for _, kv := range res.IPCnt {
        fmt.Fprintf(w, "%s\t%d\n", kv.Key, kv.Count)
    }
    w.Flush()

    return nil
}

// ---------------- Challenge webtop ----------------

type chalSummaryResp struct {
    Now string `json:"now"`
    ActiveVhosts int `json:"active_vhosts"`
    ActiveIPs int `json:"active_ips"`
}

type chalVhost struct {
    Host string `json:"host"`
    Status string `json:"status"`
    Mode string `json:"mode"`
    Since string `json:"since"`
    Score float64 `json:"score"`
    UniqIP int `json:"uniq_ip"`
    RPS float64 `json:"rps"`
    Reasons []string `json:"reasons"`
    LastAction string `json:"last_action"`
}

type chalEvent struct {
    Ts string `json:"ts"`
    Type string `json:"type"`
    Host string `json:"host,omitempty"`
    IP string `json:"ip,omitempty"`
    Rule string `json:"rule,omitempty"`
    Score float64 `json:"score,omitempty"`
    UniqIP int `json:"uniq_ip,omitempty"`
    RPS float64 `json:"rps,omitempty"`
}

func runChallengeWebTop(baseURL string, args []string) error {
    // subcommands
    if len(args) > 0 && args[0] == "events" {
        limit := 50
        if len(args) > 1 {
            if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
                limit = n
            } else {
                return fmt.Errorf("invalid events limit: %s", args[1])
            }
        }
        u := fmt.Sprintf("%s/api/v1/challenge/events?limit=%d", strings.TrimRight(baseURL, "/"), limit)
        resp, err := http.Get(u)
        if err != nil { return err }
        defer resp.Body.Close()
        var ev []chalEvent
        if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil { return err }
        for _, e := range ev {
            fmt.Printf("%s %-18s host=%s ip=%s rule=%s score=%.2f uniq=%d rps=%.2f\n",
                e.Ts, e.Type, e.Host, e.IP, e.Rule, e.Score, e.UniqIP, e.RPS)
        }
        return nil
    }

    if len(args) > 1 && args[0] == "host" {
        host := args[1]
        base := strings.TrimRight(baseURL, "/")
        u1 := fmt.Sprintf("%s/api/v1/challenge/vhost?host=%s", base, url.QueryEscape(host))
        u2 := fmt.Sprintf("%s/api/v1/challenge/events?host=%s&limit=50", base, url.QueryEscape(host))

        r1, err := http.Get(u1); if err != nil { return err }
        defer r1.Body.Close()
        var vh chalVhost
        if err := json.NewDecoder(r1.Body).Decode(&vh); err != nil { return err }

        fmt.Printf("VHOST: %s  status=%s mode=%s since=%s score=%.2f uniqIP=%d rps=%.2f action=%s\n",
            vh.Host, vh.Status, vh.Mode, vh.Since, vh.Score, vh.UniqIP, vh.RPS, vh.LastAction)
        if len(vh.Reasons) > 0 {
            fmt.Printf("Reasons: %s\n", strings.Join(vh.Reasons, ","))
        }

        r2, err := http.Get(u2); if err != nil { return err }
        defer r2.Body.Close()
        var ev []chalEvent
        if err := json.NewDecoder(r2.Body).Decode(&ev); err != nil { return err }
        fmt.Println("Recent events:")
        for _, e := range ev {
            fmt.Printf("  %s %-18s ip=%s rule=%s score=%.2f uniq=%d rps=%.2f\n",
                e.Ts, e.Type, e.IP, e.Rule, e.Score, e.UniqIP, e.RPS)
        }
        return nil
    }

    // default: list active vhosts
    base := strings.TrimRight(baseURL, "/")
    u := fmt.Sprintf("%s/api/v1/challenge/vhosts?status=active&limit=200", base)
    r, err := http.Get(u)
    if err != nil { return err }
    defer r.Body.Close()
    var vhs []chalVhost
    if err := json.NewDecoder(r.Body).Decode(&vhs); err != nil { return err }

    fmt.Printf("%-35s %-6s %-6s %-5s %-6s %-s\n", "HOST", "MODE", "STAT", "SCORE", "UNIQ", "REASONS")
    for _, h := range vhs {
        rs := ""
        if len(h.Reasons) > 0 { rs = strings.Join(h.Reasons, ",") }
        fmt.Printf("%-35s %-6s %-6s %5.2f %6d  %s\n", h.Host, h.Mode, h.Status, h.Score, h.UniqIP, rs)
    }
    return nil
}
