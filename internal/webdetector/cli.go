// internal/webdetector/cli.go
package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"
	"strings"
	"strconv"
)

// topShortCLIResponse ταιριάζει με το JSON που γυρίζει το /top-short.
type topShortCLIResponse struct {
        WindowSec      float64    `json:"window_sec"`
        LongHorizonSec float64    `json:"long_horizon_sec"`
        Rows           []ShortRow `json:"rows"`


}


// RunWebTop is the CLI entrypoint for `cfm webtop`.
// baseURL is something like "http://127.0.0.1:9070".
func RunWebTop(baseURL string, args []string) error {
	if len(args) == 0 {
		return runTopSummary(baseURL)
	}
	host := args[0]
	return runTopDrilldown(baseURL, host)
}

func runTopSummary(baseURL string) error {
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

        // Header με configured short window + long horizon (μεγαλό παράθυρο).
        fmt.Printf("[webtop] short window=%.0fs, long horizon≈%.0fs\n",
                payload.WindowSec, payload.LongHorizonSec)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
fmt.Fprintln(w, "HOST\tRPS\t2xx\t3xx\t4xx\t5xx\t401\t403\t404\t499\tuniqIP\terr%\trt_avg")



        // Συγκεντρωτικά totals για όλο τον server.
	var totRPS, tot2xx, tot3xx, tot4xx, tot5xx, tot401, tot403, tot404, tot499 float64
        var totUniq int
        var rtNum, rtDen float64

        for _, r := range rows {



fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\t%.3f\n",
    r.Host,
    r.RPS,
    r.R2xx,
    r.R3xx,
    r.R4xx,
    r.R5xx,
    r.R401,
    r.R403,
    r.R404,
    r.R499,
    r.UniqueIPs,
    r.ErrRatio*100,
    r.ProcAvgSec,
)



                // totals: RPS και κλάσεις ως άθροισμα RPS.
                totRPS  += r.RPS
                tot2xx  += r.R2xx
                tot3xx  += r.R3xx
                tot4xx  += r.R4xx
                tot5xx  += r.R5xx
                tot401  += r.R401
		tot403 += r.R403
		tot404 += r.R404
                tot499  += r.R499
                totUniq += r.UniqueIPs // approx, όχι πραγματικά unique set

                // weighted rt_avg: βάρος ~ RPS (ίδιο short window για όλους).
                if r.RPS > 0 && r.ProcAvgSec > 0 {
                        rtNum += r.ProcAvgSec * r.RPS
                        rtDen += r.RPS
                }
        }

        if len(rows) > 0 {
                errPct := 0.0
                if totRPS > 0 {
                        errPct = (tot4xx + tot5xx + tot499) / totRPS * 100.0
                }
                rtAvg := 0.0
                if rtDen > 0 {
                        rtAvg = rtNum / rtDen
                }

fmt.Fprintf(
    w,
    "TOTAL\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%d\t%.1f\t%.3f\n",
    totRPS, tot2xx, tot3xx, tot4xx, tot5xx,
    tot401, tot403, tot404, tot499,
    totUniq, errPct, rtAvg,
)

        }







	w.Flush()

	// Suspicious block (long window)
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
				s.Host, s.Score, joinReasons(s.Reasons), s.RPS, s.R3xx, s.R4xx, s.R5xx,
				s.UniqueIPs, s.ErrRatio*100)
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


        fmt.Printf("[%s] window=%.0fs total=%d direct=%.1f%% bots=%.1f%% rt_avg=%.3fs\n",
                short.Host, short.WindowSec, short.TotalReq, short.DirectPct, short.BotPct, short.ProcAvgSec)

        fmt.Println("Top IPs:")

        // Αν έχουμε enrichment, χρησιμοποιούμε το enriched view (όπως στο παλιό httpd-top).
        if len(short.EnrichedTopIPs) > 0 {
                for i, row := range short.EnrichedTopIPs {
                        ip    := row["ip"]
                        count := row["count"]
                        ptr   := row["ptr"]
                        asn   := row["asn"]      // π.χ. "216285"
                        asnNm := row["asn_name"] // π.χ. "Myip Networks G.p."
                        cc    := row["country"]  // π.χ. "GR"

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
