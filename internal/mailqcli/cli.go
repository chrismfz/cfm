// Package mailqcli is the `cfm mailtop` CLI: a human-readable render of the
// MTA-agnostic mail-queue report the active queue detector publishes. It reads
// GET /api/v1/system/mail-queue over clihttp — the same report the
// mail_queue_summary MCP tool and the WebUI use, with zero extra MTA probe.
package mailqcli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"cfm/internal/clihttp"
	"cfm/internal/mailqueue"
)

// resp mirrors the handler envelope in handleSystemMailQueue.
type resp struct {
	OK        bool             `json:"ok"`
	Schema    string           `json:"schema"`
	Available bool             `json:"available"`
	Note      string           `json:"note"`
	Report    mailqueue.Report `json:"report"`
}

// Run is the entrypoint for `cfm mailtop [--json]`.
func Run(baseURL string, args []string) error {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "help", "-h", "--help":
			printHelp()
			return nil
		}
	}

	url := strings.TrimRight(baseURL, "/") + "/api/v1/system/mail-queue"
	httpResp, err := clihttp.Get(url)
	if err != nil {
		return fmt.Errorf("mailtop: cannot reach %s: %w\n(is cfm daemon running?)", url, err)
	}
	defer httpResp.Body.Close()

	if asJSON {
		// Stream the raw body straight through for scripting.
		var raw json.RawMessage
		if err := json.NewDecoder(httpResp.Body).Decode(&raw); err != nil {
			return fmt.Errorf("mailtop: decode: %w", err)
		}
		fmt.Println(string(raw))
		return nil
	}

	var r resp
	if err := json.NewDecoder(httpResp.Body).Decode(&r); err != nil {
		return fmt.Errorf("mailtop: decode: %w", err)
	}
	if !r.Available {
		note := r.Note
		if note == "" {
			note = "no mail-queue report yet"
		}
		fmt.Printf("[mailtop] %s\n", note)
		return nil
	}
	render(r.Report)
	return nil
}

func render(rep mailqueue.Report) {
	when := rep.MeasuredAt.Local().Format("15:04:05")
	fmt.Printf("[mailtop] %s  mta=%s  total=%d  frozen=%d  deferred=%d",
		when, rep.MTA, rep.Total, rep.Frozen, rep.Deferred)
	if rep.Truncated {
		fmt.Printf("  (parsed %d — listing truncated)", rep.Parsed)
	}
	fmt.Println()

	if rep.Total == 0 {
		fmt.Println("  queue is empty")
		return
	}

	// Age distribution, in chronological bucket order.
	order := []string{"<10m", "10m-1h", "1h-6h", "6h-1d", ">1d"}
	fmt.Print("\nAGE:  ")
	for _, k := range order {
		fmt.Printf("%s=%d  ", k, rep.AgeBuckets[k])
	}
	fmt.Println()

	if len(rep.TopSenderDomains) > 0 {
		fmt.Println("\nTOP SENDER DOMAINS")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, d := range rep.TopSenderDomains {
			fmt.Fprintf(w, "  %s\t%d\n", d.Domain, d.Count)
		}
		w.Flush()
	}
	if len(rep.TopRecipientDomains) > 0 {
		fmt.Println("\nTOP RECIPIENT DOMAINS")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, d := range rep.TopRecipientDomains {
			fmt.Fprintf(w, "  %s\t%d\n", d.Domain, d.Count)
		}
		w.Flush()
	}

	if len(rep.DeferReasons) > 0 {
		fmt.Println("\nTOP DEFER / FREEZE REASONS")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  COUNT\tCATEGORY\tREASON")
		for _, d := range rep.DeferReasons {
			fmt.Fprintf(w, "  %d\t%s\t%s\n", d.Count, d.Category, truncate(d.Reason, 90))
		}
		w.Flush()
	}

	if len(rep.Oldest) > 0 {
		fmt.Println("\nOLDEST MESSAGES")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  AGE\tSIZE\tFROZEN\tSENDER\tRCPTS\tID")
		for _, m := range rep.Oldest {
			frozen := ""
			if m.Frozen {
				frozen = "❄"
			}
			sender := m.Sender
			if sender == "" {
				sender = "<>"
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%d\t%s\n",
				formatAge(m.AgeSec), formatSize(m.SizeBytes), frozen,
				truncate(sender, 40), m.Recipients, m.ID)
		}
		w.Flush()
	}
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm mailtop           # mail-queue breakdown (age / top domains / defer reasons / oldest)")
	fmt.Println("  cfm mailtop --json    # raw JSON (GET /api/v1/system/mail-queue)")
	fmt.Println()
	fmt.Println("Reads the report the active queue detector (exim_queues / postfix_queues)")
	fmt.Println("publishes each poll — no extra MTA probe. Empty if neither detector is enabled.")
}

func formatAge(secs int64) string {
	if secs <= 0 {
		return "0s"
	}
	d := time.Duration(secs) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", secs)
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", d.Minutes())
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	default:
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}

func formatSize(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fM", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1fK", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
