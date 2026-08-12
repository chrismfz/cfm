package lvecpu

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"cfm/internal/clihttp"
	"cfm/internal/lvestat"
)

// cliResponse mirrors the /api/v1/system/lve-cpu payload (handleSystemLVECPU).
// The three states are distinguished by available/ready: available=false on a
// non-CloudLinux host, ready=false while the collector warms up (needs two
// samples), and the full ranking otherwise.
type cliResponse struct {
	OK          bool                `json:"ok"`
	Available   bool                `json:"available"`
	Ready       bool                `json:"ready"`
	IntervalSec int                 `json:"interval_sec"`
	SampledAt   time.Time           `json:"sampled_at"`
	Tenants     int                 `json:"tenants"`
	Top         []lvestat.CPUSample `json:"top"`
	Error       string              `json:"error"`
}

// RunCLI is the entrypoint for `cfm lve` — the CloudLinux per-tenant CPU
// ranking (#30). It fetches the daemon's in-memory lvecpu snapshot and prints
// the hottest tenants (CPU cores + %-of-limit), hottest first.
//
//	cfm lve            # top 25 tenants by CPU
//	cfm lve top 50     # top 50
//	cfm lve --json     # raw JSON passthrough
func RunCLI(baseURL string, args []string) error {
	top := 25
	rawJSON := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			rawJSON = true
		case a == "top" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
				top = n
			}
			i++
		case a == "help" || a == "-h" || a == "--help":
			printLVEHelp()
			return nil
		default:
			// A bare number after no keyword is also accepted as the top-N.
			if n, err := strconv.Atoi(a); err == nil && n > 0 {
				top = n
			}
		}
	}

	url := strings.TrimRight(baseURL, "/") + "/api/v1/system/lve-cpu?top=" + strconv.Itoa(top)
	resp, err := clihttp.Get(url)
	if err != nil {
		return fmt.Errorf("lve: cannot reach %s: %w\n(is cfm daemon running?)", url, err)
	}
	defer resp.Body.Close()

	if rawJSON {
		// Stream the body straight through for scripting.
		var raw json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			return fmt.Errorf("lve: decode: %w", err)
		}
		b, _ := json.MarshalIndent(raw, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	var r cliResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("lve: decode: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !r.OK {
		msg := r.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("lve: %s", msg)
	}

	if !r.Available {
		fmt.Println("[lve] not a CloudLinux host (/proc/lve/list absent) — nothing to show")
		return nil
	}
	if !r.Ready {
		fmt.Printf("[lve] collector warming up — first CPU delta needs two samples (~%ds); try again shortly\n", r.IntervalSec)
		return nil
	}

	fmt.Printf("[lve] %s  tenants=%d  interval=%ds  (cores over last interval, hottest first)\n",
		r.SampledAt.Local().Format("15:04:05"), r.Tenants, r.IntervalSec)
	if len(r.Top) == 0 {
		fmt.Println("  (no tenants reported)")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RESELLER\tUID\tCORES\t%OF_LIMIT\tLIMIT\tNCPU\tEP\tNPROC")
	for _, s := range r.Top {
		fmt.Fprintf(w, "%d\t%d\t%.2f\t%s\t%s\t%d\t%d\t%d\n",
			s.Reseller, s.UID, s.Cores, pctOfLimit(s), limitCPU(s.LimitCPU), s.NumCPU, s.EP, s.NProc)
	}
	return w.Flush()
}

// pctOfLimit formats the %-of-limit with a throttle flag. lCPU==0 means the
// tenant is unlimited, so no percentage is meaningful.
func pctOfLimit(s lvestat.CPUSample) string {
	if s.LimitCPU <= 0 {
		return "-"
	}
	flag := ""
	switch {
	case s.PctOfLimit >= 90:
		flag = " 🔴"
	case s.PctOfLimit >= 70:
		flag = " 🟡"
	}
	return fmt.Sprintf("%.0f%%%s", s.PctOfLimit, flag)
}

// limitCPU renders the lCPU cap as cores (10000 units = 1 core); 0 = unlimited.
func limitCPU(l int64) string {
	if l <= 0 {
		return "∞"
	}
	return fmt.Sprintf("%.2gc", float64(l)/10000.0)
}

func printLVEHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm lve                # top 25 CloudLinux tenants by CPU (hottest first)")
	fmt.Println("  cfm lve top <N>        # top N tenants")
	fmt.Println("  cfm lve <N>            # shorthand for top N")
	fmt.Println("  cfm lve --json         # raw JSON passthrough")
	fmt.Println()
	fmt.Println("Columns: CORES = CPU cores consumed over the last sample interval;")
	fmt.Println("  %OF_LIMIT = cores as a share of the tenant's lCPU cap (100% = throttling,")
	fmt.Println("  🟡≥70% 🔴≥90%); LIMIT = lCPU cap in cores (∞ = unlimited).")
	fmt.Println()
	fmt.Println("CloudLinux only: on a non-CloudLinux host /proc/lve/list is absent and this")
	fmt.Println("reports nothing.")
}
