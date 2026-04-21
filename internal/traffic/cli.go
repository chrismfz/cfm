package traffic

import (
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"golang.org/x/term"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type summaryResp struct {
	Totals TotalsSnapshot `json:"totals"`
}

type rowsResp[T any] struct {
	Rows []T `json:"rows"`
}

func RunCLI(baseURL string, args []string) error {
	if len(args) == 0 {
		if isTTY() {
			return runLive(baseURL)
		}
		return runSummary(baseURL)
	}

	if args[0] == "--json" {
		return runJSON(baseURL)
	}

	switch args[0] {
	case "live":
		if !isTTY() {
			return runSummary(baseURL)
		}
		return runLive(baseURL)
	case "summary":
		return runSummary(baseURL)
	case "top":
		return runTop(baseURL, args[1:])
	case "conn":
		n := 20
		if len(args) > 1 {
			v, err := strconv.Atoi(args[1])
			if err != nil || v <= 0 {
				return fmt.Errorf("usage: cfm traffic conn [N]")
			}
			n = v
		}
		return runConn(baseURL, n)
	case "--help", "-h", "help":
		printTrafficHelp()
		return nil
	default:
		return fmt.Errorf("unknown traffic subcommand: %s", args[0])
	}
}

func printTrafficHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm traffic                      # live UI when TTY, summary in non-TTY")
	fmt.Println("  cfm traffic live")
	fmt.Println("  cfm traffic summary")
	fmt.Println("  cfm traffic top ips|processes|ports|protocols [N]")
	fmt.Println("  cfm traffic conn [N]")
	fmt.Println("  cfm traffic --json")
}

func runSummary(baseURL string) error {
	var s summaryResp
	if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/summary", &s); err != nil {
		return err
	}
	fmt.Printf("[traffic] in=%s out=%s active=%d\n", formatMbps(s.Totals.InBPS), formatMbps(s.Totals.OutBPS), s.Totals.ActiveConnections)
	fmt.Printf("bytes in=%s out=%s\n", formatBytes(s.Totals.InBytes), formatBytes(s.Totals.OutBytes))

	fmt.Println("\nTop processes:")
	if err := runTop(baseURL, []string{"processes", "10"}); err != nil {
		return err
	}
	fmt.Println("\nTop IPs:")
	if err := runTop(baseURL, []string{"ips", "10"}); err != nil {
		return err
	}
	return nil
}

func runTop(baseURL string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cfm traffic top ips|processes|ports|protocols [N]")
	}
	n := 20
	if len(args) > 1 {
		v, err := strconv.Atoi(args[1])
		if err != nil || v <= 0 {
			return fmt.Errorf("usage: cfm traffic top ips|processes|ports|protocols [N]")
		}
		n = v
	}
	switch args[0] {
	case "ips":
		var out rowsResp[IPSnapshot]
		if err := fetchTrafficJSON(baseURL, fmt.Sprintf("/api/v1/traffic/top-ips?limit=%d", n), &out); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IP\tASN\tPTR\tCONNS\tIN\tOUT")
		cache := map[string]string{}
		for _, r := range out.Rows {
			ptr := lookupPTR(r.IP, cache)
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n", r.IP, asnLabel(r.IP), ptr, r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}
		w.Flush()
	case "processes":
		var out rowsResp[ProcessBucketSnapshot]
		if err := fetchTrafficJSON(baseURL, fmt.Sprintf("/api/v1/traffic/top-processes?limit=%d", n), &out); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROCESS\tCONNS\tIN\tOUT")
		for _, r := range out.Rows {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", r.Bucket, r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}
		w.Flush()
	case "ports":
		var out rowsResp[PortSnapshot]
		if err := fetchTrafficJSON(baseURL, fmt.Sprintf("/api/v1/traffic/top-ports?limit=%d", n), &out); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PORT\tPROTO\tCONNS\tIN\tOUT")
		for _, r := range out.Rows {
			fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\n", r.Port, r.Protocol, r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}
		w.Flush()
	case "protocols":
		var out rowsResp[ProtocolSnapshot]
		if err := fetchTrafficJSON(baseURL, fmt.Sprintf("/api/v1/traffic/protocols?limit=%d", n), &out); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROTO\tCONNS\tIN\tOUT")
		for _, r := range out.Rows {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", r.Protocol, r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}
		w.Flush()
	default:
		return fmt.Errorf("usage: cfm traffic top ips|processes|ports|protocols [N]")
	}
	return nil
}

func runConn(baseURL string, n int) error {
	var out rowsResp[FlowSnapshot]
	if err := fetchTrafficJSON(baseURL, fmt.Sprintf("/api/v1/traffic/connections?limit=%d&sort=last_seen", n), &out); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROTO\tFLOW\tSRC\tDST\tPROC\tSTATE\tIN\tOUT")
	for _, r := range out.Rows {
		src := fmt.Sprintf("%s:%d", r.SrcIP, r.SrcPort)
		dst := fmt.Sprintf("%s:%d", r.DstIP, r.DstPort)
		proc := r.ProcessName
		if proc == "" {
			proc = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Protocol, short(r.FlowID, 16), src, dst, proc, r.State, formatMbps(r.InBPS), formatMbps(r.OutBPS))
	}
	w.Flush()
	return nil
}

func runJSON(baseURL string) error {
	payload := map[string]any{}
	paths := []string{"summary", "top-ips", "top-processes", "top-ports", "protocols", "connections"}
	for _, p := range paths {
		var out any
		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/"+p+"?limit=20", &out); err != nil {
			if p == "summary" {
				if err2 := fetchTrafficJSON(baseURL, "/api/v1/traffic/summary", &out); err2 != nil {
					return err2
				}
			}
		}
		payload[p] = out
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func runLive(baseURL string) error {
	ptrCache := map[string]string{}
	for {
		var sum summaryResp
		var procs rowsResp[ProcessBucketSnapshot]
		var ips rowsResp[IPSnapshot]
		var ports rowsResp[PortSnapshot]
		var protos rowsResp[ProtocolSnapshot]
		var flows rowsResp[FlowSnapshot]

		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/summary", &sum); err != nil {
			return err
		}
		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/top-processes?limit=8", &procs); err != nil {
			return err
		}
		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/top-ips?limit=8", &ips); err != nil {
			return err
		}
		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/top-ports?limit=8", &ports); err != nil {
			return err
		}
		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/protocols?limit=8", &protos); err != nil {
			return err
		}
		if err := fetchTrafficJSON(baseURL, "/api/v1/traffic/connections?limit=8&sort=last_seen", &flows); err != nil {
			return err
		}

		fmt.Print("\033[H\033[2J")
		fmt.Printf("cfm traffic live  in=%s  out=%s  active_conns=%d  %s\n\n",
			formatMbps(sum.Totals.InBPS), formatMbps(sum.Totals.OutBPS), sum.Totals.ActiveConnections, time.Now().Format("15:04:05"))

		fmt.Println("TOP PROCESSES")
		for _, r := range procs.Rows {
			fmt.Printf("  %-20s conn=%-4d in=%-9s out=%-9s\n", short(r.Bucket, 20), r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}

		fmt.Println("\nTOP IPs (ASN/PTR)")
		for _, r := range ips.Rows {
			ptr := lookupPTR(r.IP, ptrCache)
			fmt.Printf("  %-15s %-10s %-28s conn=%-4d in=%-8s out=%-8s\n", r.IP, asnLabel(r.IP), short(ptr, 28), r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}

		fmt.Println("\nTOP PORTS/PROTOCOLS")
		for _, r := range ports.Rows {
			fmt.Printf("  port %-5d %-4s conn=%-4d in=%-8s out=%-8s\n", r.Port, r.Protocol, r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}
		sortedP := append([]ProtocolSnapshot(nil), protos.Rows...)
		sort.Slice(sortedP, func(i, j int) bool { return sortedP[i].Connections > sortedP[j].Connections })
		for _, r := range sortedP {
			fmt.Printf("  proto %-7s conn=%-4d in=%-8s out=%-8s\n", r.Protocol, r.Connections, formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}

		fmt.Println("\nLIVE FLOWS")
		for _, r := range flows.Rows {
			fmt.Printf("  %-4s %-15s:%-5d -> %-15s:%-5d %-10s in=%-8s out=%-8s\n",
				r.Protocol, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, short(r.ProcessName, 10), formatMbps(r.InBPS), formatMbps(r.OutBPS))
		}

		time.Sleep(1 * time.Second)
	}
}

func fetchTrafficJSON(baseURL, path string, out any) error {
	u := strings.TrimRight(baseURL, "/") + path
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return fmt.Errorf("traffic api %s: %s (%v)", path, resp.Status, body["error"])
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func formatMbps(bps uint64) string {
	mbps := float64(bps) * 8 / 1_000_000
	return fmt.Sprintf("%.2fMbps", mbps)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func short(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func lookupPTR(ip string, cache map[string]string) string {
	if v, ok := cache[ip]; ok {
		return v
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		cache[ip] = "-"
		return "-"
	}
	ptr := strings.TrimSuffix(names[0], ".")
	cache[ip] = ptr
	return ptr
}

func asnLabel(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "-"
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return "private"
	}
	return "n/a"
}
