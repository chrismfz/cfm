// internal/webdetector/cli_bots.go
//
// `cfm bots` — box-wide UA emergency control surface.
//
// Subcommands:
//
//	cfm bots                         live two-pane termui (default)
//	cfm bots top   [N]               static top-N snapshot
//	cfm bots list                    active emergency rules
//	cfm bots drill <ua>              drilldown for one normalized UA
//	cfm bots block    <ua> [opts]    install block rule
//	cfm bots throttle <ua> [opts]    install throttle rule
//	cfm bots remove   <ua>           undo an active rule
//
// Options for install commands:
//
//	--ttl <duration>    rule TTL (default 30m, max 60m)
//	--reason <text>     free-form reason captured in audit log
//	--confirm           required when the UA is a verified Google crawler
//
// All commands talk to the existing webdetector HTTP API. Authentication is
// the same Bearer token that backs `cfm webtop`.
package webdetector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	clihttp "cfm/internal/clihttp"
)

// drainClose drains any unread bytes from a response body (bounded by
// BYTES and TIME) and then closes it. Required for HTTP/1.1 keep-alive
// reuse — Go's net/http only returns the underlying TCP connection to
// the idle pool when the body is read to EOF.
//
// Two bounds, both required:
//   - drainCap (256 KiB) caps memory if a misbehaving server sends a
//     massive body. Bodies larger than this lose keep-alive.
//   - drainTimeout (2s) caps wall time so a slowloris server trickling
//     bytes (below the cap, but indefinitely) can't hang the TUI.
//     clihttp uses http.DefaultClient with no body-read deadline, so
//     without this we'd block until the kernel TCP timeout fires.
//
// The drain runs in a goroutine so the timeout actually fires; Close()
// from the caller aborts the in-flight Read on the underlying conn.
const (
	drainCap     = 256 * 1024
	drainTimeout = 2 * time.Second
)

func drainClose(b io.ReadCloser) {
	if b == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.CopyN(io.Discard, b, drainCap)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		// Timeout. Close() below will abort the in-flight Read in the
		// drain goroutine, which then exits via the done channel that
		// nobody reads from. No leak — the goroutine returns once Close
		// unblocks the Read.
	}
	_ = b.Close()
}

// RunBots is the entry point used by cmd/cfm/main.go.
func RunBots(baseURL string, args []string) error {
	if len(args) == 0 {
		return runBotsLive(baseURL)
	}

	switch strings.ToLower(args[0]) {
	case "help", "-h", "--help":
		printBotsHelp()
		return nil

	case "top":
		limit := 20
		if len(args) >= 2 {
			if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
				limit = n
			}
		}
		return runBotsTopStatic(baseURL, limit)

	case "list":
		return runBotsList(baseURL)

	case "drill":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm bots drill <ua>")
		}
		return runBotsDrill(baseURL, args[1])

	case "block", "throttle":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm bots %s <ua> [--ttl 30m] [--reason ...] [--confirm]", args[0])
		}
		opts, err := parseBotsActionOpts(args[2:])
		if err != nil {
			return err
		}
		return runBotsInstall(baseURL, args[1], strings.ToLower(args[0]), opts)

	case "remove", "delete", "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm bots remove <ua>")
		}
		return runBotsRemove(baseURL, args[1])

	case "live":
		return runBotsLive(baseURL)
	}

	return fmt.Errorf("unknown subcommand %q (try: cfm bots help)", args[0])
}

func printBotsHelp() {
	fmt.Println("cfm bots — box-wide UA emergency control")
	fmt.Println()
	fmt.Println("  cfm bots                          # live two-pane TUI")
	fmt.Println("  cfm bots top [N]                  # static top-N snapshot")
	fmt.Println("  cfm bots list                     # show active emergency rules")
	fmt.Println("  cfm bots drill <ua>               # drilldown for one normalized UA")
	fmt.Println("  cfm bots block    <ua> [opts]     # install block rule")
	fmt.Println("  cfm bots throttle <ua> [opts]     # install throttle rule")
	fmt.Println("  cfm bots remove   <ua>            # undo an active rule")
	fmt.Println()
	fmt.Println("Options (install commands):")
	fmt.Println("  --ttl <duration>   default 30m, hard-capped at 60m")
	fmt.Println("  --reason <text>    free-form, captured in /var/log/cfm/ua_emergency.log")
	fmt.Println("  --confirm          required for verified Google crawlers")
	fmt.Println()
	fmt.Println("Note: per-UA request counts (RPS / Reqs / Vhosts) are always")
	fmt.Println("aggregated and visible. Unique-IP tracking is the heavier path,")
	fmt.Println("so it only activates while at least one emergency rule is")
	fmt.Println("installed — the IPS column shows 0 until then. Install any")
	fmt.Println("throttle or block rule (or a short throwaway observer rule) to")
	fmt.Println("see IP detail.")
}

// ── opts parsing ────────────────────────────────────────────────────────────

type botsActionOpts struct {
	TTL     time.Duration
	Reason  string
	Confirm bool
}

func parseBotsActionOpts(args []string) (botsActionOpts, error) {
	opts := botsActionOpts{TTL: 30 * time.Minute}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--ttl", "-t":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--ttl requires a value")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return opts, fmt.Errorf("invalid --ttl %q: %v", args[i+1], err)
			}
			opts.TTL = d
			i += 2
		case "--reason", "-r":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--reason requires a value")
			}
			opts.Reason = args[i+1]
			i += 2
		case "--confirm", "-y":
			opts.Confirm = true
			i++
		default:
			return opts, fmt.Errorf("unknown option %q", args[i])
		}
	}
	return opts, nil
}

// ── static views ────────────────────────────────────────────────────────────

func runBotsTopStatic(baseURL string, limit int) error {
	rows, err := fetchUATop(baseURL, limit)
	if err != nil {
		return err
	}
	rules, _ := fetchUAEmergencyList(baseURL) // best-effort

	fmt.Printf("[cfm bots top]   limit=%d   active_rules=%d\n", limit, len(rules))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "#\tUA\tRPS\tREQS\tIPS\tVHOSTS\tACTIVE_RULE")
	ruleByUA := indexRulesByUA(rules)
	for i, r := range rows {
		active := "-"
		if ar, ok := ruleByUA[r.UA]; ok {
			active = fmt.Sprintf("%s(%s left)", ar.Action, leftDuration(ar.ExpiresAt))
		}
		fmt.Fprintf(w, "%d\t%s\t%.2f\t%d\t%d\t%d\t%s\n",
			i+1, r.UA, r.RPS, r.Reqs, r.UniqueIPs, r.Vhosts, active)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	// Hint: when rules aren't installed and no drilldown observe window is
	// armed, the IPS column is always 0 (unique-IP tracking is gated to
	// keep memory down on idle boxes). Surface that so operators
	// understand why IPS is 0 in a row that shows RPS > 0.
	if len(rows) > 0 && len(rules) == 0 {
		fmt.Println()
		fmt.Println("  Note: IPS column may be 0 — IP tracking is armed by an active")
		fmt.Println("  emergency rule or by opening a UA drilldown (WebUI Web Bots")
		fmt.Println("  page, 10 min), e.g.:")
		fmt.Println("    cfm bots throttle <ua> --ttl 5m --reason observing")
	}
	return nil
}

func runBotsList(baseURL string) error {
	rules, err := fetchUAEmergencyList(baseURL)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Println("(no active emergency rules)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "UA\tACTION\tEXPIRES_IN\tHITS\tBY\tREASON")
	for _, r := range rules {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			r.UA, r.Action, leftDuration(r.ExpiresAt), r.Hits, r.CreatedBy, r.Reason)
	}
	return w.Flush()
}

func runBotsDrill(baseURL, ua string) error {
	u := fmt.Sprintf("%s/api/v1/webdet/ua-drill?ua=%s", baseURL, url.QueryEscape(ua))
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return httpStatusErr(resp)
	}
	var d UADetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return err
	}

	fmt.Printf("UA:            %s\n", d.UA)
	fmt.Printf("Window:        %.0fs\n", d.WindowSec)
	fmt.Printf("Requests:      %d\n", d.Reqs)
	fmt.Printf("RPS:           %.2f\n", d.RPS)
	fmt.Printf("Unique IPs:    %d\n", d.UniqueIPs)
	fmt.Printf("Vhosts:        %d\n\n", d.Vhosts)

	printTopKV("Top IPs", d.TopIPs)
	printTopKV("Top Vhosts", d.TopHosts)
	printTopKV("Raw UA variants", d.TopRawUAs)
	return nil
}

func printTopKV(title string, kvs []TopKV) {
	if len(kvs) == 0 {
		return
	}
	fmt.Printf("=== %s ===\n", title)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, kv := range kvs {
		fmt.Fprintf(w, "  %s\t%d\n", kv.Key, kv.Count)
	}
	w.Flush()
	fmt.Println()
}

// ── install / remove ────────────────────────────────────────────────────────

func runBotsInstall(baseURL, ua, action string, opts botsActionOpts) error {
	body := uaEmergencyPostBody{
		UA:         ua,
		Action:     action,
		TTLSeconds: int(opts.TTL.Seconds()),
		Reason:     opts.Reason,
		Confirm:    opts.Confirm,
	}
	data, _ := json.Marshal(body)
	resp, err := clihttp.Post(baseURL+"/api/v1/webdet/ua-emergency", "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)

	if resp.StatusCode == http.StatusConflict {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody["error"] == "google_verified_bot_requires_confirm" {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "  ⚠  %q is a verified Google crawler.\n", errBody["ua"])
			fmt.Fprintln(os.Stderr, "     Re-run with --confirm to proceed.")
			return fmt.Errorf("confirmation required")
		}
		return fmt.Errorf("conflict: %v", errBody)
	}
	if resp.StatusCode/100 != 2 {
		return httpStatusErr(resp)
	}
	var r UAEmergencyRule
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return err
	}
	fmt.Printf("✓ %s ua=%s ttl=%s expires=%s (by=%s)\n",
		r.Action, r.UA,
		r.ExpiresAt.Sub(r.CreatedAt).Round(time.Second),
		r.ExpiresAt.Local().Format("15:04:05"),
		r.CreatedBy)
	return nil
}

func runBotsRemove(baseURL, ua string) error {
	u := fmt.Sprintf("%s/api/v1/webdet/ua-emergency?ua=%s", baseURL, url.QueryEscape(ua))
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := clihttp.Do(req)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("(no active rule for %q)\n", NormalizeUA(ua))
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return httpStatusErr(resp)
	}
	var r UAEmergencyRule
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return err
	}
	fmt.Printf("✓ removed %s rule for ua=%s (was active for %s, %d hits)\n",
		r.Action, r.UA,
		time.Since(r.CreatedAt).Round(time.Second),
		r.Hits)
	return nil
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

func fetchUATop(baseURL string, limit int) ([]UATopRow, error) {
	u := fmt.Sprintf("%s/api/v1/webdet/ua-top?limit=%d", baseURL, limit)
	resp, err := clihttp.Get(u)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, httpStatusErr(resp)
	}
	var rows []UATopRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func fetchUAEmergencyList(baseURL string) ([]UAEmergencyRule, error) {
	resp, err := clihttp.Get(baseURL + "/api/v1/webdet/ua-emergency")
	if err != nil {
		return nil, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, httpStatusErr(resp)
	}
	var rules []UAEmergencyRule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func indexRulesByUA(rules []UAEmergencyRule) map[string]UAEmergencyRule {
	m := make(map[string]UAEmergencyRule, len(rules))
	for _, r := range rules {
		m[r.UA] = r
	}
	return m
}

func leftDuration(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		return "expired"
	}
	return d.Round(time.Second).String()
}

func httpStatusErr(resp *http.Response) error {
	// Read the whole (capped) body: a single Read can short-read a chunked or
	// >1-packet error payload and truncate the diagnostic — or return nothing
	// on a zero-length first read — which the callers that surface these errors
	// rely on being intact.
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	body := strings.TrimSpace(string(buf))
	if body == "" {
		return fmt.Errorf("http %s", resp.Status)
	}
	return fmt.Errorf("http %s: %s", resp.Status, body)
}
