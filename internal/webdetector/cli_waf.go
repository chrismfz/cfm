// internal/webdetector/cli_waf.go
//
// `cfm webtop waf` subcommand — WAF profile management from the CLI.
//
// Usage:
//   cfm webtop waf                                    # list active profiles
//   cfm webtop waf status <host>                      # profile for one vhost
//   cfm webtop waf set <host> <profile> [--ttl 1h]   # activate profile
//   cfm webtop waf clear <host>                       # back to defaults
//   cfm webtop waf profiles                           # show available profiles
//   cfm webtop waf engine [--hours 24 --limit 20 --top 10]  # WAF engine stats/events
//
// Profiles:  normal | attack | strict | off
//
// Add to RunWebTop() dispatch in cli.go:
//
//   case "waf":
//       return runWafWebTop(baseURL, args[1:])
//
// Add to printWebTopHelp():
//   fmt.Println("  cfm webtop waf                              # list active WAF profiles")
//   fmt.Println("  cfm webtop waf set <host> <profile> [--ttl 1h]")
//   fmt.Println("  cfm webtop waf clear <host>")
//   fmt.Println("  cfm webtop waf status <host>")
//   fmt.Println("  cfm webtop waf profiles                     # available profiles")

package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// runWafWebTop is the entry point for `cfm webtop waf [subcommand]`.
func runWafWebTop(baseURL string, args []string) error {
	if len(args) == 0 {
		return runWafList(baseURL)
	}
	switch args[0] {
	case "set", "activate", "enable":
		return runWafSet(baseURL, args[1:])
	case "clear", "remove", "rm", "reset":
		return runWafClear(baseURL, args[1:])
	case "status":
		return runWafStatus(baseURL, args[1:])
	case "profiles", "list-profiles":
		return runWafProfiles(baseURL)
	case "exclude":
		return runWAFExclude(baseURL, args[1:])
	case "engine", "summary", "stats":
		return runWAFEngineSummary(baseURL, args[1:])
	default:
		return fmt.Errorf("unknown waf subcommand %q\nusage: cfm webtop waf [set|clear|status|profiles|engine|exclude]", args[0])
	}
}

type wafEngineSummaryCLI struct {
	FromUnix      int64 `json:"from_unix"`
	ToUnix        int64 `json:"to_unix"`
	Hours         int   `json:"hours"`
	TotalEvents   int   `json:"total_events"`
	UniqueHosts   int   `json:"unique_hosts"`
	UniqueIPs     int   `json:"unique_ips"`
	BlockedEvents int   `json:"blocked_events"`
	TopRules      []struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	} `json:"top_rules"`
	TopRuleBases []struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	} `json:"top_rule_bases"`
	TopHosts []struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	} `json:"top_hosts"`
	TopIPs []struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	} `json:"top_ips"`
	Rows []struct {
		TsUnix  int64  `json:"ts_unix"`
		Host    string `json:"host"`
		IP      string `json:"ip"`
		URI     string `json:"uri"`
		Method  string `json:"method"`
		Status  int    `json:"status"`
		Reason  string `json:"reason"`
		Country string `json:"country"`
		ASN     uint   `json:"asn"`
	} `json:"rows"`
}

func runWAFEngineSummary(baseURL string, args []string) error {
	hours := 24
	limit := 20
	top := 10
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--hours" || a == "-h":
			if i+1 >= len(args) {
				return fmt.Errorf("--hours requires a value")
			}
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --hours: %s", args[i])
			}
			hours = v
		case strings.HasPrefix(a, "--hours="):
			v, err := strconv.Atoi(strings.TrimPrefix(a, "--hours="))
			if err != nil {
				return fmt.Errorf("invalid --hours: %s", a)
			}
			hours = v
		case a == "--limit" || a == "-n":
			if i+1 >= len(args) {
				return fmt.Errorf("--limit requires a value")
			}
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --limit: %s", args[i])
			}
			limit = v
		case strings.HasPrefix(a, "--limit="):
			v, err := strconv.Atoi(strings.TrimPrefix(a, "--limit="))
			if err != nil {
				return fmt.Errorf("invalid --limit: %s", a)
			}
			limit = v
		case a == "--top":
			if i+1 >= len(args) {
				return fmt.Errorf("--top requires a value")
			}
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --top: %s", args[i])
			}
			top = v
		case strings.HasPrefix(a, "--top="):
			v, err := strconv.Atoi(strings.TrimPrefix(a, "--top="))
			if err != nil {
				return fmt.Errorf("invalid --top: %s", a)
			}
			top = v
		default:
			return fmt.Errorf("usage: cfm webtop waf engine [--hours 24] [--limit 20] [--top 10]")
		}
	}
	if hours <= 0 {
		hours = 24
	}
	if limit <= 0 {
		limit = 20
	}
	if top <= 0 {
		top = 10
	}
	u := fmt.Sprintf("%s/api/v1/waf/engine/summary?hours=%d&limit=%d&top=%d", strings.TrimRight(baseURL, "/"), hours, limit, top)
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("waf engine summary HTTP %d", resp.StatusCode)
	}
	var out wafEngineSummaryCLI
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	fmt.Printf("WAF engine summary (%dh): total=%d blocked=%d unique_hosts=%d unique_ips=%d\n", out.Hours, out.TotalEvents, out.BlockedEvents, out.UniqueHosts, out.UniqueIPs)
	printTop := func(title string, rows []struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	}) {
		if len(rows) == 0 {
			return
		}
		fmt.Println(title)
		for i, row := range rows {
			fmt.Printf("  %2d) %-45s %d\n", i+1, row.Key, row.Count)
		}
	}
	printTop("Top rule families:", out.TopRuleBases)
	printTop("Top rules:", out.TopRules)
	printTop("Top hosts:", out.TopHosts)
	printTop("Top IPs:", out.TopIPs)
	if len(out.Rows) == 0 {
		fmt.Println("No WAF events in selected window.")
		return nil
	}
	fmt.Println("Recent WAF events:")
	fmt.Printf("%-19s %-28s %-15s %-6s %-4s %-28s %s\n", "TIME", "HOST", "IP", "METHOD", "ST", "RULE", "URI")
	for _, row := range out.Rows {
		ts := time.Unix(row.TsUnix, 0).Format("2006-01-02 15:04:05")
		host := row.Host
		if host == "" {
			host = "-"
		}
		uri := row.URI
		if len(uri) > 90 {
			uri = uri[:87] + "..."
		}
		rule := row.Reason
		if len(rule) > 28 {
			rule = rule[:25] + "..."
		}
		fmt.Printf("%-19s %-28s %-15s %-6s %-4d %-28s %s\n", ts, host, row.IP, row.Method, row.Status, rule, uri)
	}
	return nil
}

// ── cfm webtop waf  ───────────────────────────────────────────────────────────

func runWafList(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/waf/vhosts"
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var entries []struct {
		Host      string    `json:"host"`
		Profile   string    `json:"profile"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No active WAF profile overrides. All vhosts using default RULES.")
		return nil
	}

	fmt.Printf("%-40s %-10s  %s\n", "HOST", "PROFILE", "EXPIRES")
	fmt.Printf("%-40s %-10s  %s\n", strings.Repeat("-", 40), "----------", "-------------------")
	for _, e := range entries {
		remaining := time.Until(e.ExpiresAt).Round(time.Second)
		fmt.Printf("%-40s %-10s  %s (in %s)\n",
			e.Host, e.Profile,
			e.ExpiresAt.Format("2006-01-02 15:04:05"),
			remaining,
		)
	}
	return nil
}

// ── cfm webtop waf set <host> <profile> [--ttl 1h]  ─────────────────────────

func runWafSet(baseURL string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: cfm webtop waf set <host> <profile> [--ttl 1h]\nprofiles: normal | attack | strict | off")
	}

	host := args[0]
	profile := args[1]
	ttl := "1h"

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--ttl", "-t":
			if i+1 >= len(args) {
				return fmt.Errorf("--ttl requires a value")
			}
			ttl = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "--ttl=") {
				ttl = strings.TrimPrefix(args[i], "--ttl=")
			}
		}
	}

	u := fmt.Sprintf("%s/api/v1/waf/vhost/set?host=%s&profile=%s&ttl=%s",
		strings.TrimRight(baseURL, "/"),
		url.QueryEscape(host),
		url.QueryEscape(profile),
		url.QueryEscape(ttl),
	)
	resp, err := http.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("waf set error: %s", errMsg)
	}

	fmt.Printf("✓ WAF profile [%s] active for %s  ttl=%s  expires=%s\n",
		profile, host, ttl, result["expires_at"])
	return nil
}

// ── cfm webtop waf clear <host>  ─────────────────────────────────────────────

func runWafClear(baseURL string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cfm webtop waf clear <host>")
	}
	host := args[0]
	u := fmt.Sprintf("%s/api/v1/waf/vhost/clear?host=%s",
		strings.TrimRight(baseURL, "/"),
		url.QueryEscape(host),
	)
	resp, err := http.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("waf clear error: %s", errMsg)
	}
	fmt.Printf("✓ WAF profile cleared for %s — back to default RULES\n", host)
	return nil
}

// ── cfm webtop waf status <host>  ────────────────────────────────────────────

func runWafStatus(baseURL string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cfm webtop waf status <host>")
	}
	host := args[0]
	u := fmt.Sprintf("%s/api/v1/waf/vhost/status?host=%s",
		strings.TrimRight(baseURL, "/"),
		url.QueryEscape(host),
	)
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Host      string    `json:"host"`
		Profile   string    `json:"profile"`
		Active    bool      `json:"active"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	fmt.Printf("host: %s\n", result.Host)
	if result.Active {
		remaining := time.Until(result.ExpiresAt).Round(time.Second)
		fmt.Printf("  WAF profile: [%s]  active  expires=%s  (in %s)\n",
			result.Profile,
			result.ExpiresAt.Format("2006-01-02 15:04:05"),
			remaining,
		)
	} else {
		fmt.Printf("  WAF profile: none (using default RULES from cfm_waf.lua)\n")
	}
	return nil
}

// ── cfm webtop waf profiles  ─────────────────────────────────────────────────

func runWafProfiles(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/waf/profiles"
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var profiles []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profiles); err != nil {
		return err
	}

	fmt.Println("Available WAF profiles:")
	fmt.Println()
	for _, p := range profiles {
		fmt.Printf("  %-10s  %s\n", p.Name, p.Description)
	}
	fmt.Println()
	fmt.Println("Activate:  cfm webtop waf set <host> <profile> [--ttl 1h]")
	fmt.Println("Reset:     cfm webtop waf clear <host>")
	return nil
}

// ── Live dashboard [w] keybind ────────────────────────────────────────────────
//
// In live.go (RunLiveDrilldown), add a WAF profile cycle keybind.
//
// The profiles cycle in order: "" → attack → strict → off → normal → ""
// Each press advances one step and calls the set/clear API.
// The current profile is shown in the status bar alongside [c] challenge.
//
// Add to the liveSnapshot struct (or fetch from a separate API call):
//   WafProfile string
//
// Add to fetchLiveSnapshot:
//   wafStatus, _ := fetchWafStatus(baseURL, host)
//   snap.WafProfile = wafStatus
//
// Status bar update (replace the chalHint section):
//
//   wafProfiles := []string{"", "attack", "strict", "off", "normal"}
//   wafIdx := 0
//   for i, p := range wafProfiles { if p == snap.WafProfile { wafIdx = i; break } }
//   nextWaf := wafProfiles[(wafIdx+1) % len(wafProfiles)]
//   wafLabel := snap.WafProfile; if wafLabel == "" { wafLabel = "default" }
//   wafHint := fmt.Sprintf("[w] waf:%s→%s", wafLabel, nextWaf)
//   if nextWaf == "" { wafHint = fmt.Sprintf("[w] waf:%s→default", wafLabel) }
//
//   statusBar.Text = fmt.Sprintf(
//     " [q] quit  [r] refresh  [%s]  │  [%s]  │  %s  │  %s%s  │  tick #%d",
//     chalHint, wafHint, ipHint, ts, blockLine, tick,
//   )
//
// wafToggle function (alongside chalToggle):

// WafCycleNext returns the next profile in the rotation and calls the API.
// Call this from the live event loop when the user presses 'w'.
func wafCycleNext(baseURL, host, currentProfile string) error {
	cycle := []string{"", "attack", "strict", "off", "normal"}
	next := ""
	for i, p := range cycle {
		if p == currentProfile {
			next = cycle[(i+1)%len(cycle)]
			break
		}
	}

	if next == "" {
		// Clear: back to defaults
		u := fmt.Sprintf("%s/api/v1/waf/vhost/clear?host=%s",
			strings.TrimRight(baseURL, "/"), url.QueryEscape(host))
		_, err := http.Post(u, "application/json", nil)
		return err
	}

	u := fmt.Sprintf("%s/api/v1/waf/vhost/set?host=%s&profile=%s&ttl=1h",
		strings.TrimRight(baseURL, "/"),
		url.QueryEscape(host),
		url.QueryEscape(next),
	)
	_, err := http.Post(u, "application/json", nil)
	return err
}

// fetchWafProfile returns the active WAF profile for a vhost, or "".
func fetchWafProfile(baseURL, host string) string {
	u := fmt.Sprintf("%s/api/v1/waf/vhost/status?host=%s",
		strings.TrimRight(baseURL, "/"), url.QueryEscape(host))
	resp, err := http.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var result struct {
		Profile string `json:"profile"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.Profile
}
