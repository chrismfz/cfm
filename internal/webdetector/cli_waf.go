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
	default:
		return fmt.Errorf("unknown waf subcommand %q\nusage: cfm webtop waf [set|clear|status|profiles]", args[0])
	}
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

	host    := args[0]
	profile := args[1]
	ttl     := "1h"

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
