// internal/webdetector/cli_http3.go
//
// `cfm webtop http3 ...` subcommand. Opt-in / opt-out individual vhosts
// for HTTP/3 (Alt-Svc advertisement). Default for every vhost is OFF.
//
// Subcommands:
//   list                      — show all opt-in vhosts
//   enable  <vhost>           — advertise Alt-Svc for vhost
//   disable <vhost>           — stop advertising Alt-Svc
//
// Aliases for enable: on, opt-in
// Aliases for disable: off, opt-out, remove, rm

package webdetector

import (
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

func runHTTP3WebTop(baseURL string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		return runHTTP3List(baseURL)
	}

	if len(args) < 2 {
		return fmt.Errorf("usage: cfm webtop http3 [list|enable <vhost>|disable <vhost>]")
	}

	action := args[0]
	host := strings.TrimSpace(args[1])
	if host == "" {
		return fmt.Errorf("missing vhost")
	}

	var endpoint string
	switch action {
	case "enable", "on", "opt-in":
		endpoint = "enable"
	case "disable", "off", "opt-out", "remove", "rm":
		endpoint = "disable"
	default:
		return fmt.Errorf("unknown http3 action %q (use list/enable/disable)", action)
	}

	q := url.Values{}
	q.Set("host", host)
	u := fmt.Sprintf("%s/api/v1/http3/%s?%s",
		strings.TrimRight(baseURL, "/"), endpoint, q.Encode())
	resp, err := clihttp.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Read body once so we can fall back to raw text when JSON decoding
	// fails (e.g. a reverse proxy returning HTML 502, or a plain-text
	// `forbidden\n` from http.Error). Prior versions printed "✓" on
	// non-JSON 4xx/5xx because the decode error was swallowed.
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http3 %s HTTP %d: %s", action, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("http3 %s: server returned non-JSON 2xx (%d bytes): %q", action, len(body), strings.TrimSpace(string(body)))
	}
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("http3 %s error: %s", action, errMsg)
	}
	fmt.Printf("✓ HTTP/3 %s for vhost %s\n", action, host)
	return nil
}

func runHTTP3List(baseURL string) error {
	u := fmt.Sprintf("%s/api/v1/http3/list", strings.TrimRight(baseURL, "/"))
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http3 list HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rows []http3CLIEntry
	if err := json.Unmarshal(body, &rows); err != nil {
		return fmt.Errorf("http3 list: server returned non-JSON (%d bytes): %q", len(body), strings.TrimSpace(string(body)))
	}
	if len(rows) == 0 {
		fmt.Println("No vhosts opted in to HTTP/3. Default is OFF (HTTP/2 only).")
		return nil
	}
	fmt.Printf("%-50s %s\n", "VHOST", "CREATED")
	for _, r := range rows {
		fmt.Printf("%-50s %s\n", r.Host, r.CreatedAt)
	}
	return nil
}
