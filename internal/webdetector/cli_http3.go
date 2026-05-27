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
	if a := args[0]; a == "help" || a == "-h" || a == "--help" {
		printHTTP3Help()
		return nil
	}

	if len(args) < 2 {
		printHTTP3Help()
		return fmt.Errorf("missing vhost for action %q", args[0])
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
		printHTTP3Help()
		return fmt.Errorf("unknown http3 action %q", action)
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

func printHTTP3Help() {
	fmt.Println(`
cfm webtop http3 — per-vhost HTTP/3 (Alt-Svc) opt-in

  Default for every vhost is OFF: nginx does NOT advertise Alt-Svc and
  browsers stay on HTTP/2 over TCP. Listed vhosts get an Alt-Svc header
  on every response, so capable browsers will try QUIC.

Usage:
  cfm webtop http3                            list opted-in vhosts (same as 'list')
  cfm webtop http3 list                       list opted-in vhosts
  cfm webtop http3 enable  <vhost>            advertise Alt-Svc for vhost
  cfm webtop http3 disable <vhost>            stop advertising Alt-Svc for vhost
  cfm webtop http3 help                       this text

Aliases:
  enable:  on, opt-in
  disable: off, opt-out, remove, rm

Supported vhost patterns:
  example.com                                 exact host
  *.cdn.example.com                           wildcard one-level suffix

Anything else (` + "`?`, `[abc]`, `cdn.*.example.com`" + `, multiple '*') is
rejected — the Lua matcher cannot honor those patterns and we refuse to
hold any pattern the Lua data path cannot match.

Propagation: changes take effect within ~CFM_H3_REFRESH_SEC seconds
(default 60s) without an nginx reload.

Same scope rules as WAF/Challenge: admin tokens can manage any host,
scoped tokens only their own. The cfm-admin web UI exposes the same
toggles in Per-vhost controls.`)
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
