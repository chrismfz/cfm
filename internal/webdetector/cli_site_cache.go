// internal/webdetector/cli_site_cache.go
//
// `cfm webtop site-cache ...` — per-vhost edge caching (see site_cache.go and
// docs/site-cache-design.md). Default for every vhost is OFF. Two independent
// tiers: static-asset cache and micro-cache of HTML.
//
// Subcommands:
//   list                                     — show configured vhosts
//   get     <vhost>                          — one vhost's policy (JSON)
//   set     <vhost> [--static R] [--micro R] — upsert a policy
//               [--static-ttl D] [--micro-ttl D] [--strict-cookies]
//               [--auth-cookies a,b,c]
//   off     <vhost>                          — turn caching OFF (aliases: remove, rm, disable)
//   purge   <vhost> | --all                  — bump generation (--all is admin-only)
//
// HTTP goes through internal/clihttp (the sanctioned CLI transport, CLAUDE.md §5).

package webdetector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"cfm/internal/clihttp"
)

func runSiteCacheWebTop(baseURL string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		return runSiteCacheList(baseURL)
	}
	switch args[0] {
	case "help", "-h", "--help":
		printSiteCacheHelp()
		return nil
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop site-cache get <vhost>")
		}
		return runSiteCacheGet(baseURL, args[1])
	case "set":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop site-cache set <vhost> [--static RECIPE] [--micro RECIPE] [--static-ttl D] [--micro-ttl D] [--strict-cookies] [--auth-cookies a,b,c]")
		}
		return runSiteCacheSet(baseURL, args[1], args[2:])
	case "off", "remove", "rm", "disable":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop site-cache off <vhost>")
		}
		return runSiteCacheRemove(baseURL, args[1])
	case "purge":
		return runSiteCachePurge(baseURL, args[1:])
	default:
		printSiteCacheHelp()
		return fmt.Errorf("unknown site-cache subcommand %q (use list|get|set|off|purge)", args[0])
	}
}

func printSiteCacheHelp() {
	fmt.Println(`
cfm webtop site-cache — per-vhost edge caching (default: every vhost OFF)

  Two independent tiers per vhost:
    static — cache static assets (css/js/img/…). Recipes: static_lean, static_aggressive
    micro  — short micro-cache of anonymous HTML.  Recipes: micro_safe, micro_aggressive,
             micro_custom, fullpage_advanced

Usage:
  cfm webtop site-cache list                          list configured vhosts
  cfm webtop site-cache get <vhost>                   show one vhost's policy (JSON)
  cfm webtop site-cache set <vhost> [flags]           create/update a policy
  cfm webtop site-cache off <vhost>                   turn caching OFF for a vhost
  cfm webtop site-cache purge <vhost>                 invalidate a vhost's cache
  cfm webtop site-cache purge --all                   invalidate ALL vhosts (admin only)

set flags:
  --static RECIPE        enable the static tier with RECIPE
  --micro  RECIPE        enable the micro tier with RECIPE
  --static-ttl D         static TTL bucket (e.g. 1h, 7d, 30d)
  --micro-ttl  D         micro TTL bucket (e.g. 1s, 5s, 30s)
  --strict-cookies       bypass on ANY non-CFM cookie (max safety, less cache)
  --auth-cookies a,b,c   extra app-session cookie names that force a bypass

Scope: admin tokens manage any host; scoped (cPanel) tokens manage only their
own vhosts. purge --all is admin only.`)
}

func runSiteCacheList(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/list"
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("site-cache list HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload siteCacheListResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("site-cache list: server returned non-JSON (%d bytes): %q", len(body), strings.TrimSpace(string(body)))
	}
	if len(payload.Rows) == 0 {
		fmt.Println("No vhosts configured for caching. Default is OFF.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VHOST\tSTATIC\tMICRO\tGEN\tUPDATED")
	for _, e := range payload.Rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			e.Host, siteCacheTierCLI(e.Static), siteCacheTierCLI(e.Micro), e.Generation,
			e.UpdatedAt.Format("2006-01-02 15:04"))
	}
	return w.Flush()
}

func siteCacheTierCLI(t SiteCacheTier) string {
	if !t.Enabled {
		return "-"
	}
	s := t.Recipe
	if s == "" {
		s = "on"
	}
	if t.TTL != "" {
		s += "/" + t.TTL
	}
	return s
}

func runSiteCacheGet(baseURL, host string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/get?host=" + url.QueryEscape(host)
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("site-cache get HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out bytes.Buffer
	if err := json.Indent(&out, body, "", "  "); err != nil {
		fmt.Println(string(body))
		return nil
	}
	fmt.Println(out.String())
	return nil
}

func runSiteCacheSet(baseURL, host string, flags []string) error {
	entry := SiteCacheEntry{Host: host}
	for i := 0; i < len(flags); i++ {
		a := flags[i]
		next := ""
		if i+1 < len(flags) {
			next = flags[i+1]
		}
		takeVal := func() (string, error) {
			if next == "" || strings.HasPrefix(next, "--") {
				return "", fmt.Errorf("missing value for %s", a)
			}
			i++
			return next, nil
		}
		switch {
		case a == "--static":
			v, err := takeVal()
			if err != nil {
				return err
			}
			entry.Static.Enabled = true
			entry.Static.Recipe = v
		case strings.HasPrefix(a, "--static="):
			entry.Static.Enabled = true
			entry.Static.Recipe = strings.TrimPrefix(a, "--static=")
		case a == "--micro":
			v, err := takeVal()
			if err != nil {
				return err
			}
			entry.Micro.Enabled = true
			entry.Micro.Recipe = v
		case strings.HasPrefix(a, "--micro="):
			entry.Micro.Enabled = true
			entry.Micro.Recipe = strings.TrimPrefix(a, "--micro=")
		case a == "--static-ttl":
			v, err := takeVal()
			if err != nil {
				return err
			}
			entry.Static.TTL = v
		case strings.HasPrefix(a, "--static-ttl="):
			entry.Static.TTL = strings.TrimPrefix(a, "--static-ttl=")
		case a == "--micro-ttl":
			v, err := takeVal()
			if err != nil {
				return err
			}
			entry.Micro.TTL = v
		case strings.HasPrefix(a, "--micro-ttl="):
			entry.Micro.TTL = strings.TrimPrefix(a, "--micro-ttl=")
		case a == "--strict-cookies":
			entry.StrictCookies = true
		case a == "--auth-cookies":
			v, err := takeVal()
			if err != nil {
				return err
			}
			entry.AuthCookies = splitCSVCLI(v)
		case strings.HasPrefix(a, "--auth-cookies="):
			entry.AuthCookies = splitCSVCLI(strings.TrimPrefix(a, "--auth-cookies="))
		default:
			return fmt.Errorf("unknown flag %q (see: cfm webtop site-cache help)", a)
		}
	}
	if !entry.Static.Enabled && !entry.Micro.Enabled {
		return fmt.Errorf("nothing to enable: pass --static RECIPE and/or --micro RECIPE (or use 'off' to disable)")
	}

	b, _ := json.Marshal(entry)
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/set"
	resp, err := clihttp.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("site-cache set HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result siteCacheResultResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("site-cache set: server returned non-JSON (%d bytes): %q", len(body), strings.TrimSpace(string(body)))
	}
	if result.Error != "" {
		return fmt.Errorf("site-cache set error: %s", result.Error)
	}
	fmt.Printf("✓ cache policy set for %s (static=%s micro=%s)\n",
		result.Entry.Host, siteCacheTierCLI(result.Entry.Static), siteCacheTierCLI(result.Entry.Micro))
	return nil
}

func runSiteCacheRemove(baseURL, host string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/remove?host=" + url.QueryEscape(host)
	return siteCachePostStatus(u, fmt.Sprintf("✓ caching OFF for %s\n", host), "site-cache off")
}

func runSiteCachePurge(baseURL string, args []string) error {
	q := url.Values{}
	msg := ""
	switch {
	case len(args) == 0:
		return fmt.Errorf("usage: cfm webtop site-cache purge <vhost> | --all")
	case args[0] == "--all":
		q.Set("all", "1")
		msg = "✓ purged ALL vhost caches\n"
	default:
		q.Set("host", args[0])
		msg = fmt.Sprintf("✓ purged cache for %s\n", args[0])
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/purge?" + q.Encode()
	return siteCachePostStatus(u, msg, "site-cache purge")
}

// siteCachePostStatus POSTs an empty body and prints okMsg on a 2xx {status:ok}.
func siteCachePostStatus(u, okMsg, label string) error {
	resp, err := clihttp.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s HTTP %d: %s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("%s: server returned non-JSON (%d bytes): %q", label, len(body), strings.TrimSpace(string(body)))
	}
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("%s error: %s", label, errMsg)
	}
	fmt.Print(okMsg)
	return nil
}

func splitCSVCLI(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
