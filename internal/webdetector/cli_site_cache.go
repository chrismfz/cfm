// internal/webdetector/cli_site_cache.go
//
// `cfm webtop site-cache ...` — per-vhost edge caching (see site_cache.go and
// docs/site-cache-design.md). Default for every vhost is OFF. Two independent
// tiers: static-asset cache and micro-cache of HTML.
//
// Subcommands:
//   list                                     — show configured vhosts
//   get     <vhost>                          — one vhost's policy (JSON)
//   set     <vhost> [--static R|off] [--micro R|off] — create/update a policy;
//               [--static-ttl D] [--micro-ttl D]      changes ONLY the flags
//               [--strict-cookies|--no-strict-cookies] given (merge)
//               [--auth-cookies a,b,c|--no-auth-cookies]
//   off     <vhost>                          — caching OFF: both tiers off, kept as an
//                                              opt-out that also overrides a broader
//                                              armed *.suffix wildcard (alias: disable)
//   remove  <vhost>                          — DELETE the policy: the host then follows a
//                                              covering *.suffix wildcard (alias: rm)
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
			return fmt.Errorf("usage: cfm webtop site-cache set <vhost> [--static RECIPE|off] [--micro RECIPE|off] [--static-ttl D] [--micro-ttl D] [--strict-cookies|--no-strict-cookies] [--auth-cookies a,b,c|--no-auth-cookies]")
		}
		return runSiteCacheSet(baseURL, args[1], args[2:])
	case "off", "disable":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop site-cache off <vhost>")
		}
		return runSiteCacheOff(baseURL, args[1])
	case "remove", "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop site-cache remove <vhost>")
		}
		return runSiteCacheRemove(baseURL, args[1])
	case "purge":
		return runSiteCachePurge(baseURL, args[1:])
	case "stats":
		return runSiteCacheStats(baseURL, args[1:])
	default:
		printSiteCacheHelp()
		return fmt.Errorf("unknown site-cache subcommand %q (use list|get|set|off|remove|purge|stats)", args[0])
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
  cfm webtop site-cache off <vhost>                   turn caching OFF (both tiers off; this
                                                      also opts the vhost — or a narrower
                                                      *.suffix — out of a broader armed
                                                      wildcard; re-arming starts a fresh cache)
  cfm webtop site-cache remove <vhost>                delete the vhost's policy (it then
                                                      follows a covering *.suffix wildcard)
  cfm webtop site-cache purge <vhost>                 invalidate a vhost's cache
  cfm webtop site-cache purge --all                   invalidate ALL vhosts (admin only)
  cfm webtop site-cache stats [vhost]                 per-vhost HIT/MISS/hit-ratio

set flags (set changes ONLY the flags you pass; the rest of the policy is kept):
  --static RECIPE        enable the static tier with RECIPE
  --static off           disable the static tier (its recipe/TTL are kept)
  --micro  RECIPE        enable the micro tier with RECIPE
  --micro off            disable the micro tier (its recipe/TTL are kept)
  --static-ttl D         static TTL bucket (e.g. 1h, 7d, 30d)
  --micro-ttl  D         micro TTL bucket (e.g. 1s, 5s, 30s)
  --strict-cookies       bypass on ANY non-CFM cookie (max safety, less cache)
  --no-strict-cookies    back to the named auth-cookie allowlist (the default)
  --auth-cookies a,b,c   extra app-session cookie names that force a bypass
                         (replaces the stored list)
  --no-auth-cookies      clear the extra auth-cookie list

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

func runSiteCacheStats(baseURL string, args []string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/stats"
	if len(args) > 0 {
		if h := strings.TrimSpace(args[0]); h != "" && !strings.HasPrefix(h, "-") {
			u += "?host=" + url.QueryEscape(h)
		}
	}
	resp, err := clihttp.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("site-cache stats HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload siteCacheStatsResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("site-cache stats: server returned non-JSON (%d bytes): %q", len(body), strings.TrimSpace(string(body)))
	}
	if len(payload.Rows) == 0 {
		fmt.Println("No cache stats yet. The edge reports per-vhost HIT/MISS only for ARMED vhosts once they serve traffic (pushed ~every 60s).")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VHOST\tHIT\tMISS\tEXPIRED\tSTALE\tBYPASS\tHIT%\tCACHEABLE")
	for _, r := range payload.Rows {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%.1f\t%d\n",
			r.Host, r.Hit, r.Miss, r.Expired, r.Stale, r.Bypass, r.HitRatioPct, r.CacheableTotal)
	}
	return w.Flush()
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
	patch, err := parseSiteCacheSetFlags(host, flags)
	if err != nil {
		return err
	}
	e, err := postSiteCachePatch(baseURL, patch, "site-cache set")
	if err != nil {
		return err
	}
	fmt.Printf("✓ cache policy set for %s (static=%s micro=%s)\n",
		e.Host, siteCacheTierCLI(e.Static), siteCacheTierCLI(e.Micro))
	return nil
}

// runSiteCacheOff turns BOTH tiers off and KEEPS the entry: an explicit
// opt-out (for an exact host, or a narrower wildcard under a broader armed
// one). Deleting the entry (what `off` used to do) left a host under an
// admin's armed *.suffix wildcard cached by that wildcard — and deleted an
// opt-out, turning caching back ON.
func runSiteCacheOff(baseURL, host string) error {
	off := false
	e, err := postSiteCachePatch(baseURL, SiteCachePatch{
		Host:   host,
		Static: &SiteCacheTierPatch{Enabled: &off},
		Micro:  &SiteCacheTierPatch{Enabled: &off},
	}, "site-cache off")
	if err != nil {
		return err
	}
	what := "it"
	if strings.HasPrefix(e.Host, "*.") {
		what = "its sub-hosts"
	}
	note := ""
	if e.CreatedAt.Equal(e.UpdatedAt) {
		// A brand-new entry: `off` used to 404 on a host with no policy, so
		// say what happened — a typo would otherwise pass unnoticed.
		note = " No policy existed for it; an opt-out was stored."
	}
	fmt.Printf("✓ caching OFF for %s: both tiers off, and a broader armed *.suffix wildcard no longer caches %s either ('remove' deletes the policy instead).%s\n", e.Host, what, note)
	return nil
}

func postSiteCachePatch(baseURL string, patch SiteCachePatch, label string) (*SiteCacheEntry, error) {
	b, _ := json.Marshal(patch)
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/set"
	resp, err := clihttp.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s HTTP %d: %s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var result siteCacheResultResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("%s: server returned non-JSON (%d bytes): %q", label, len(body), strings.TrimSpace(string(body)))
	}
	if result.Error != "" {
		return nil, fmt.Errorf("%s error: %s", label, result.Error)
	}
	if result.Entry == nil {
		return nil, fmt.Errorf("%s: server returned no entry", label)
	}
	return result.Entry, nil
}

// parseSiteCacheSetFlags turns `set` flags into a merge patch: only the flags
// given are sent, so the server keeps every other stored field (the set used
// to send a whole policy built from the flags alone, which reset the omitted
// tier and the cookie settings on every retune).
func parseSiteCacheSetFlags(host string, flags []string) (SiteCachePatch, error) {
	p := SiteCachePatch{Host: host}
	tier := func(t **SiteCacheTierPatch) *SiteCacheTierPatch {
		if *t == nil {
			*t = &SiteCacheTierPatch{}
		}
		return *t
	}
	setRecipe := func(t **SiteCacheTierPatch, v string) {
		tp := tier(t)
		if strings.EqualFold(strings.TrimSpace(v), "off") {
			tp.Enabled = boolPtrCLI(false)
			return
		}
		tp.Enabled = boolPtrCLI(true)
		tp.Recipe = &v
	}
	for i := 0; i < len(flags); i++ {
		a := flags[i]
		name, val, hasEq := strings.Cut(a, "=")
		takeVal := func() (string, error) {
			if hasEq {
				return val, nil
			}
			if i+1 >= len(flags) || flags[i+1] == "" || strings.HasPrefix(flags[i+1], "--") {
				return "", fmt.Errorf("missing value for %s", a)
			}
			i++
			return flags[i], nil
		}
		noValue := func() error {
			if hasEq {
				return fmt.Errorf("%s takes no value", name)
			}
			return nil
		}
		switch name {
		case "--static", "--micro", "--static-ttl", "--micro-ttl":
			v, err := takeVal()
			if err != nil {
				return SiteCachePatch{}, err
			}
			if strings.TrimSpace(v) == "" {
				return SiteCachePatch{}, fmt.Errorf("empty value for %s", name)
			}
			switch name {
			case "--static":
				setRecipe(&p.Static, v)
			case "--micro":
				setRecipe(&p.Micro, v)
			case "--static-ttl":
				tier(&p.Static).TTL = &v
			case "--micro-ttl":
				tier(&p.Micro).TTL = &v
			}
		case "--strict-cookies", "--no-strict-cookies":
			if err := noValue(); err != nil {
				return SiteCachePatch{}, err
			}
			p.StrictCookies = boolPtrCLI(name == "--strict-cookies")
		case "--auth-cookies":
			v, err := takeVal()
			if err != nil {
				return SiteCachePatch{}, err
			}
			list := splitCSVCLI(v)
			if len(list) == 0 {
				return SiteCachePatch{}, fmt.Errorf("empty --auth-cookies (use --no-auth-cookies to clear the list)")
			}
			p.AuthCookies = &list
		case "--no-auth-cookies":
			if err := noValue(); err != nil {
				return SiteCachePatch{}, err
			}
			empty := []string{}
			p.AuthCookies = &empty
		default:
			return SiteCachePatch{}, fmt.Errorf("unknown flag %q (see: cfm webtop site-cache help)", a)
		}
	}
	if p.Static == nil && p.Micro == nil && p.StrictCookies == nil && p.AuthCookies == nil {
		return SiteCachePatch{}, fmt.Errorf("nothing to change: pass --static RECIPE and/or --micro RECIPE, or another set flag ('off' turns caching off)")
	}
	return p, nil
}

func boolPtrCLI(b bool) *bool { return &b }

func runSiteCacheRemove(baseURL, host string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/site-cache/remove?host=" + url.QueryEscape(host)
	return siteCachePostStatus(u, fmt.Sprintf("✓ policy removed for %s — it is now uncached, unless an armed *.suffix wildcard covers it: then that wildcard's policy (and its cache) applies. Use 'off' to keep it uncached.\n", host), "site-cache remove")
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
