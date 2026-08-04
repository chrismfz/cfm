package webdetector

import (
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type excludeCLIEntry struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	RuleIDs    []int    `json:"rule_ids,omitempty"`
	ScopeHosts []string `json:"scope_hosts,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

func runChallengeExclude(baseURL string, args []string) error {
	return runGenericExclude(baseURL, "challenge", "exclude", args)
}

func runWAFExclude(baseURL string, args []string) error {
	return runGenericExclude(baseURL, "waf", "exclude", args)
}

// RunClamOverride drives `cfm clam override` / `cfm webtop clam override`. The
// per-vhost ClamAV scan toggle is an "override" (a flip from the global
// CLAM_SCAN_DEFAULT), not an "exclude", so it uses the /api/v1/clam/override/*
// resource. Raw add/remove/list of the override host list; whether a listed host
// ends up scanned depends on the global default (the vhost-controls UI shows the
// resolved on/off state).
func RunClamOverride(baseURL string, args []string) error {
	return runGenericExclude(baseURL, "clam", "override", args)
}

// RunClamMode drives `cfm clam mode add|remove|list <host>` — the per-vhost
// async/inline flip against the global CLAM_SCAN_MODE (same XOR shape as the
// scan override, separate /api/v1/clam/mode/* store).
func RunClamMode(baseURL string, args []string) error {
	return runGenericExclude(baseURL, "clam", "mode", args)
}

// resource is the API path segment after the feature prefix ("exclude" for
// waf/challenge, "override" for clam).
func runGenericExclude(baseURL, prefix, resource string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		u := fmt.Sprintf("%s/api/v1/%s/%s/list", strings.TrimRight(baseURL, "/"), prefix, resource)
		resp, err := clihttp.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var rows []excludeCLIEntry
		if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Printf("No %s excludes configured.\n", prefix)
			return nil
		}
		// RULES is "*" for whole-WAF / challenge entries, else the rule-id list.
		// SCOPE is "*" for admin-global entries, else the comma-joined vhost(s)
		// the entry is pinned to — the value to echo back on `remove`.
		fmt.Printf("%-8s %-40s %-16s %-24s %s\n", "TYPE", "VALUE", "RULES", "SCOPE", "CREATED")
		for _, r := range rows {
			rules := "*"
			if len(r.RuleIDs) > 0 {
				rules = formatRuleIDs(r.RuleIDs)
			}
			scope := "*"
			if len(r.ScopeHosts) > 0 {
				scope = strings.Join(r.ScopeHosts, ",")
			}
			fmt.Printf("%-8s %-40s %-16s %-24s %s\n", r.Type, r.Value, rules, scope, r.CreatedAt)
		}
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: cfm webtop %s %s [add|remove] <value> [--type host|path]%s",
			prefix, resource, ruleFlagUsage(prefix))
	}
	action := args[0]
	value := args[1]
	typ := "host"
	var rules []string  // collected raw specifiers; sent verbatim to API for parsing
	var scopes []string // WAF-only: host(s) to scope the entry to (admin only)
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "--type" && i+1 < len(args):
			typ = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--type="):
			typ = strings.TrimPrefix(args[i], "--type=")
		case prefix == "waf" && args[i] == "--rule" && i+1 < len(args):
			rules = append(rules, args[i+1])
			i++
		case prefix == "waf" && strings.HasPrefix(args[i], "--rule="):
			rules = append(rules, strings.TrimPrefix(args[i], "--rule="))
		case prefix == "waf" && args[i] == "--scope" && i+1 < len(args):
			scopes = append(scopes, args[i+1])
			i++
		case prefix == "waf" && strings.HasPrefix(args[i], "--scope="):
			scopes = append(scopes, strings.TrimPrefix(args[i], "--scope="))
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	var endpoint string
	switch action {
	case "add":
		endpoint = "add"
	case "remove", "rm", "del":
		endpoint = "remove"
	default:
		return fmt.Errorf("unknown exclude action %q (use add/remove/list)", action)
	}
	q := url.Values{}
	q.Set("type", typ)
	q.Set("value", value)
	if len(rules) > 0 {
		// API parser accepts comma-separated mix of N / Nxx / N-M.
		q.Set("rule_ids", strings.Join(rules, ","))
	}
	if len(scopes) > 0 {
		// Host(s) to scope the entry to. The server honours this only for an
		// admin token; a scoped token is always pinned to its own vhost set.
		q.Set("scope_hosts", strings.Join(scopes, ","))
	}
	u := fmt.Sprintf("%s/api/v1/%s/%s/%s?%s",
		strings.TrimRight(baseURL, "/"), prefix, resource, endpoint, q.Encode())
	resp, err := clihttp.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("%s exclude %s error: %s", prefix, action, errMsg)
	}
	rulesShown := ""
	if len(rules) > 0 {
		rulesShown = " rules=" + strings.Join(rules, ",")
	}
	if len(scopes) > 0 {
		rulesShown += " scope=" + strings.Join(scopes, ",")
	}
	fmt.Printf("✓ %s exclude %s: type=%s value=%s%s\n", strings.ToUpper(prefix), action, typ, value, rulesShown)
	return nil
}

// formatRuleIDs renders a sorted []int as a comma-joined string, collapsing
// runs of consecutive IDs into "lo-hi" ranges for readability. Pure
// presentation helper — the API/store always sees the fully expanded set.
func formatRuleIDs(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	var parts []string
	i := 0
	for i < len(ids) {
		j := i
		for j+1 < len(ids) && ids[j+1] == ids[j]+1 {
			j++
		}
		if j == i {
			parts = append(parts, fmt.Sprintf("%d", ids[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ids[i], ids[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

func ruleFlagUsage(prefix string) string {
	if prefix != "waf" {
		return ""
	}
	return " [--rule N|Nxx|N-M ...] [--scope host ...]"
}
