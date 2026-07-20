package webdetector

import (
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

func runHistoryWebTop(baseURL string, args []string) error {
	rest := []string{}
	if len(args) > 1 {
		rest = args[1:]
	}
	if len(args) == 0 || args[0] == "events" {
		return runHistoryEvents(baseURL, rest)
	}
	switch args[0] {
	case "summary":
		return runHistorySummary(baseURL, rest)
	case "outcomes":
		return runHistoryOutcomes(baseURL, rest)
	case "prune":
		return runHistoryPrune(baseURL, rest)
	case "truncate":
		return runHistoryTruncate(baseURL, rest)
	case "waf-by-rule", "waf":
		return runHistoryWAFByRule(baseURL, rest)
	case "overview", "vhost-overview":
		return runHistoryVhostOverview(baseURL, rest)
	default:
		return fmt.Errorf("usage: cfm webtop history [events|summary|outcomes|waf-by-rule|overview|prune|truncate]")

	}
}

func parseHistoryFilters(args []string) (host, ip string, limit, hours int) {
	limit = 100
	hours = 24
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--host" && i+1 < len(args):
			host = args[i+1]
			i++
		case strings.HasPrefix(a, "--host="):
			host = strings.TrimPrefix(a, "--host=")
		case a == "--ip" && i+1 < len(args):
			ip = args[i+1]
			i++
		case strings.HasPrefix(a, "--ip="):
			ip = strings.TrimPrefix(a, "--ip=")
		case a == "--limit" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				limit = n
			}
			i++
		case strings.HasPrefix(a, "--limit="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--limit=")); err == nil {
				limit = n
			}
		case a == "--hours" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				hours = n
			}
			i++
		case strings.HasPrefix(a, "--hours="):
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--hours=")); err == nil {
				hours = n
			}
		}
	}
	return
}

func runHistoryEvents(baseURL string, args []string) error {
	host, ip, limit, _ := parseHistoryFilters(args)
	u, _ := url.Parse(strings.TrimRight(baseURL, "/") + "/api/v1/webdet/history/events")
	q := u.Query()
	if host != "" {
		q.Set("host", host)
	}
	if ip != "" {
		q.Set("ip", ip)
	}
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()
	resp, err := clihttp.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var payload struct {
		Rows []HistoryEvent `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TS\tTYPE\tHOST\tIP\tREASON\tUA")
	for _, ev := range payload.Rows {
		ts := strconv.FormatInt(ev.TsUnix, 10)
		if strings.TrimSpace(ev.TsUTC) != "" {
			ts = ev.TsUTC
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", ts, ev.Type, ev.Host, ev.IP, ev.Reason, truncate(payloadString(ev.Payload, "ua"), 60))
	}
	return w.Flush()
}

func payloadString(p map[string]interface{}, key string) string {
	if p == nil {
		return ""
	}
	v, ok := p[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func runHistorySummary(baseURL string, args []string) error {
	host, ip, _, hours := parseHistoryFilters(args)
	u, _ := url.Parse(strings.TrimRight(baseURL, "/") + "/api/v1/webdet/history/summary")
	q := u.Query()
	if host != "" {
		q.Set("host", host)
	}
	if ip != "" {
		q.Set("ip", ip)
	}
	q.Set("hours", strconv.Itoa(hours))
	u.RawQuery = q.Encode()
	resp, err := clihttp.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var s HistorySummary
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return err
	}
	fmt.Printf("history summary (%dh): total=%d challenge_issued=%d solved=%d unsolved_expired=%d escalated=%d block_triggers=%d waf=%d suspicious=%d\n",
		hours, s.TotalEvents, s.ChallengeIssued, s.ChallengeSolved, s.ChallengeExpiredUnsolved, s.ChallengeEscalated, s.BlockTriggers, s.WAFObserved, s.Suspicious)
	return nil
}

func runHistoryOutcomes(baseURL string, args []string) error {
	host, ip, limit, _ := parseHistoryFilters(args)
	u, _ := url.Parse(strings.TrimRight(baseURL, "/") + "/api/v1/webdet/history/challenge-outcomes")
	q := u.Query()
	if host != "" {
		q.Set("host", host)
	}
	if ip != "" {
		q.Set("ip", ip)
	}
	q.Set("limit", strconv.Itoa(limit))
	u.RawQuery = q.Encode()
	resp, err := clihttp.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var payload struct {
		Solved   []HistoryEvent `json:"solved"`
		Unsolved []HistoryEvent `json:"unsolved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	fmt.Printf("challenge outcomes: solved=%d unsolved=%d\n", len(payload.Solved), len(payload.Unsolved))
	return nil
}

func runHistoryPrune(baseURL string, args []string) error {
	days := 30
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			days = n
		}
	}
	u := fmt.Sprintf("%s/api/v1/webdet/history/prune?days=%d", strings.TrimRight(baseURL, "/"), days)
	resp, err := clihttp.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("pruned days=%d rows_deleted=%v\n", days, out["rows_deleted"])
	return nil
}

func runHistoryTruncate(baseURL string, args []string) error {
	confirm := false
	for _, a := range args {
		if a == "--yes" {
			confirm = true
			break
		}
	}
	if !confirm {
		return fmt.Errorf("refusing to truncate without --yes")
	}
	u := fmt.Sprintf("%s/api/v1/webdet/history/truncate?confirm=yes", strings.TrimRight(baseURL, "/"))
	resp, err := clihttp.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	fmt.Printf("history truncated rows_deleted=%v\n", out["rows_deleted"])
	return nil
}

func runHistoryWAFByRule(baseURL string, args []string) error {
	host, _, _, hours := parseHistoryFilters(args)
	u, _ := url.Parse(strings.TrimRight(baseURL, "/") + "/api/v1/webdet/history/waf-by-rule")
	q := u.Query()
	if host != "" {
		q.Set("host", host)
	}
	q.Set("hours", strconv.Itoa(hours))
	u.RawQuery = q.Encode()
	resp, err := clihttp.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var payload struct {
		Host  string       `json:"host"`
		Hours int          `json:"hours"`
		Rules []WAFRuleHit `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	scope := "global"
	if payload.Host != "" {
		scope = payload.Host
	}
	fmt.Printf("WAF rule hits (%dh) — %s\n", payload.Hours, scope)
	if len(payload.Rules) == 0 {
		fmt.Println("  (no WAF events in this window)")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RULE\tHITS")
	for _, r := range payload.Rules {
		fmt.Fprintf(w, "%s\t%d\n", r.Rule, r.Count)
	}
	return w.Flush()
}

func runHistoryVhostOverview(baseURL string, args []string) error {
	host, _, _, hours := parseHistoryFilters(args)
	u, _ := url.Parse(strings.TrimRight(baseURL, "/") + "/api/v1/webdet/history/vhost-overview")
	q := u.Query()
	if host != "" {
		q.Set("host", host)
	}
	q.Set("hours", strconv.Itoa(hours))
	u.RawQuery = q.Encode()
	resp, err := clihttp.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var ov VhostOverview
	if err := json.NewDecoder(resp.Body).Decode(&ov); err != nil {
		return err
	}

	scope := "global"
	if ov.Host != "" {
		scope = ov.Host
	}
	fmt.Printf("Security overview (%dh) — %s\n", ov.Hours, scope)
	fmt.Printf("  Challenges issued : %d\n", ov.ChallengeIssued)
	fmt.Printf("  Challenges solved : %d (%.2f%%)\n", ov.ChallengeSolved, ov.SolveRatePct)
	fmt.Printf("  WAF hits          : %d\n", ov.WAFHits)
	if ov.TopWAFRule != "" {
		fmt.Printf("  Top WAF rule      : %s\n", ov.TopWAFRule)
	}
	if len(ov.WAFByRule) > 0 {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  RULE\tHITS")
		for _, r := range ov.WAFByRule {
			fmt.Fprintf(w, "  %s\t%d\n", r.Rule, r.Count)
		}
		_ = w.Flush()
	}
	return nil
}
