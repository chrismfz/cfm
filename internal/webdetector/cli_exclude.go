package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type excludeCLIEntry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at"`
}

func runChallengeExclude(baseURL string, args []string) error {
	return runGenericExclude(baseURL, "challenge", args)
}

func runWAFExclude(baseURL string, args []string) error {
	return runGenericExclude(baseURL, "waf", args)
}

func runGenericExclude(baseURL, prefix string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		u := fmt.Sprintf("%s/api/v1/%s/exclude/list", strings.TrimRight(baseURL, "/"), prefix)
		resp, err := http.Get(u)
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
		fmt.Printf("%-8s %-50s %s\n", "TYPE", "VALUE", "CREATED")
		for _, r := range rows {
			fmt.Printf("%-8s %-50s %s\n", r.Type, r.Value, r.CreatedAt)
		}
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: cfm webtop %s exclude [add|remove] <value> [--type host|path]", prefix)
	}
	action := args[0]
	value := args[1]
	typ := "host"
	for i := 2; i < len(args); i++ {
		if args[i] == "--type" && i+1 < len(args) {
			typ = args[i+1]
			i++
		} else if strings.HasPrefix(args[i], "--type=") {
			typ = strings.TrimPrefix(args[i], "--type=")
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
	u := fmt.Sprintf("%s/api/v1/%s/exclude/%s?type=%s&value=%s",
		strings.TrimRight(baseURL, "/"),
		prefix,
		endpoint,
		url.QueryEscape(typ),
		url.QueryEscape(value),
	)
	resp, err := http.Post(u, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if errMsg, ok := result["error"].(string); ok {
		return fmt.Errorf("%s exclude %s error: %s", prefix, action, errMsg)
	}
	fmt.Printf("✓ %s exclude %s: type=%s value=%s\n", strings.ToUpper(prefix), action, typ, value)
	return nil
}
