package webdetector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"cfm/internal/clihttp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

func runRulesWebTop(baseURL string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		return runRulesList(baseURL)
	}
	switch args[0] {
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop rules get <id>")
		}
		return runRulesGet(baseURL, args[1])
	case "add":
		path, err := readFileFlag(args[1:])
		if err != nil {
			return err
		}
		return runRulesAdd(baseURL, path)
	case "update":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop rules update <id> --file rule.json")
		}
		path, err := readFileFlag(args[2:])
		if err != nil {
			return err
		}
		return runRulesUpdate(baseURL, args[1], path)
	case "remove", "rm", "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop rules remove <id>")
		}
		return runRulesRemove(baseURL, args[1])
	case "simulate":
		in, err := parseRulesSimulateFlags(args[1:])
		if err != nil {
			return err
		}
		return runRulesSimulate(baseURL, in)
	default:
		return fmt.Errorf("unknown rules subcommand %q (use list|get|add|update|remove|simulate)", args[0])
	}
}

func readFileFlag(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--file" && i+1 < len(args) {
			return args[i+1], nil
		}
		if strings.HasPrefix(a, "--file=") {
			return strings.TrimPrefix(a, "--file="), nil
		}
	}
	return "", fmt.Errorf("missing --file path")
}

func doJSON(method, rawURL string, reqBody any, out any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := clihttp.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	if resp.StatusCode >= 400 {
		if m, ok := out.(map[string]any); ok {
			if e, ok := m["error"].(string); ok && strings.TrimSpace(e) != "" {
				return errors.New(e)
			}
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}
	return nil
}

func runRulesList(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules"
	var payload struct {
		Rows []TrafficRule `json:"rows"`
	}
	if err := doJSON(http.MethodGet, u, nil, &payload); err != nil {
		return err
	}
	if len(payload.Rows) == 0 {
		fmt.Println("No traffic rules configured.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tENABLED\tPRIORITY\tACTION\tPROFILE\tVHOSTS\tMATCH")
	for _, r := range payload.Rows {
		fmt.Fprintf(w, "%s\t%t\t%d\t%s\t%s\t%s\t%s\n",
			r.ID,
			r.Enabled,
			r.Priority,
			r.Action.Type,
			r.Action.Profile,
			strings.Join(r.Scope.Vhosts, ","),
			rulesMatchSummary(r.Match),
		)
	}
	return w.Flush()
}

func runRulesGet(baseURL, id string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/get?id=" + url.QueryEscape(id)
	var payload map[string]any
	if err := doJSON(http.MethodGet, u, nil, &payload); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(b))
	return nil
}

func runRulesAdd(baseURL, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var req TrafficRule
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid rule json: %w", err)
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/add"
	var payload map[string]any
	if err := doJSON(http.MethodPost, u, req, &payload); err != nil {
		return err
	}
	fmt.Printf("✓ rule added id=%v\n", payloadPath(payload, "rule", "id"))
	return nil
}

func runRulesUpdate(baseURL, id, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var req TrafficRule
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid rule json: %w", err)
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/update?id=" + url.QueryEscape(id)
	var payload map[string]any
	if err := doJSON(http.MethodPost, u, req, &payload); err != nil {
		return err
	}
	fmt.Printf("✓ rule updated id=%v\n", payloadPath(payload, "rule", "id"))
	return nil
}

func runRulesRemove(baseURL, id string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/remove?id=" + url.QueryEscape(id)
	var payload map[string]any
	if err := doJSON(http.MethodPost, u, map[string]any{}, &payload); err != nil {
		return err
	}
	fmt.Printf("✓ rule removed id=%s\n", id)
	return nil
}

func parseRulesSimulateFlags(args []string) (TrafficRuleEvalInput, error) {
	in := TrafficRuleEvalInput{Method: "GET"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch {
		case a == "--host" && next != "":
			in.Host = next
			i++
		case strings.HasPrefix(a, "--host="):
			in.Host = strings.TrimPrefix(a, "--host=")
		case a == "--ip" && next != "":
			in.IP = next
			i++
		case strings.HasPrefix(a, "--ip="):
			in.IP = strings.TrimPrefix(a, "--ip=")
		case a == "--ua" && next != "":
			in.UA = next
			i++
		case strings.HasPrefix(a, "--ua="):
			in.UA = strings.TrimPrefix(a, "--ua=")
		case a == "--path" && next != "":
			in.Path = next
			i++
		case strings.HasPrefix(a, "--path="):
			in.Path = strings.TrimPrefix(a, "--path=")
		case a == "--method" && next != "":
			in.Method = strings.ToUpper(next)
			i++
		case strings.HasPrefix(a, "--method="):
			in.Method = strings.ToUpper(strings.TrimPrefix(a, "--method="))
		case a == "--country" && next != "":
			in.Country = strings.ToUpper(next)
			i++
		case strings.HasPrefix(a, "--country="):
			in.Country = strings.ToUpper(strings.TrimPrefix(a, "--country="))
case a == "--qs" && next != "":
    in.QueryString = next
    i++
case strings.HasPrefix(a, "--qs="):
    in.QueryString = strings.TrimPrefix(a, "--qs=")

		}
	}
	if strings.TrimSpace(in.Host) == "" {
		return TrafficRuleEvalInput{}, fmt.Errorf("usage: cfm webtop rules simulate --host <vhost> [--ip <ip>] [--ua <ua>] [--path </x>] [--method GET] [--country US] [--qs 'key=value']")
	}
	return in, nil
}

func runRulesSimulate(baseURL string, in TrafficRuleEvalInput) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/simulate"
	var out TrafficRuleEvalResult
	if err := doJSON(http.MethodPost, u, in, &out); err != nil {
		return err
	}
	if !out.Matched {
		fmt.Println("No rule matched.")
		return nil
	}
	fmt.Printf("Matched rule id=%s priority=%d action=%s", out.Rule.ID, out.Rule.Priority, out.Action)
	if out.Profile != "" {
		fmt.Printf(" profile=%s", out.Profile)
	}
	fmt.Println()
	return nil
}

func rulesMatchSummary(m TrafficRuleMatch) string {
	parts := []string{}
	if len(m.CountryIn) > 0 {
		parts = append(parts, "cc="+strings.Join(m.CountryIn, ","))
	}
	if len(m.Methods) > 0 {
		parts = append(parts, "m="+strings.Join(m.Methods, ","))
	}
	if len(m.UAAny) > 0 {
		parts = append(parts, "ua="+strconv.Itoa(len(m.UAAny)))
	}
	if len(m.PathAny) > 0 {
		parts = append(parts, "path="+strconv.Itoa(len(m.PathAny)))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " ")
}

func payloadPath(m map[string]any, keys ...string) any {
	cur := any(m)
	for _, k := range keys {
		x, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = x[k]
		if !ok {
			return nil
		}
	}
	return cur
}
