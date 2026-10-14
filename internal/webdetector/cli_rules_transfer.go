package webdetector

import (
	"bytes"
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
)

type rulesImportFlags struct {
	File     string
	DryRun   bool
	Disabled bool
}

func parseRulesExportFlags(args []string) (vhosts []string, out string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch {
		case a == "--vhost" && next != "":
			vhosts = append(vhosts, next)
			i++
		case strings.HasPrefix(a, "--vhost="):
			vhosts = append(vhosts, strings.TrimPrefix(a, "--vhost="))
		case a == "--out" && next != "":
			out = next
			i++
		case strings.HasPrefix(a, "--out="):
			out = strings.TrimPrefix(a, "--out=")
		case a == "--vhost" || a == "--out":
			return nil, "", fmt.Errorf("missing value for %s", a)
		default:
			return nil, "", fmt.Errorf("unexpected argument %q (usage: cfm webtop rules export [--vhost <host>]... [--out rules.json])", a)
		}
	}
	return vhosts, out, nil
}

func parseRulesImportFlags(args []string) (rulesImportFlags, error) {
	var f rulesImportFlags
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--file" && i+1 < len(args):
			f.File = args[i+1]
			i++
		case strings.HasPrefix(a, "--file="):
			f.File = strings.TrimPrefix(a, "--file=")
		case a == "--dry-run":
			f.DryRun = true
		case a == "--disabled":
			f.Disabled = true
		default:
			return f, fmt.Errorf("unexpected argument %q (usage: cfm webtop rules import --file rules.json [--dry-run] [--disabled])", a)
		}
	}
	if f.File == "" {
		return f, fmt.Errorf("missing --file path")
	}
	return f, nil
}

func runRulesExport(baseURL string, vhosts []string, out string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/export"
	if len(vhosts) > 0 {
		q := url.Values{}
		for _, v := range vhosts {
			q.Add("vhost", v)
		}
		u += "?" + q.Encode()
	}
	var doc TrafficRulesExportDoc
	if err := doJSON(http.MethodGet, u, nil, &doc); err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if out == "" || out == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		return err
	}
	msg := fmt.Sprintf("✓ exported %d rule(s) to %s", len(doc.Rules), out)
	if doc.Skipped > 0 {
		msg += fmt.Sprintf(" (%d skipped: written by a newer cfm)", doc.Skipped)
	}
	fmt.Fprintln(os.Stderr, msg)
	return nil
}

// runRulesImport posts the document and prints the per-rule plan. Unlike
// doJSON it reads the plan from a 400 too: an all-or-nothing rejection is
// only useful with the rule that caused it.
func runRulesImport(baseURL string, f rulesImportFlags) error {
	body, err := os.ReadFile(f.File)
	if err != nil {
		return err
	}
	q := url.Values{}
	if f.DryRun {
		q.Set("dry_run", "1")
	}
	if f.Disabled {
		q.Set("disabled", "1")
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/webdet/rules/import"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := clihttp.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var res TrafficRuleImportResult
	if jerr := json.Unmarshal(raw, &res); jerr != nil {
		if resp.StatusCode >= 400 {
			return fmt.Errorf("request failed with status %d", resp.StatusCode)
		}
		return jerr
	}
	printRulesImportResult(res)
	if resp.StatusCode >= 400 || res.Error != "" {
		if res.Error == "" {
			res.Error = fmt.Sprintf("request failed with status %d", resp.StatusCode)
		}
		return fmt.Errorf("%s", res.Error)
	}
	switch {
	case res.DryRun:
		fmt.Printf("dry run: %d to add, %d duplicate(s); nothing written\n", res.Add, res.Duplicates)
	default:
		fmt.Printf("✓ imported %d rule(s), %d duplicate(s) skipped\n", len(res.Added), res.Duplicates)
	}
	return nil
}

func printRulesImportResult(res TrafficRuleImportResult) {
	if len(res.Items) == 0 {
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "#\tSTATUS\tID\tENABLED\tPRIORITY\tACTION\tVHOSTS\tDETAIL")
	for _, it := range res.Items {
		detail := it.Error
		if it.DuplicateOf != "" {
			detail = "same as " + it.DuplicateOf
		}
		if len(it.Warnings) > 0 {
			if detail != "" {
				detail += "; "
			}
			detail += strings.Join(it.Warnings, "; ")
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%t\t%d\t%s\t%s\t%s\n",
			it.Index+1, it.Status, it.Rule.ID, it.Rule.Enabled, it.Rule.Priority,
			it.Rule.Action.Type, strings.Join(it.Rule.Scope.Vhosts, ","), detail)
	}
	_ = w.Flush()
}
