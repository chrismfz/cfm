package webdetector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"cfm/internal/clihttp"
)

// CLI for the ClamAV signature-trust layer and infection visibility:
//
//	cfm clam sigignore list [--host <vhost>]
//	cfm clam sigignore add|remove <pattern> [--host <vhost>]   (no --host = global, admin-only)
//	cfm clam infections [--host <vhost>] [--limit N]
//
// Both talk to the scoped webdetector API (clihttp transport), so the same
// commands work for an admin and — host-scoped — for a scoped token.

// clamCLIFlags pulls --host/--limit style flags out of args, returning the
// remaining positionals. Unknown flags error so a typo can't silently widen a
// query.
func clamCLIFlags(args []string, want map[string]bool) (map[string]string, []string, error) {
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimPrefix(a, "--")
		if k, v, found := strings.Cut(name, "="); found {
			if !want[k] {
				return nil, nil, fmt.Errorf("unknown flag --%s", k)
			}
			flags[k] = v
			continue
		}
		if !want[name] {
			return nil, nil, fmt.Errorf("unknown flag --%s", name)
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("flag --%s needs a value", name)
		}
		i++
		flags[name] = args[i]
	}
	return flags, pos, nil
}

func clamAPIGet(baseURL, path string, out any) error {
	resp, err := clihttp.Get(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func clamAPIPost(baseURL, path string) error {
	resp, err := clihttp.Post(strings.TrimRight(baseURL, "/")+path, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// RunClamSigIgnore drives `cfm clam sigignore …`.
func RunClamSigIgnore(baseURL string, args []string) error {
	usage := "usage: cfm clam sigignore [list|add|remove] <pattern> [--host <vhost>]"
	action := "list"
	if len(args) > 0 {
		action = strings.ToLower(strings.TrimSpace(args[0]))
		args = args[1:]
	}
	flags, pos, err := clamCLIFlags(args, map[string]bool{"host": true})
	if err != nil {
		return err
	}
	host := strings.TrimSpace(flags["host"])

	switch action {
	case "list":
		var out struct {
			Entries []struct {
				Host      string    `json:"host"`
				Pattern   string    `json:"pattern"`
				CreatedAt time.Time `json:"created_at"`
			} `json:"entries"`
		}
		if err := clamAPIGet(baseURL, "/api/v1/clam/sigignore/list", &out); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "SCOPE\tPATTERN\tCREATED")
		n := 0
		for _, e := range out.Entries {
			scope := e.Host
			if scope == "" {
				scope = "(global)"
			}
			if host != "" && !strings.EqualFold(e.Host, host) {
				continue
			}
			n++
			fmt.Fprintf(w, "%s\t%s\t%s\n", scope, e.Pattern, e.CreatedAt.Format("2006-01-02 15:04"))
		}
		w.Flush()
		if n == 0 {
			fmt.Println("(no signature excludes; add one with: cfm clam sigignore add '<glob>' [--host <vhost>])")
		}
		return nil

	case "add", "remove":
		if len(pos) != 1 || strings.TrimSpace(pos[0]) == "" {
			return fmt.Errorf("%s", usage)
		}
		q := url.Values{}
		q.Set("pattern", pos[0])
		if host != "" {
			q.Set("host", host)
		}
		if err := clamAPIPost(baseURL, "/api/v1/clam/sigignore/"+action+"?"+q.Encode()); err != nil {
			return err
		}
		scope := host
		if scope == "" {
			scope = "(global)"
		}
		fmt.Printf("OK\tsigignore %s pattern=%q scope=%s\n", action, pos[0], scope)
		return nil

	default:
		return fmt.Errorf("%s", usage)
	}
}

// RunClamInfections drives `cfm clam infections` — the CLI view of the scoped
// clam_infected history (what the ClamAV page's tables show).
func RunClamInfections(baseURL string, args []string) error {
	flags, pos, err := clamCLIFlags(args, map[string]bool{"host": true, "limit": true})
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("usage: cfm clam infections [--host <vhost>] [--limit N]")
	}
	limit := 50
	if v := strings.TrimSpace(flags["limit"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("--limit wants a positive integer, got %q", v)
		}
		limit = n
	}
	q := url.Values{}
	q.Set("type", "clam_infected")
	q.Set("limit", strconv.Itoa(limit))
	q.Set("enrich", "1")
	if host := strings.TrimSpace(flags["host"]); host != "" {
		q.Set("host", host)
	}

	var out struct {
		Rows []struct {
			TsUnix  int64          `json:"ts_unix"`
			Host    string         `json:"host"`
			IP      string         `json:"ip"`
			Reason  string         `json:"reason"`
			Country string         `json:"country"`
			Payload map[string]any `json:"payload"`
		} `json:"rows"`
	}
	if err := clamAPIGet(baseURL, "/api/v1/webdet/history/events?"+q.Encode(), &out); err != nil {
		return err
	}
	if len(out.Rows) == 0 {
		fmt.Println("(no recorded infections)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "WHEN\tVHOST\tSOURCE IP\tFILE\tSIGNATURE\tACTION")
	for _, r := range out.Rows {
		file, _ := r.Payload["filename"].(string)
		if file == "" {
			file = "-"
		}
		action := "notified"
		if ig, _ := r.Payload["sig_ignored"].(bool); ig {
			by, _ := r.Payload["ignored_by"].(string)
			action = "ignored"
			if by != "" {
				action = "ignored (" + by + ")"
			}
		}
		ip := r.IP
		if r.Country != "" {
			ip += " " + r.Country
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			time.Unix(r.TsUnix, 0).Format("2006-01-02 15:04:05"),
			r.Host, ip, file, r.Reason, action)
	}
	w.Flush()
	return nil
}
