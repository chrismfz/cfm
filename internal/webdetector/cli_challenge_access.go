package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

// runChallengeAccessWebTop drives `cfm webtop challenge-access …`: the CLI over
// the /api/v1/challenge/access/* API. Mirrors runRulesWebTop (JSON-body add/
// update from a --file, id-keyed remove, flag-driven simulate).
func runChallengeAccessWebTop(baseURL string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		return runCAList(baseURL)
	}
	switch args[0] {
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop challenge-access get <id>")
		}
		return runCAGet(baseURL, args[1])
	case "add":
		path, err := readFileFlag(args[1:])
		if err != nil {
			return err
		}
		return runCAAdd(baseURL, path)
	case "update":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop challenge-access update <id> --file entry.json")
		}
		path, err := readFileFlag(args[2:])
		if err != nil {
			return err
		}
		return runCAUpdate(baseURL, args[1], path)
	case "remove", "rm", "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: cfm webtop challenge-access remove <id>")
		}
		return runCARemove(baseURL, args[1])
	case "simulate":
		in, err := parseCASimulateFlags(args[1:])
		if err != nil {
			return err
		}
		return runCASimulate(baseURL, in)
	default:
		return fmt.Errorf("unknown challenge-access subcommand %q (use list|get|add|update|remove|simulate)", args[0])
	}
}

func runCAList(baseURL string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/challenge/access"
	var payload struct {
		Rows []ChallengeAccessEntry `json:"rows"`
	}
	if err := doJSON(http.MethodGet, u, nil, &payload); err != nil {
		return err
	}
	if len(payload.Rows) == 0 {
		fmt.Println("No challenge-access exemptions configured.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tENABLED\tVHOSTS\tEXEMPTS")
	for _, e := range payload.Rows {
		state := "on"
		if !e.Enabled {
			state = "off"
		}
		if e.Unsupported {
			state = "unsupported"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.ID, state, strings.Join(e.Scope.Vhosts, ","), caMatchSummaryCLI(e.Match))
	}
	return w.Flush()
}

func runCAGet(baseURL, id string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/challenge/access/get?id=" + url.QueryEscape(id)
	var payload map[string]any
	if err := doJSON(http.MethodGet, u, nil, &payload); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(b))
	return nil
}

func runCAAdd(baseURL, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var req ChallengeAccessEntry
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid challenge-access json: %w", err)
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/challenge/access/add"
	var payload map[string]any
	if err := doJSON(http.MethodPost, u, req, &payload); err != nil {
		return err
	}
	fmt.Printf("✓ exemption added id=%v\n", payloadPath(payload, "entry", "id"))
	return nil
}

func runCAUpdate(baseURL, id, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var req ChallengeAccessEntry
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid challenge-access json: %w", err)
	}
	u := strings.TrimRight(baseURL, "/") + "/api/v1/challenge/access/update?id=" + url.QueryEscape(id)
	var payload map[string]any
	if err := doJSON(http.MethodPost, u, req, &payload); err != nil {
		return err
	}
	fmt.Printf("✓ exemption updated id=%v\n", payloadPath(payload, "entry", "id"))
	return nil
}

func runCARemove(baseURL, id string) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/challenge/access/remove?id=" + url.QueryEscape(id)
	var payload map[string]any
	if err := doJSON(http.MethodPost, u, map[string]any{}, &payload); err != nil {
		return err
	}
	fmt.Printf("✓ exemption removed id=%s\n", id)
	return nil
}

func parseCASimulateFlags(args []string) (ChallengeAccessSimInput, error) {
	in := ChallengeAccessSimInput{Method: "GET"}
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
		case a == "--asn" && next != "":
			in.ASN = parseASNCLI(next)
			i++
		case strings.HasPrefix(a, "--asn="):
			in.ASN = parseASNCLI(strings.TrimPrefix(a, "--asn="))
		case a == "--qs" && next != "":
			in.QueryString = next
			i++
		case strings.HasPrefix(a, "--qs="):
			in.QueryString = strings.TrimPrefix(a, "--qs=")
		case a == "--verified-bot" && next != "" && !strings.HasPrefix(next, "--"):
			in.VerifiedBot = next
			i++
		case a == "--verified-bot":
			in.VerifiedBot = "googlebot"
		case strings.HasPrefix(a, "--verified-bot="):
			in.VerifiedBot = strings.TrimPrefix(a, "--verified-bot=")
		default:
			switch a {
			case "--host", "--ip", "--ua", "--path", "--method", "--country", "--asn", "--qs":
				return ChallengeAccessSimInput{}, fmt.Errorf("missing value for %s", a)
			}
			if strings.HasPrefix(a, "-") {
				return ChallengeAccessSimInput{}, fmt.Errorf("unknown flag %q", a)
			}
			return ChallengeAccessSimInput{}, fmt.Errorf("unexpected argument %q", a)
		}
	}
	if strings.TrimSpace(in.Host) == "" {
		return ChallengeAccessSimInput{}, fmt.Errorf("usage: cfm webtop challenge-access simulate --host <vhost> [--ip <ip>] [--ua <ua>] [--path </x>] [--method GET] [--country US] [--asn 15169] [--qs 'k=v'] [--verified-bot[=name]]")
	}
	return in, nil
}

func parseASNCLI(v string) uint32 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "as"), 10, 32)
	return uint32(n)
}

func runCASimulate(baseURL string, in ChallengeAccessSimInput) error {
	u := strings.TrimRight(baseURL, "/") + "/api/v1/challenge/access/simulate"
	var out ChallengeAccessSimResult
	if err := doJSON(http.MethodPost, u, in, &out); err != nil {
		return err
	}
	if out.Exempted && out.Entry != nil {
		fmt.Printf("EXEMPTED from challenge by id=%s (%s)\n", out.Entry.ID, caMatchSummaryCLI(out.Entry.Match))
	} else {
		fmt.Println("NOT exempted — the request would be challenged (no matching exemption).")
	}
	fmt.Printf("resolved: country=%s asn=%s crawler=%s\n",
		orDash(out.Country),
		asnLabelCLI(out.ASN),
		orDash(out.VerifiedBot))
	if out.VerifiedBotInconclusive != "" {
		fmt.Printf("verified-crawler check: %s (not a definitive negative)\n", out.VerifiedBotInconclusive)
	}
	if !out.Exempted && out.VerifiedBot != "" && !out.VerifiedBotOverride {
		fmt.Println("note: this IP verifies as a crawler; the edge's built-in verified-crawler exemption would let it through separately.")
	}
	return nil
}

func caMatchSummaryCLI(m challengeAccessMatch) string {
	parts := []string{}
	if len(m.CountryIn) > 0 {
		parts = append(parts, "cc="+strings.Join(m.CountryIn, ","))
	}
	if len(m.CountryNotIn) > 0 {
		parts = append(parts, "cc!="+strings.Join(m.CountryNotIn, ","))
	}
	if len(m.AsnIn) > 0 {
		as := make([]string, 0, len(m.AsnIn))
		for _, a := range m.AsnIn {
			as = append(as, "AS"+strconv.FormatUint(uint64(a), 10))
		}
		parts = append(parts, "asn="+strings.Join(as, ","))
	}
	if len(m.IPAny) > 0 {
		parts = append(parts, "ip="+strings.Join(m.IPAny, ","))
	}
	if m.VerifiedBot {
		parts = append(parts, "verified_bot")
	}
	if len(m.UAAny) > 0 {
		parts = append(parts, "ua="+strconv.Itoa(len(m.UAAny)))
	}
	if len(m.PathAny) > 0 {
		parts = append(parts, "path="+strconv.Itoa(len(m.PathAny)))
	}
	if len(m.Methods) > 0 {
		parts = append(parts, "m="+strings.Join(m.Methods, ","))
	}
	if len(parts) == 0 {
		return "(whole vhost)"
	}
	return strings.Join(parts, " ")
}

func asnLabelCLI(a uint32) string {
	if a == 0 {
		return "-"
	}
	return "AS" + strconv.FormatUint(uint64(a), 10)
}
