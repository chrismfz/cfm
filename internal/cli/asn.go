package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var asnRe = regexp.MustCompile(`(?i)^AS\d+$`)

type ripeAnnouncedPrefixesResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func RunASN(args []string) int {
	fs := flag.NewFlagSet("asn", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm asn <AS12345> [--json]")
		return 2
	}

	asn := strings.ToUpper(strings.TrimSpace(fs.Arg(0)))
	if !asnRe.MatchString(asn) {
		if strings.HasPrefix(asn, "AS") {
			fmt.Fprintln(os.Stderr, "invalid ASN format; expected AS<number>")
			return 2
		}
		if matched, _ := regexp.MatchString(`^\d+$`, asn); matched {
			asn = "AS" + asn
		} else {
			fmt.Fprintln(os.Stderr, "invalid ASN format; expected AS<number>")
			return 2
		}
	}

	url := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + asn
	client := http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "asn lookup failed:", err)
		return 1
	}
	req.Header.Set("User-Agent", "cfm/"+"dev")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "asn lookup failed:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "asn lookup failed: HTTP %d\n", resp.StatusCode)
		return 1
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "asn lookup failed:", err)
		return 1
	}

	var parsed ripeAnnouncedPrefixesResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		fmt.Fprintln(os.Stderr, "asn lookup failed: invalid RIPE response")
		return 1
	}

	prefixes := make([]string, 0, len(parsed.Data.Prefixes))
	for _, p := range parsed.Data.Prefixes {
		if s := strings.TrimSpace(p.Prefix); s != "" {
			prefixes = append(prefixes, s)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(prefixes)
		return 0
	}

	for _, p := range prefixes {
		fmt.Println(p)
	}
	return 0
}
