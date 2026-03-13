// internal/cli/which.go
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	ipquery "cfm/internal/ipquery"
)

// WhichHit is exported so callers can JSON-marshal it.
type WhichHit struct {
	Action string `json:"action"` // "ALLOW"/"BLOCK"/"MATCH"
	Via    string `json:"via"`    // "manual"/"feed"
	Table  string `json:"table"`  // nft table name
	Set    string `json:"set"`    // set name
	Match  string `json:"match"`  // exact ip or cidr
	Feed   string `json:"feed"`   // optional feed key
}

func RunWhich(args []string, be firewall.Backend, cfgDir string) int {
	fs := flag.NewFlagSet("which", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm which <IP> [--json]")
		return 2
	}

	arg := fs.Arg(0)

	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	if !nft.TableExistsCFM() {
		if err := be.EnsureBase(); err != nil {
			fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
			return 1
		}
	}

	rawHits, err := ipquery.Find(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	hits := make([]WhichHit, 0, len(rawHits))
	for _, h := range rawHits {
		v := "manual"
		if h.Feed != "" {
			v = "feed"
		}
		hits = append(hits, WhichHit{
			Action: h.Action,
			Via:    v,
			Table:  "inet/cfm",
			Set:    h.Set,
			Match:  h.Match,
			Feed:   h.Feed,
		})
	}

	suffix := ipquery.EnrichSuffix(cfgDir, arg)

	if *asJSON {
		b, _ := json.MarshalIndent(hits, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	if len(hits) == 0 {
		fmt.Println("(no matches)")
		return 0
	}

	fmt.Printf("Matches for %s%s:\n", arg, suffix)
	for _, h := range hits {
		feed := ""
		if h.Feed != "" {
			feed = fmt.Sprintf(" (feed: %s)", h.Feed)
		}
		fmt.Printf(" - %s via %s %s in table %s set %s%s\n", h.Action, h.Via, h.Match, h.Table, h.Set, feed)
	}
	return 0
}
