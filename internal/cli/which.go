// internal/cli/which.go
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"cfm/internal/firewall"
	ipquery "cfm/internal/ipquery"
	"cfm/internal/locate"
)

// RunWhich implements `cfm which|search <IP|CIDR>`: a read-only,
// multi-source lookup across nft, cfm.deny, csf, fail2ban and
// imunify360 (sources that aren't installed are reported as skipped).
func RunWhich(args []string, be firewall.Backend, cfgDir string, tableExists func() bool) int {
	fs := flag.NewFlagSet("which", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: cfm which <IP|CIDR> [--json]")
		return 2
	}

	arg := fs.Arg(0)

	if be != nil && (tableExists == nil || !tableExists()) {
		if err := be.EnsureBase(); err != nil {
			fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
			return 1
		}
	}

	res, err := locate.FindWithTimeout(arg, locate.Options{
		BE:        be,
		ConfigDir: cfgDir,
	}, 20*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	suffix := ipquery.EnrichSuffix(cfgDir, arg)

	if len(res.Locations) == 0 {
		fmt.Println("(no matches)")
	} else {
		fmt.Printf("Matches for %s%s:\n", arg, suffix)
		for _, l := range res.Locations {
			line := fmt.Sprintf(" - %s via %s %s [%s]", l.Action, l.Source, l.List, l.Match)
			if l.Feed != "" {
				line += fmt.Sprintf(" (feed: %s)", l.Feed)
			}
			if l.Reason != "" {
				line += " — " + l.Reason
			}
			fmt.Println(line)
		}
	}

	if len(res.Skipped) > 0 {
		srcs := make([]string, 0, len(res.Skipped))
		for s := range res.Skipped {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs)
		for _, s := range srcs {
			fmt.Printf("(skipped: %s — %s)\n", s, res.Skipped[s])
		}
	}
	return 0
}
