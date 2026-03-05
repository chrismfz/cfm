// internal/cli/which.go
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	ipquery "cfm/internal/ipquery"
)

// WhichHit is exported so callers can JSON-marshal it.
type WhichHit struct {
	Action string `json:"action"` // "ALLOW"/"BLOCK"
	Via    string `json:"via"`    // "manual"/"feed"
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

	hits, err := fastWhich(be, arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
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
		fmt.Printf(" - %s via %s %s in set %s%s\n", h.Action, h.Via, h.Match, h.Set, feed)
	}
	return 0
}

// listSetNamesByPrefixes returns set names that start with any of the given
// prefixes, using a single terse nft listing (no elements printed).
func listSetNamesByPrefixes(prefixes ...string) ([]string, error) {
	out, err := exec.Command("nft", "-t", "-n", "list", "table", "inet", "cfm").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list table: %v: %s", err, string(out))
	}

	var pfx []string
	for _, p := range prefixes {
		if p = strings.TrimSpace(p); p != "" {
			pfx = append(pfx, p)
		}
	}

	var names []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		for _, p := range pfx {
			if strings.HasPrefix(name, p) {
				names = append(names, name)
				break
			}
		}
	}
	return names, nil
}

func fastWhich(be firewall.Backend, ipStr string) ([]WhichHit, error) {
	nb, ok := be.(*nft.Backend)
	if !ok {
		return nil, fmt.Errorf("nft backend required")
	}

	var hits []WhichHit

	manualHostSets := []string{"allow_v4", "block_v4", "allow_v6", "block_v6"}
	manualNetSets  := []string{"allow_v4_nets", "block_v4_nets", "allow_v6_nets", "block_v6_nets"}

	if ip := net.ParseIP(ipStr); ip != nil {
		ipNorm := ip.String()
		for _, s := range manualHostSets {
			ok, _ := nb.HasElem(s, ipNorm)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, WhichHit{Action: act, Via: "manual", Set: s, Match: ipNorm})
			}
		}
	}

	if _, nw, err := net.ParseCIDR(ipStr); err == nil && nw != nil {
		cidr := nw.String()
		for _, s := range manualNetSets {
			ok, _ := nb.HasElem(s, cidr)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, WhichHit{Action: act, Via: "manual", Set: s, Match: cidr})
			}
		}
	}

	feedSets, _ := listSetNamesByPrefixes(
		"allow_ext_v4_hosts_", "allow_ext_v6_hosts_", "allow_ext_v4_nets_", "allow_ext_v6_nets_",
		"block_ext_v4_hosts_", "block_ext_v6_hosts_", "block_ext_v4_nets_", "block_ext_v6_nets_",
	)

	if ip := net.ParseIP(ipStr); ip != nil {
		ipNorm := ip.String()
		for _, s := range feedSets {
			if !strings.Contains(s, "_hosts_") { continue }
			ok, _ := nb.HasElem(s, ipNorm)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, WhichHit{Action: act, Via: "feed", Set: s, Match: ipNorm, Feed: feedKeyFromSet(s)})
			}
		}
	}

	if _, nw, err := net.ParseCIDR(ipStr); err == nil && nw != nil {
		cidr := nw.String()
		for _, s := range feedSets {
			if !strings.Contains(s, "_nets_") { continue }
			ok, _ := nb.HasElem(s, cidr)
			if ok {
				act := "ALLOW"
				if strings.HasPrefix(s, "block_") { act = "BLOCK" }
				hits = append(hits, WhichHit{Action: act, Via: "feed", Set: s, Match: cidr, Feed: feedKeyFromSet(s)})
			}
		}
	}

	return hits, nil
}

func feedKeyFromSet(setName string) string {
	if i := strings.LastIndex(setName, "_"); i > 0 && i < len(setName)-1 {
		return setName[i+1:]
	}
	return ""
}
