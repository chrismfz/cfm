// internal/cli/list.go
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"cfm/internal/firewall"
)

func RunList(args []string, be firewall.Backend, tableExists func() bool) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	if tableExists == nil || !tableExists() {
		if err := be.EnsureBase(); err != nil {
			fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
			return 1
		}
	}

	entries, err := be.ListBlocks()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list error:", err)
		return 1
	}

	if *asJSON {
		type out struct {
			IP      string     `json:"ip"`
			Expires *time.Time `json:"expires,omitempty"`
			Comment string     `json:"comment,omitempty"`
		}
		data := make([]out, 0, len(entries))
		for _, e := range entries {
			data = append(data, out{IP: e.IP.String(), Expires: e.Expires, Comment: e.Comment})
		}
		b, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	if len(entries) == 0 {
		fmt.Println("(no blocked IPs)")
		return 0
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP.String() < entries[j].IP.String() })
	fmt.Printf("%-40s %-20s %s\n", "IP", "Expires", "Comment")
	for _, e := range entries {
		exp := "-"
		if e.Expires != nil {
			exp = e.Expires.Format(time.RFC3339)
		}
		fmt.Printf("%-40s %-20s %s\n", e.IP.String(), exp, e.Comment)
	}
	return 0
}

func RunAllowList(args []string, be firewall.Backend, tableExists func() bool) int {
	fs := flag.NewFlagSet("allow-list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	if tableExists == nil || !tableExists() {
		if err := be.EnsureBase(); err != nil {
			fmt.Fprintln(os.Stderr, "EnsureBase error:", err)
			return 1
		}
	}

	entries, err := be.ListAllows()
	if err != nil {
		fmt.Fprintln(os.Stderr, "list error:", err)
		return 1
	}

	if *asJSON {
		type out struct {
			IP      string     `json:"ip"`
			Expires *time.Time `json:"expires,omitempty"`
		}
		data := make([]out, 0, len(entries))
		for _, e := range entries {
			data = append(data, out{IP: e.IP.String(), Expires: e.Expires})
		}
		b, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	if len(entries) == 0 {
		fmt.Println("(no allowed IPs)")
		return 0
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP.String() < entries[j].IP.String() })
	fmt.Printf("%-40s %-20s\n", "IP", "Expires")
	for _, e := range entries {
		exp := "-"
		if e.Expires != nil {
			exp = e.Expires.Format(time.RFC3339)
		}
		fmt.Printf("%-40s %-20s\n", e.IP.String(), exp)
	}
	return 0
}
