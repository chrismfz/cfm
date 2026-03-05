// internal/cli/test.go
package cli

import "fmt"

func RunTest() {
	fmt.Println("== cfm test ==")

	type check struct {
		name string
		fn   func() (string, bool)
	}

	checks := []check{
		{"nft (binary)", func() (string, bool) { return HasBinary("nft") }},
		{"iptables (binary)", func() (string, bool) { return HasBinary("iptables") }},
		{"ip6tables (binary)", func() (string, bool) { return HasBinary("ip6tables") }},
		{"ipset (binary)", func() (string, bool) { return HasBinary("ipset") }},
		{"kernel module: nf_tables", func() (string, bool) { return HasModule("nf_tables") }},
		{"kernel module: ip_tables", func() (string, bool) { return HasModule("ip_tables") }},
		{"kernel module: xt_owner", func() (string, bool) { return HasModule("xt_owner") }},
	}

	for _, c := range checks {
		msg, ok := c.fn()
		status := "OK"
		if !ok {
			status = "MISSING"
		}
		fmt.Printf(" - %-28s : %-7s %s\n", c.name, status, msg)
	}

	fmt.Printf("\nDetected backend preference: %s\n", detectBackend())
}

func detectBackend() string {
	if _, ok := LookPath("nft"); ok {
		return "nftables"
	}
	if _, ok := LookPath("iptables"); ok {
		return "iptables"
	}
	return "none"
}
