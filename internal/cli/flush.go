// internal/cli/flush.go
package cli

import (
	"fmt"
	"os"

	"cfm/internal/firewall"
)

func RunFlush(args []string, be firewall.Backend, tableExists func() bool) int {
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

	sets := []string{"block_v4", "block_v6"}
	for _, setName := range sets {
		if err := be.FlushSet("inet", "cfm", setName); err != nil {
			fmt.Fprintf(os.Stderr, "flush error: %v\n", err)
			return 1
		}
	}
	fmt.Println("✔ flushed all blocked/allowed IPs")
	return 0
}
