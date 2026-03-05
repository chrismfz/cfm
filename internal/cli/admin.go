// internal/cli/admin.go
package cli

import (
	"fmt"
	"os"

	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
)

func RunReset(args []string, be firewall.Backend) int {
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	nb, ok := be.(*nft.Backend)
	if !ok {
		fmt.Fprintln(os.Stderr, "reset: unsupported backend")
		return 1
	}
	if err := nb.ResetTable(); err != nil {
		fmt.Fprintln(os.Stderr, "reset error:", err)
		return 1
	}
	fmt.Println("✔ reset: flushed table inet cfm (rules & sets emptied)")
	return 0
}

func RunDisable(args []string, be firewall.Backend) int {
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	nb, ok := be.(*nft.Backend)
	if !ok {
		fmt.Fprintln(os.Stderr, "disable: unsupported backend")
		return 1
	}
	if err := nb.DropEverything(); err != nil {
		fmt.Fprintln(os.Stderr, "disable error:", err)
		return 1
	}
	fmt.Println("✔ disable: deleted table inet cfm (firewall off)")
	return 0
}
