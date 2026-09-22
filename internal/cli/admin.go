// internal/cli/admin.go
package cli

import (
	"fmt"
	"os"

	"cfm/internal/firewall"
)

func RunReset(args []string, be firewall.Backend) int {
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	if err := be.ResetTable(); err != nil {
		fmt.Fprintln(os.Stderr, "reset error:", err)
		return 1
	}
	fmt.Println("✔ reset: flushed table inet cfm (rules & sets emptied)")
	fmt.Println("  restart the daemon (systemctl restart cfm) to re-apply the firewall rules and blocklists")
	return 0
}

func RunDisable(args []string, be firewall.Backend) int {
	if be == nil {
		fmt.Fprintln(os.Stderr, "no firewall backend available")
		return 1
	}
	if err := be.DropEverything(); err != nil {
		fmt.Fprintln(os.Stderr, "disable error:", err)
		return 1
	}
	fmt.Println("✔ disable: deleted table inet cfm (firewall off)")
	return 0
}
