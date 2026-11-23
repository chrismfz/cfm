// internal/cli/admin.go
package cli

import (
	"fmt"
	"os"

	"cfm/internal/clihelp"
	"cfm/internal/firewall"
)

const (
	resetUsage = `usage: cfm reset
  Flush table inet cfm: every rule and set is emptied. Takes no argument.
  Restart the daemon (systemctl restart cfm) to re-apply the rules; it
  restores the TTL bans it saved (/var/lib/cfm/ttlbans.json).`
	disableUsage = `usage: cfm disable
  Delete table inet cfm: the firewall is off until the daemon builds it
  again. Takes no argument.`
)

// RunReset is `cfm reset`. It takes no argument: a help word prints the usage
// and any other argument is refused, before the backend is touched (it never
// read args, so `cfm reset --help` emptied the table).
func RunReset(args []string, be firewall.Backend) int {
	if rc, done := clihelp.NoArgs("reset", resetUsage, args); done {
		return rc
	}
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

// RunDisable is `cfm disable`. It takes no argument, like RunReset (`cfm
// disable --help` deleted the table).
func RunDisable(args []string, be firewall.Backend) int {
	if rc, done := clihelp.NoArgs("disable", disableUsage, args); done {
		return rc
	}
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
