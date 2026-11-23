// internal/cli/flush.go
package cli

import (
	"fmt"
	"os"

	"cfm/internal/clihelp"
	"cfm/internal/firewall"
	"cfm/internal/ttlban"
)

const flushUsage = `usage: cfm flush
  Empty the block sets (every TTL ban, the IPv6 client /64s included) and
  discard the saved TTL bans, so a restart does not restore them. Takes no
  argument.`

// RunFlush is `cfm flush`. It takes no argument: a help word prints the usage
// and any other argument is refused, before the backend is touched (it never
// read args, so `cfm flush --help` freed every TTL ban).
func RunFlush(args []string, be firewall.Backend, tableExists func() bool) int {
	if rc, done := clihelp.NoArgs("flush", flushUsage, args); done {
		return rc
	}
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

	// The block sets the TTL bans live in, block_v6_clients (the automatic
	// IPv6 client /64s) included.
	for _, setName := range ttlban.Sets {
		if err := be.FlushSet("inet", "cfm", setName); err != nil {
			if setName == firewall.BlockV6Clients && firewall.IsMissingSet(err) {
				// A table an older daemon built has no such set: nothing to flush.
				fmt.Fprintf(os.Stderr, "warning: flush %s: %v\n", setName, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "flush error: %v\n", err)
			return 1
		}
	}
	// A flush is meant: the persisted TTL bans go too, or the next daemon
	// start (or a reboot) would restore them (internal/ttlban).
	if err := ttlban.Discard(ttlban.DefaultPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove %s (%v): a restart restores those bans\n", ttlban.DefaultPath, err)
	}
	fmt.Println("✔ flushed all blocked/allowed IPs")
	return 0
}
