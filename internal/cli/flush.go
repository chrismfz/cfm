// internal/cli/flush.go
package cli

import (
	"fmt"
	"os"

	"cfm/internal/firewall"
	"cfm/internal/ttlban"
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
	// A flush is meant: the persisted TTL bans go too, or the next daemon
	// start (or a reboot) would restore them (internal/ttlban).
	if err := ttlban.Discard(ttlban.DefaultPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove %s (%v): a restart restores those bans\n", ttlban.DefaultPath, err)
	}
	fmt.Println("✔ flushed all blocked/allowed IPs")
	return 0
}
