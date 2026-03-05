// internal/cli/flush.go
package cli

import (
	"fmt"
	"os"
	"os/exec"

	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
)

func RunFlush(args []string, be firewall.Backend) int {
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

	sets := []string{"block_v4", "block_v6"}
	for _, setName := range sets {
		out, err := exec.Command("nft", "-n", "flush", "set", "inet", "cfm", setName).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "flush error: %s: %v\n", string(out), err)
			return 1
		}
	}
	fmt.Println("✔ flushed all blocked/allowed IPs")
	return 0
}
