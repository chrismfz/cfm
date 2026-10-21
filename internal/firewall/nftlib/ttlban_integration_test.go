//go:build linux

package nftlib

import (
	"testing"

	"cfm/internal/firewall"
	"cfm/internal/firewall/bantest"
)

// Run it in an isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run LiveNFTTTLBans -v
func TestLiveNFTTTLBansSurviveRestart(t *testing.T) {
	bantest.RunTTLBansSurviveRestart(t, func() firewall.Backend {
		b, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return b
	})
}
