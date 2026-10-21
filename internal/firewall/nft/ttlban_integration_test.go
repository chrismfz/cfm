//go:build linux

package nft

import (
	"testing"

	"cfm/internal/firewall"
	"cfm/internal/firewall/bantest"
)

// Run it in an isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run LiveNFTTTLBans -v
func TestLiveNFTTTLBansSurviveRestart(t *testing.T) {
	bantest.RunTTLBansSurviveRestart(t, func() firewall.Backend { return New() })
}
