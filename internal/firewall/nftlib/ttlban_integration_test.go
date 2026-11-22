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

// unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run LiveNFTClientSlash64 -v
func TestLiveNFTClientSlash64Bans(t *testing.T) {
	bantest.RunClientSlash64Bans(t, func() firewall.Backend {
		b, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return b
	})
}

// Every extra copy of every base rule goes, through nft text (never a netlink
// read of the input chain), in one transaction: the nft backend's
// TestLiveNFTDedupeBaseRules, the same driver.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run LiveNFTDedupe -v
func TestLiveNFTDedupeBaseRules(t *testing.T) {
	bantest.RunDedupeBaseRules(t, func() firewall.Backend {
		b, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return b
	})
}
