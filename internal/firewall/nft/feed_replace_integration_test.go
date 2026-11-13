//go:build linux

package nft

import (
	"testing"

	"cfm/internal/firewall"
	"cfm/internal/firewall/feedtest"
)

// Run it in an isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run LiveNFTFeedReplace -v
//
// Under unshare -r a large batch is capped at wmem_max, so the engine takes
// its logged chunked fallback and the prober may see the gap. Run it as real
// root in a new netns (unshare -n) for the daemon's conditions.
func TestLiveNFTFeedReplaceIsAtomic(t *testing.T) {
	feedtest.RunFeedReplaceIsAtomic(t, func() firewall.Backend { return New() })
}
