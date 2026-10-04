//go:build linux

package nft

import (
	"testing"

	"cfm/internal/config"
	"cfm/internal/firewall/portstest"
)

// Run it in an isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run ApplyPortsPolicyIsAtomic -v
func TestApplyPortsPolicyIsAtomicAndStable(t *testing.T) {
	portstest.RunAtomicAndStable(t, func(cfg *config.Config) portstest.Engine {
		b := New()
		b.cfg = cfg
		return portstest.Engine{
			EnsureBase:        b.EnsureBase,
			ApplyPortsPolicy:  b.ApplyPortsPolicy,
			DNATOn:            func() error { return b.DNATOn("inet", "cfm_redirect", 9080, 9043) },
			EnsureDNATAccepts: b.EnsureDNATAccepts,
		}
	})
}
