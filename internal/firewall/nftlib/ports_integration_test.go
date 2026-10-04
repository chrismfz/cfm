//go:build linux

package nftlib

import (
	"testing"

	"cfm/internal/config"
	"cfm/internal/firewall/portstest"
)

// Run it in an isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run ApplyPortsPolicyIsAtomic -v
func TestApplyPortsPolicyIsAtomicAndStable(t *testing.T) {
	portstest.RunAtomicAndStable(t, func(cfg *config.Config) portstest.Engine {
		b, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		b.cfg = cfg
		return portstest.Engine{
			EnsureBase:        b.EnsureBase,
			ApplyPortsPolicy:  b.ApplyPortsPolicy,
			DNATOn:            func() error { return b.DNATOn("inet", "cfm_redirect", 9080, 9043) },
			EnsureDNATAccepts: b.EnsureDNATAccepts,
			DNATOnPorts:       func(h, hs int) error { return b.DNATOn("inet", "cfm_redirect", h, hs) },
		}
	})
}
