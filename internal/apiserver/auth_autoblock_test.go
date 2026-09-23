package apiserver

import (
	"net"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// authBlockBackend holds one permanently blocked address and records adds.
type authBlockBackend struct {
	stubFirewallBackend
	permanent string
	batches   []firewall.BlockEntry
	adds      []*time.Duration
}

func (b *authBlockBackend) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	var r firewall.BlockBatchResult
	for _, e := range entries {
		b.batches = append(b.batches, e)
		if e.IP.String() == b.permanent {
			r.Kept++
		} else {
			r.Added++
		}
	}
	return r, nil
}

func (b *authBlockBackend) AddBlock(_ net.IP, _ string, ttl *time.Duration) error {
	b.adds = append(b.adds, ttl)
	return nil
}

// A ttl login brute-force block never shortens an existing block: AddBlock
// replaced a permanent block of the address with a timed one.
func TestAuthAutoblockApply_TTLNeverShortens(t *testing.T) {
	be := &authBlockBackend{permanent: "198.51.100.8"}
	ttl := 24 * time.Hour
	if got := authAutoblockApply(be, net.ParseIP("198.51.100.8"), "ttl", &ttl); got != authBlockKept {
		t.Errorf("ttl over a permanent block = %q, want %q", got, authBlockKept)
	}
	if got := authAutoblockApply(be, net.ParseIP("198.51.100.9"), "ttl", &ttl); got != authBlockDone {
		t.Errorf("ttl block = %q, want %q", got, authBlockDone)
	}
	if len(be.adds) != 0 {
		t.Errorf("ttl mode used AddBlock, which replaces the element")
	}
	if len(be.batches) != 2 || be.batches[1].TTL != ttl || be.batches[1].Permanent {
		t.Errorf("batches = %+v, want two 24h entries", be.batches)
	}

	if got := authAutoblockApply(be, net.ParseIP("198.51.100.8"), "permanent", nil); got != authBlockDone || len(be.adds) != 1 || be.adds[0] != nil {
		t.Errorf("permanent = %q with adds %v, want one permanent AddBlock", got, be.adds)
	}
	if got := authAutoblockApply(be, net.ParseIP("198.51.100.10"), "dryrun", nil); got != authBlockDone || len(be.adds) != 1 || len(be.batches) != 2 {
		t.Errorf("dryrun = %q and added something", got)
	}
}
