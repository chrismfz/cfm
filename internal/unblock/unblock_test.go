package unblock

import (
	"context"
	"errors"
	"net"
	"testing"

	"cfm/internal/firewall"
)

// ensureCounter records the backend calls an unblock makes.
type ensureCounter struct {
	firewall.Backend
	ensureBase int
	removed    []string
}

func (c *ensureCounter) EnsureBase() error { c.ensureBase++; return nil }
func (c *ensureCounter) RemoveBlock(ip net.IP) error {
	c.removed = append(c.removed, ip.String())
	return nil
}
func (c *ensureCounter) ListTableTextNoDNS(string, string) (string, error) {
	return "", errors.New("no feed sets in this test")
}

// An unblock removes the IP by key and never runs EnsureBase: removing needs
// no base ruleset, and EnsureBase costs dozens of nft processes (10-70s on
// busy nodes), which used to run twice per unblock.
func TestDo_NoEnsureBase(t *testing.T) {
	be := &ensureCounter{}
	res, err := Do(context.Background(), net.ParseIP("198.51.100.1"), Options{BE: be})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if be.ensureBase != 0 {
		t.Errorf("EnsureBase ran %d times, want 0", be.ensureBase)
	}
	if len(be.removed) != 1 || be.removed[0] != "198.51.100.1" || !res.WasBlocked {
		t.Errorf("removed %v (was_blocked=%v), want the IP removed once", be.removed, res.WasBlocked)
	}
}
