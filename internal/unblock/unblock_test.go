package unblock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"cfm/internal/firewall"
)

// TestMain runs the package's tests with an empty PATH: an unblock runs csf,
// fail2ban-client, imunify360-agent and systemctl when it finds them, and a
// test must never reach the host's own. fakeTools puts fakes on it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-unblock-path-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Setenv("PATH", dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

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
