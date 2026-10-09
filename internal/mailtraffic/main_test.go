package mailtraffic

import (
	"os"
	"testing"
)

// TestMain keeps the real host out of the unit tests: the node's own
// addresses (selfip) would otherwise silently drop a test login whose IP
// happens to be on this machine's interface (a TEST-NET 192.0.2.x eth0 is
// not "private" to Go). A test about the self-IP rule stubs isSelfIP itself.
func TestMain(m *testing.M) {
	isSelfIP = func(string) bool { return false }
	os.Exit(m.Run())
}
