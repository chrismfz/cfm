package mailtraffic

import (
	"os"
	"testing"

	"cfm/internal/panelmap"
)

// TestMain keeps the real host out of the unit tests: the node's own
// addresses (selfip) would otherwise silently drop a test login whose IP
// happens to be on this machine's interface (a TEST-NET 192.0.2.x eth0 is
// not "private" to Go). A test about the self-IP rule stubs isSelfIP itself.
// The host's cPanel mail config (forwarders, filters) is kept out the same
// way; a test about it points cpanelEtc / mailboxHome at a temp dir.
func TestMain(m *testing.M) {
	isSelfIP = func(string) bool { return false }
	cpanelEtc = "/nonexistent/cfm-test-etc"
	panelmap.UserDataDomainsPath = "/nonexistent/cfm-test-etc/userdatadomains"
	panelmap.UserDomainsPath = "/nonexistent/cfm-test-etc/userdomains"
	mailboxHome = func(string) string { return "" }
	os.Exit(m.Run())
}
