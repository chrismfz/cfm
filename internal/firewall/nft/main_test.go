package nft

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the self-IPs Lua snapshot at a temp dir for the whole
// package: EnsureBase rewrites it (refreshSelfSets), so a test driving
// EnsureBase through a fake runner replaced the live
// /var/lib/cfm/lua/cfm_self_ips.lua — the list the edge's local-origin bypass
// trusts — with test data.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfm-nft-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "nft TestMain:", err)
		os.Exit(1)
	}
	selfIPsLuaPath = filepath.Join(dir, "lua", "cfm_self_ips.lua")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
