//go:build linux

package nftlib

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// Every DNAT accepts read of the input chain (web ensure and cleanup, panel
// ensure) is bounded by firewall.InputAcceptsNFTTimeout, not by
// ListChainText's 5 s diagnostic deadline, which EL8's 4-12 s listing ran past
// (`cfm edge on` failed on virgo, 2026-11-28). With the budget shortened and
// the listing hung, each returns well before 5 s: a read still on the 5 s
// deadline fails the test. TestInputAcceptsNFTTimeout_FitsEL8 pins the budget.
func TestInputAcceptsRead_UsesItsBudget(t *testing.T) {
	if firewall.InputAcceptsNFTTimeout < firewall.BaseInputReadTimeout {
		t.Fatalf("InputAcceptsNFTTimeout = %v, below EnsureBase's %v", firewall.InputAcceptsNFTTimeout, firewall.BaseInputReadTimeout)
	}
	old := firewall.InputAcceptsNFTTimeout
	firewall.InputAcceptsNFTTimeout = 300 * time.Millisecond
	t.Cleanup(func() { firewall.InputAcceptsNFTTimeout = old })

	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %q
if [ "$1" = "-f" ]; then cat >/dev/null; exit 0; fi
if [ "$*" = "-a list chain inet cfm input" ]; then exec sleep 30; fi
exit 0
`, filepath.Join(dir, "nft.log"))
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	b := &Backend{}
	spec := []dnatRuleSpec{{proto: 6, dport: 80, toPort: 9080}}
	for _, c := range []struct {
		name    string
		run     func() error
		wantErr bool
	}{
		{"ListInput", func() error { _, err := b.inputAcceptOps().ListInput(); return err }, true},
		{"web ensure", func() error { return b.ensureScopedDNATAccepts(dnatAcceptNamespaceEdge, spec, true) }, true},
		{"web cleanup", func() error { return b.cleanupScopedDNATAccepts(dnatAcceptNamespaceEdge) }, false},
		{"panel ensure", func() error { _, err := b.EnsurePanelDNATAccepts(); return err }, true},
	} {
		start := time.Now()
		err := c.run()
		took := time.Since(start)
		if c.wantErr && err == nil {
			t.Errorf("%s: a hung listing read as success", c.name)
		}
		if took >= 4*time.Second {
			t.Errorf("%s took %v with a 300ms budget: the read is not bounded by InputAcceptsNFTTimeout", c.name, took)
		}
	}
}
