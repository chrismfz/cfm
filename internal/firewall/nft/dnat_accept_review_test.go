//go:build linux

package nft

import (
	"strings"
	"testing"
)

// nftOut runs `nft -f -` (script mode); a leading-dash arg is a CLI flag and a
// syntax error there. The runtime guard must reject it before executing nft, so
// a mistaken `nftOut("-a list …")` can never silently return garbage again.
func TestNftOutRejectsLeadingFlag(t *testing.T) {
	b := New()
	out, err := b.nftOut("-a list chain inet cfm input")
	if err == nil {
		t.Fatalf("nftOut(\"-a list …\") returned nil error; want a rejection (out=%q)", out)
	}
	if !strings.Contains(err.Error(), "script mode") {
		t.Errorf("unexpected error text: %v", err)
	}
	// A normal script expression is still accepted by the guard (it will fail
	// later for other reasons in a sandbox, but not on the leading-dash check).
	if _, err := b.nftOut("list tables"); err != nil && strings.Contains(err.Error(), "starts with a CLI flag") {
		t.Errorf("guard wrongly rejected a non-flag expression: %v", err)
	}
}
