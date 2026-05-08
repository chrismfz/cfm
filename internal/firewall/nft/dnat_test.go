//go:build linux

package nft

import (
	"strings"
	"testing"
)

func TestDNATAcceptRuleExprCanInsertBeforeDefaultDropHandle(t *testing.T) {
	spec := dnatAcceptRuleSpecs(9080, 9043)[0]
	chain := `table inet cfm {
		chain input {
			ct state new tcp dport 0-65535 drop # handle 41
			ct state new udp dport 0-65535 drop # handle 42
		}
	}`
	handle := firstInputDefaultDropHandle(chain)
	if handle != "41" {
		t.Fatalf("firstInputDefaultDropHandle() = %q, want 41", handle)
	}
	got := dnatAcceptRuleExpr(spec, handle)
	if !strings.HasPrefix(got, "insert rule inet cfm input position 41 ") {
		t.Fatalf("DNAT accept rule was not handle-inserted before default drops: %q", got)
	}
	if strings.HasPrefix(got, "add rule inet cfm input ") {
		t.Fatalf("DNAT accept rule used append syntax that can place it after default drops: %q", got)
	}
}
