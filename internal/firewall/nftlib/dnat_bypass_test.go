//go:build linux

package nftlib

import (
	"testing"

	"github.com/google/nftables/expr"

	"cfm/internal/firewall"
)

func TestDnatBypassRuleExprs_IPv4SingleAddress(t *testing.T) {
	entry, err := firewall.ParseDNATBypassEntry("84.54.49.205")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	exprs, err := dnatBypassRuleExprs(entry)
	if err != nil {
		t.Fatalf("build exprs: %v", err)
	}
	// Expected 5 expressions: meta nfproto, cmp nfproto, payload saddr,
	// cmp saddr, verdict accept.
	if len(exprs) != 5 {
		t.Fatalf("expected 5 expressions, got %d: %+v", len(exprs), exprs)
	}
	// Last expression must be ACCEPT verdict.
	verdict, ok := exprs[len(exprs)-1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Errorf("expected final ACCEPT verdict, got %#v", exprs[len(exprs)-1])
	}
	// First expression must be Meta(NFPROTO).
	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyNFPROTO {
		t.Errorf("expected leading nfproto meta, got %#v", exprs[0])
	}
}

func TestDnatBypassRuleExprs_IPv4CIDR_AddsBitwise(t *testing.T) {
	entry, err := firewall.ParseDNATBypassEntry("84.54.49.0/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	exprs, err := dnatBypassRuleExprs(entry)
	if err != nil {
		t.Fatalf("build exprs: %v", err)
	}
	hasBitwise := false
	for _, e := range exprs {
		if _, ok := e.(*expr.Bitwise); ok {
			hasBitwise = true
			break
		}
	}
	if !hasBitwise {
		t.Errorf("expected Bitwise mask for CIDR, missing in %+v", exprs)
	}
}

func TestDnatBypassRuleExprs_IPv6SingleAddress(t *testing.T) {
	entry, err := firewall.ParseDNATBypassEntry("2001:db8::1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	exprs, err := dnatBypassRuleExprs(entry)
	if err != nil {
		t.Fatalf("build exprs: %v", err)
	}
	// The Payload offset for source-IP differs between v4 (12,4) and
	// v6 (8,16). Verify the v6 offsets are used.
	for _, e := range exprs {
		if p, ok := e.(*expr.Payload); ok {
			if p.Offset != 8 || p.Len != 16 {
				t.Errorf("expected IPv6 payload offset=8 len=16, got offset=%d len=%d", p.Offset, p.Len)
			}
			return
		}
	}
	t.Errorf("no Payload expression in IPv6 bypass rule: %+v", exprs)
}

func TestDnatBypassIsManaged(t *testing.T) {
	if !dnatBypassIsManaged([]byte("cfm_dnat_bypass:v1:84.54.49.205")) {
		t.Errorf("expected bypass UserData to be recognised as managed")
	}
	if dnatBypassIsManaged([]byte("cfm-dnat-managed:v2:f2:p6:d80:t9080:s:a-")) {
		t.Errorf("non-bypass UserData must not be matched")
	}
	if dnatBypassIsManaged([]byte("")) {
		t.Errorf("empty UserData must not be matched")
	}
	if dnatBypassIsManaged([]byte("short")) {
		t.Errorf("shorter-than-prefix UserData must not be matched")
	}
}
