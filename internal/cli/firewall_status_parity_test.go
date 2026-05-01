package cli

import (
	"errors"
	"testing"
)

type mockEngineDiag struct{ mockDiagBE }

func (m mockEngineDiag) ThrottledSetNames() []string { return []string{"throttled_v4", "throttled_v6"} }
func (m mockEngineDiag) ScannerSetNames() []string   { return []string{"port_scanners_v4", "port_scanners_v6"} }
func (m mockEngineDiag) CardinalitySetNames() map[string]string {
	return map[string]string{"block": "block_v4", "allow": "allow_v4", "ignore": "ignore_v4", "challenge": "challenge_v4", "feed": "block_ext_v4_hosts"}
}

func TestCollectFirewallStatusParityFieldsAcrossEngines(t *testing.T) {
	sets := map[string][]string{
		"block_v4":         {"1.1.1.1"},
		"allow_v4":         {"2.2.2.2"},
		"ignore_v4":        {},
		"challenge_v4":     {"3.3.3.3"},
		"block_ext_v4_hosts":{"4.4.4.4"},
		"throttled_v4":     {"5.5.5.5"},
		"throttled_v6":     {},
		"port_scanners_v4": {},
		"port_scanners_v6": {},
	}
	nft := collectFirewallStatus(mockEngineDiag{mockDiagBE{dnat: true, sets: sets}}, "", "nft", "default", false)
	nftlib := collectFirewallStatus(mockEngineDiag{mockDiagBE{dnat: true, sets: sets}}, "", "nftlib", "default", false)

	keys := []string{"block_cardinality", "allow_cardinality", "ignore_cardinality", "challenge_cardinality", "feed_cardinality", "throttled_v4", "port_scanners_v4"}
	for _, k := range keys {
		if _, ok := nft.SetSizes[k]; !ok {
			t.Fatalf("nft missing field %s", k)
		}
		if _, ok := nftlib.SetSizes[k]; !ok {
			t.Fatalf("nftlib missing field %s", k)
		}
	}
	if nft.Features["dnat_challenge"] != nftlib.Features["dnat_challenge"] {
		t.Fatalf("dnat feature mismatch")
	}
}

func TestCollectFirewallStatusUnsupportedExplicit(t *testing.T) {
	be := mockEngineDiag{mockDiagBE{dnatErr: errors.New("unsupported"), sets: map[string][]string{"block_v4": {}, "block_ext_v4_hosts": {}}}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if !r.Unsupported["dnat_redirect"] {
		t.Fatalf("expected explicit unsupported dnat_redirect")
	}
	if !r.Unsupported["flood_counter"] {
		t.Fatalf("expected explicit unsupported counter")
	}
}
