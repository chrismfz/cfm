package cli

import (
	"errors"
	"testing"
)

type mockEngineDiag struct{ mockDiagBE }

func (m mockEngineDiag) ThrottledSetNames() []string { return []string{"throttled_v4", "throttled_v6"} }
func (m mockEngineDiag) ScannerSetNames() []string   { return []string{"port_scanners_v4", "port_scanners_v6"} }
func (m mockEngineDiag) CardinalitySetNames() map[string]string {
	return map[string]string{"block": "block_ips", "allow": "allow_ips", "ignore": "ignore_ips", "challenge": "challenge_ips", "feed": "feed_ext"}
}

func TestCollectFirewallStatusParityFieldsAcrossEngines(t *testing.T) {
	sets := map[string][]string{
		"block_ips":        {"1.1.1.1"},
		"allow_ips":        {"2.2.2.2"},
		"ignore_ips":       {},
		"challenge_ips":    {"3.3.3.3"},
		"feed_ext":         {"4.4.4.0/24"},
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
	if nft.Features["dnat"] != nftlib.Features["dnat"] {
		t.Fatalf("dnat feature mismatch")
	}
}

func TestCollectFirewallStatusUnsupportedExplicit(t *testing.T) {
	be := mockEngineDiag{mockDiagBE{dnatErr: errors.New("unsupported"), sets: map[string][]string{"block_ips": {}, "feed_ext": {}}}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if !r.Unsupported["dnat_redirect"] {
		t.Fatalf("expected explicit unsupported dnat_redirect")
	}
	if !r.Unsupported["flood_counter"] {
		t.Fatalf("expected explicit unsupported counter")
	}
}
