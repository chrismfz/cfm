package cli

import (
	"errors"
	"testing"
)

type mockDiagBE struct {
	dnat bool
	dnatErr error
	tableErr error
	sets map[string][]string
}

func (m mockDiagBE) DNATStatus(family, table string) (bool, error) { return m.dnat, m.dnatErr }
func (m mockDiagBE) ListSetElementsRaw(setName string) ([]string, error) {
	if v, ok := m.sets[setName]; ok { return v, nil }
	return nil, errors.New("missing set")
}
func (m mockDiagBE) ListTableJSON(family, table string) ([]byte, error) {
	if m.tableErr != nil { return nil, m.tableErr }
	return []byte(`{"ok":true}`), nil
}

func TestCollectFirewallStatusHealthy(t *testing.T) {
	be := mockDiagBE{dnat: true, sets: map[string][]string{
		"block_v4": {}, "block_v6": {}, "block_v4_nets": {}, "block_v6_nets": {},
		"allow_v4": {}, "allow_v6": {}, "allow_v4_nets": {}, "allow_v6_nets": {},
		"ignore_v4": {}, "ignore_v6": {}, "ignore_v4_nets": {}, "ignore_v6_nets": {},
		"allow_dyn_v4": {}, "allow_dyn_v6": {},
		"challenge_v4": {}, "challenge_v6": {},
		"throttled_v4": {}, "throttled_v6": {}, "port_scanners_v4": {}, "port_scanners_v6": {},
	}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if r.Status != "ok" { t.Fatalf("expected ok got %s", r.Status) }
	if !r.Features["dnat"] { t.Fatalf("expected dnat enabled") }
	if r.SetSizes["block_v4"] != 0 { t.Fatalf("expected block_v4 size 0") }
}

func TestCollectFirewallStatusDegraded(t *testing.T) {
	be := mockDiagBE{tableErr: errors.New("boom"), sets: map[string][]string{}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if r.Status != "fail" { t.Fatalf("expected fail got %s", r.Status) }
	if len(r.Findings) == 0 { t.Fatalf("expected findings") }
}
