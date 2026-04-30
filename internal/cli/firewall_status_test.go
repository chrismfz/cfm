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
	be := mockDiagBE{dnat:true, sets: map[string][]string{"block_ips":{"1.1.1.1"},"allow_ips":{},"ignore_ips":{},"challenge_ips":{"2.2.2.2"},"feed_ext":{}}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if r.Status != "ok" { t.Fatalf("expected ok got %s", r.Status) }
	if !r.Features["dnat"] { t.Fatalf("expected dnat enabled") }
	if r.SetSizes["block_ips"] != 1 { t.Fatalf("expected block size 1") }
}

func TestCollectFirewallStatusDegraded(t *testing.T) {
	be := mockDiagBE{tableErr: errors.New("boom"), sets: map[string][]string{}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if r.Status != "fail" { t.Fatalf("expected fail got %s", r.Status) }
	if len(r.Findings) == 0 { t.Fatalf("expected findings") }
}
