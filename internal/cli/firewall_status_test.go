package cli

import (
	"errors"
	"testing"
)

type mockDiagBE struct {
	dnat     bool
	dnatErr  error
	tableErr error
	sets     map[string][]string
}

func (m mockDiagBE) DNATStatus(family, table string) (bool, error) { return m.dnat, m.dnatErr }
func (m mockDiagBE) ListSetElementsRaw(setName string) ([]string, error) {
	if v, ok := m.sets[setName]; ok {
		return v, nil
	}
	return nil, errors.New("missing set")
}
func (m mockDiagBE) ListTableJSON(family, table string) ([]byte, error) {
	if m.tableErr != nil {
		return nil, m.tableErr
	}
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
	if r.Status != "ok" {
		t.Fatalf("expected ok got %s", r.Status)
	}
	if !r.Features["dnat"] {
		t.Fatalf("expected dnat enabled")
	}
	if r.SetSizes["block_v4"] != 0 {
		t.Fatalf("expected block_v4 size 0")
	}
}

func TestCollectFirewallStatusDegraded(t *testing.T) {
	be := mockDiagBE{tableErr: errors.New("boom"), sets: map[string][]string{}}
	r := collectFirewallStatus(be, "", "nft", "default", false)
	if r.Status != "fail" {
		t.Fatalf("expected fail got %s", r.Status)
	}
	if len(r.Findings) == 0 {
		t.Fatalf("expected findings")
	}
}

func TestCollectPolicyDomainsCanonicalDescriptors(t *testing.T) {
	raw := []byte(`{"nftables":[
		{"rule":{"chain":"input","expr":[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"drop":null}]}},
		{"rule":{"chain":"smtpblock","expr":[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[25,465]}}},{"accept":null}]}}
	]}`)
	got := collectPolicyDomains(raw)
	if len(got["base"][0].Ports) == 0 || got["base"][0].Ports[0] != "22" {
		t.Fatalf("expected canonical port 22, got %#v", got["base"][0])
	}
	if got["base"][0].Verdict != "drop" {
		t.Fatalf("expected drop verdict, got %#v", got["base"][0])
	}
	if len(got["smtp"]) != 1 {
		t.Fatalf("expected smtp domain rule, got %#v", got["smtp"])
	}
}

func TestEvaluateCanonicalChecksCategories(t *testing.T) {
	r := fwReport{
		Findings: []fwFinding{
			{Level: "fail", Message: "set(block_v4) missing (feature=ports dependency=always; expected source: core infrastructure): missing set"},
			{Level: "warn", Message: "rule condition dependency mismatch for connlimit"},
			{Level: "warn", Message: "verdict mismatch for smtp"},
		},
		Unsupported: map[string]bool{"dnat_redirect": true},
	}
	cc := evaluateCanonicalChecks(r)
	if cc.ByDomain["ports"].MissingObject == 0 {
		t.Fatalf("expected missing object bucket to increment")
	}
	if cc.ByDomain["connlimit"].MismatchedRuleCondition == 0 {
		t.Fatalf("expected mismatched rule condition bucket to increment")
	}
	if cc.ByDomain["smtp"].MismatchedVerdict == 0 {
		t.Fatalf("expected mismatched verdict bucket to increment")
	}
	if cc.ByDomain["dnat"].UnsupportedFeature == 0 {
		t.Fatalf("expected unsupported feature bucket to increment")
	}
}
