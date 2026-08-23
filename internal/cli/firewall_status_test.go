package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockDiagBE struct {
	dnat     bool
	dnatErr  error
	tableErr error
	dnatJSON []byte
	sets     map[string][]string
	counters map[string]int64
}

func (m mockDiagBE) DNATStatus(family, table string) (bool, error) { return m.dnat, m.dnatErr }
func (m mockDiagBE) ListSetElementsRaw(setName string) ([]string, error) {
	if v, ok := m.sets[setName]; ok {
		return v, nil
	}
	return nil, errors.New("missing set")
}
func (m mockDiagBE) ListTableJSON(family, table string) ([]byte, error) {
	if table == "cfm_redirect" && m.dnatJSON != nil {
		return m.dnatJSON, nil
	}
	if m.tableErr != nil {
		return nil, m.tableErr
	}
	return []byte(`{"ok":true}`), nil
}
func (m mockDiagBE) CounterValue(name string) (int64, error) {
	if v, ok := m.counters[name]; ok {
		return v, nil
	}
	return 0, errors.New("missing counter")
}

var healthyDNATJSON = []byte(`{"nftables":[
 {"chain":{"family":"inet","table":"cfm_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":-99}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},{"dnat":{"port":9080}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}}
]}`)

type hostRulesetMock struct{ mockDiagBE }

func (m hostRulesetMock) HostRulesetJSON() ([]byte, error) { return healthyDNATJSON, nil }

func TestCollectFirewallStatusHealthy(t *testing.T) {
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "detectors.conf"), []byte("CHALLENGE_PATHS=1\n"), 0o644); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}
	be := mockDiagBE{dnat: true, dnatJSON: healthyDNATJSON, sets: map[string][]string{
		"block_v4": {}, "block_v6": {}, "block_v4_nets": {}, "block_v6_nets": {},
		"allow_v4": {}, "allow_v6": {}, "allow_v4_nets": {}, "allow_v6_nets": {},
		"ignore_v4": {}, "ignore_v6": {}, "ignore_v4_nets": {}, "ignore_v6_nets": {},
		"allow_dyn_v4": {}, "allow_dyn_v6": {},
		"challenge_v4": {}, "challenge_v6": {},
		"throttled_v4": {}, "throttled_v6": {}, "port_scanners_v4": {}, "port_scanners_v6": {},
	}}
	r := collectFirewallStatus(be, cfgDir, "nft", "default", false)
	if r.Status != "ok" {
		t.Fatalf("expected ok got %s", r.Status)
	}
	if !r.Features["dnat_edge"] {
		t.Fatalf("expected edge dnat feature enabled")
	}
	if _, ok := r.Features["dnat_challenge"]; ok {
		t.Fatalf("retired dnat_challenge feature must not be published")
	}
	if r.SetSizes["block_v4"] != 0 {
		t.Fatalf("expected block_v4 size 0")
	}
}

func TestCollectFirewallStatusFallsBackToHostRuleset(t *testing.T) {
	be := hostRulesetMock{mockDiagBE: mockDiagBE{dnat: true, tableErr: errors.New("backend table inspection unsupported"), sets: map[string][]string{}}}
	r := collectFirewallStatus(be, t.TempDir(), "nftlib", "config", false)
	for _, f := range r.Findings {
		if f.Level == "fail" && strings.Contains(f.Message, "dnat redirect") {
			t.Fatalf("host ruleset fallback failed: %+v", r.Findings)
		}
	}
}

func TestCollectFirewallStatusOpenRestyModeOnlyDNATEdgeOK(t *testing.T) {
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "detectors.conf"), []byte("OPENRESTY_MODE=1\n"), 0o644); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}
	be := mockDiagBE{
		dnat:     false,
		dnatJSON: healthyDNATJSON,
		sets: map[string][]string{
			"block_v4": {}, "block_v6": {}, "block_v4_nets": {}, "block_v6_nets": {},
			"allow_v4": {}, "allow_v6": {}, "allow_v4_nets": {}, "allow_v6_nets": {},
			"ignore_v4": {}, "ignore_v6": {}, "ignore_v4_nets": {}, "ignore_v6_nets": {},
			"allow_dyn_v4": {}, "allow_dyn_v6": {},
		},
	}
	r := collectFirewallStatus(be, cfgDir, "nft", "default", false)
	if r.FeatureChecks["dnat_edge"].Status != "pass" {
		t.Fatalf("expected dnat_edge pass got %s", r.FeatureChecks["dnat_edge"].Status)
	}
	if _, ok := r.FeatureChecks["dnat_challenge"]; ok {
		t.Fatalf("retired dnat_challenge feature check must not be published")
	}
	if _, ok := r.FeatureChecks["challenge_redirect"]; ok {
		t.Fatalf("retired challenge_redirect feature check must not be published")
	}
	for _, f := range r.Findings {
		if f.Level == "fail" {
			t.Fatalf("expected no fail findings, got %+v", r.Findings)
		}
	}
}

func TestCollectFirewallStatusBothEnabledAndHealthy(t *testing.T) {
	// Edge mode is the only mode: dnat_edge is always expected, and the legacy
	// per-IP challenge DNAT never reports armed (the daemon force-disables and
	// cleans it up on start). The deprecated OPENRESTY_MODE key in the config
	// is ignored either way.
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "detectors.conf"), []byte("OPENRESTY_MODE=1\nCHALLENGE_PATHS=1\n"), 0o644); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}
	be := mockDiagBE{
		dnat:     true,
		dnatJSON: healthyDNATJSON,
		sets: map[string][]string{
			"block_v4": {}, "block_v6": {}, "block_v4_nets": {}, "block_v6_nets": {},
			"allow_v4": {}, "allow_v6": {}, "allow_v4_nets": {}, "allow_v6_nets": {},
			"ignore_v4": {}, "ignore_v6": {}, "ignore_v4_nets": {}, "ignore_v6_nets": {},
			"allow_dyn_v4": {}, "allow_dyn_v6": {},
			"challenge_v4": {}, "challenge_v6": {},
		},
	}
	r := collectFirewallStatus(be, cfgDir, "nft", "default", false)
	if r.FeatureChecks["dnat_edge"].Status != "pass" {
		t.Fatalf("expected dnat_edge pass got %s", r.FeatureChecks["dnat_edge"].Status)
	}
	if _, ok := r.FeatureChecks["dnat_challenge"]; ok {
		t.Fatal("retired dnat_challenge feature check must not be published")
	}
	if _, ok := r.FeatureChecks["challenge_redirect"]; ok {
		t.Fatal("retired challenge_redirect feature check must not be published")
	}
}

func TestCollectFirewallStatusChallengeChecksNeverPublished(t *testing.T) {
	// Even with no OPENRESTY_MODE key at all, edge mode is the only mode:
	// the retired challenge-DNAT feature checks are never published, even
	// when challenge config and stale challenge sets are present (Phase 1c
	// of docs/edge-unification-plan.md).
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "detectors.conf"), []byte("CHALLENGE_PATHS=1\n"), 0o644); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}
	be := mockDiagBE{
		dnat:     true,
		dnatJSON: healthyDNATJSON,
		sets: map[string][]string{
			"block_v4": {}, "block_v6": {}, "block_v4_nets": {}, "block_v6_nets": {},
			"allow_v4": {}, "allow_v6": {}, "allow_v4_nets": {}, "allow_v6_nets": {},
			"ignore_v4": {}, "ignore_v6": {}, "ignore_v4_nets": {}, "ignore_v6_nets": {},
			"allow_dyn_v4": {}, "allow_dyn_v6": {},
			"challenge_v4": {}, "challenge_v6": {},
		},
	}
	r := collectFirewallStatus(be, cfgDir, "nft", "default", false)
	if r.FeatureChecks["dnat_edge"].Status != "pass" {
		t.Fatalf("expected dnat_edge pass got %s", r.FeatureChecks["dnat_edge"].Status)
	}
	if _, ok := r.FeatureChecks["dnat_challenge"]; ok {
		t.Fatal("retired dnat_challenge feature check must not be published")
	}
	if _, ok := r.FeatureChecks["challenge_redirect"]; ok {
		t.Fatal("retired challenge_redirect feature check must not be published")
	}
}

func TestEvaluateFeatureChecksRetiredKeysAbsent(t *testing.T) {
	// The legacy challenge-DNAT feature checks are retired entirely — the
	// evaluator must not publish them even when the caller passes stale keys.
	r := fwReport{Features: map[string]bool{"dnat_challenge": false, "challenge_redirect": false, "smtp": false, "portflood": false, "connlimit": false, "autoblock": false}, SetSizes: map[string]int{}, Counters: map[string]int64{}}
	checks := evaluateFeatureChecks(r)
	if _, ok := checks["dnat_challenge"]; ok {
		t.Fatal("retired dnat_challenge feature check must not be published")
	}
	if _, ok := checks["challenge_redirect"]; ok {
		t.Fatal("retired challenge_redirect feature check must not be published")
	}
	if checks["smtp"].Status != "N/A" {
		t.Fatalf("expected smtp N/A got %s", checks["smtp"].Status)
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

func TestEvaluateFeatureChecksCounterPatterns(t *testing.T) {
	r := fwReport{
		Features: map[string]bool{"portflood": true, "connlimit": true, "autoblock": true, "dnat_challenge": false, "challenge_redirect": false, "smtp": false},
		SetSizes: map[string]int{"throttled_v4": 1, "throttled_v6": 1},
		Counters: map[string]int64{
			"portflood_443_tcp": 4,
			"connlimit_443_tcp": 2,
			"badflags_drop":     1,
		},
	}
	checks := evaluateFeatureChecks(r)
	if checks["portflood"].Status != "pass" {
		t.Fatalf("expected portflood pass, got %s (%s)", checks["portflood"].Status, checks["portflood"].Reason)
	}
	if checks["connlimit"].Status != "pass" {
		t.Fatalf("expected connlimit pass, got %s (%s)", checks["connlimit"].Status, checks["connlimit"].Reason)
	}
	if checks["autoblock"].Status != "warn" {
		t.Fatalf("expected autoblock warn due to missing expected flood counters, got %s", checks["autoblock"].Status)
	}
}
