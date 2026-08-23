package netfilterdiag

import (
	"fmt"
	"strings"
	"testing"
)

const fixture = `{"nftables":[
 {"chain":{"family":"inet","table":"imunify360","name":"PREROUTING","type":"nat","hook":"prerouting","prio":-100,"policy":"accept","handle":1}},
 {"chain":{"family":"inet","table":"cfm_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":-99,"policy":"accept","handle":2}},
 {"chain":{"family":"inet","table":"cfm","name":"input","type":"filter","hook":"input","prio":-50,"policy":"accept","handle":3}},
 {"rule":{"family":"inet","table":"imunify360","chain":"PREROUTING","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9443}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","handle":11,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}}
]}`

func TestAnalyzeOrdersHooksAndFindsCompetingNAT(t *testing.T) {
	r, err := Analyze([]byte(fixture), Expected{InputPriority: -50, DNATPriority: -99})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Chains) != 3 || r.Chains[0].Table != "imunify360" || r.Chains[1].Table != "cfm_redirect" {
		t.Fatalf("unexpected chains: %#v", r.Chains)
	}
	if len(r.NATRules) != 2 || r.NATRules[0].Owner != "imunify" {
		t.Fatalf("unexpected NAT rules: %#v", r.NATRules)
	}
	if r.Status != "ok" || !hasFinding(r, "ordered_nat_overlap") {
		t.Fatalf("missing ordered NAT visibility: %#v", r.Findings)
	}
}

func TestAnalyzeFindsPriorityAmbiguityAndDrift(t *testing.T) {
	b := strings.Replace(fixture, `"prio":-99`, `"prio":-100`, 1)
	r, err := Analyze([]byte(b), Expected{InputPriority: -50, DNATPriority: -99})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(r, "same_priority_ambiguity") || !hasFinding(r, "cfm_priority_drift") {
		t.Fatalf("findings: %#v", r.Findings)
	}
}

func TestFilterTraffic(t *testing.T) {
	r, _ := Analyze([]byte(fixture), Expected{InputPriority: -50, DNATPriority: -99})
	r = Filter(r, Filters{Hook: "prerouting", Proto: "tcp", DPort: 443})
	if len(r.Chains) != 2 || len(r.NATRules) != 2 {
		t.Fatalf("filtered report: %#v", r.Summary)
	}
	if err := ValidateFilters(Filters{Hook: "sideways"}); err == nil {
		t.Fatal("expected bad hook")
	}
}

func TestAnalyzeIgnoresLargeSetContents(t *testing.T) {
	raw := `{"nftables":[{"set":{"family":"inet","table":"cfm","name":"feed","elem":["1.1.1.1","2.2.2.2","3.3.3.3"]}},` + strings.TrimPrefix(fixture, `{"nftables":[`)
	r, err := Analyze([]byte(raw), Expected{InputPriority: -50, DNATPriority: -99})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Chains) != 3 || len(r.NATRules) != 2 {
		t.Fatalf("set contents leaked into report: %+v", r.Summary)
	}
}

func TestHasWebDNATRulesStructured(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"cfm_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":-99}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},{"dnat":{"port":9080}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}}
]}`
	if !HasWebDNATRules([]byte(raw)) {
		t.Fatal("expected structured DNAT rules to be recognized")
	}
	if HasWebDNATRules([]byte(strings.Replace(raw, `"op":"=="`, `"op":"!="`, 1))) {
		t.Fatal("negative match must not satisfy DNAT health")
	}
	contradictory := strings.Replace(raw, `{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}}`, `{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":81}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}}`, 1)
	if HasWebDNATRules([]byte(contradictory)) {
		t.Fatal("contradictory port constraints must not satisfy DNAT health")
	}
	blocked := strings.Replace(raw, `{"rule":{"family":"inet"`, `{"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","expr":[{"accept":null}]}},{"rule":{"family":"inet"`, 1)
	if HasWebDNATRules([]byte(blocked)) {
		t.Fatal("rules after an unconditional terminal verdict are unreachable")
	}
	if HasWebDNATRules([]byte(`{"nftables":[]}`)) {
		t.Fatal("empty ruleset matched")
	}
}

func TestMarsStylePanelImunifyWebOrderIsVisibleButHealthy(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"cfm_panel_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":-101}},
 {"chain":{"family":"ip","table":"imunify360","name":"PREROUTING","type":"nat","hook":"prerouting","prio":-100}},
 {"chain":{"family":"inet","table":"cfm_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":-99}},
 {"rule":{"family":"inet","table":"cfm_panel_redirect","chain":"prerouting","handle":1,"expr":[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":2087}},{"dnat":{"port":12087}}]}},
 {"rule":{"family":"ip","table":"imunify360","chain":"PREROUTING","handle":2,"expr":[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":52223}}]}},
 {"rule":{"family":"inet","table":"cfm_redirect","chain":"prerouting","handle":3,"expr":[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9043}}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{DNATPriority: -99, PanelDNATPriority: -101})
	if err != nil {
		t.Fatal(err)
	}
	if r.Chains[0].Table != "cfm_panel_redirect" || r.Chains[1].Table != "imunify360" || r.Chains[2].Table != "cfm_redirect" {
		t.Fatalf("order=%+v", r.Chains)
	}
	if r.Status != "ok" || !hasFinding(r, "ordered_nat_overlap") {
		t.Fatalf("status/findings=%s %+v", r.Status, r.Findings)
	}
}

func TestAnalyzeAnnotatesReachableJumpChainAndSkipsOrphan(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"chain":{"family":"inet","table":"vendor","name":"redirects"}},
 {"chain":{"family":"inet","table":"vendor","name":"orphan"}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[{"jump":{"target":"redirects"}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"redirects","handle":9,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"dnat":{"port":9443}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"orphan","handle":10,"expr":[{"dnat":{"port":9999}}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.NATRules) != 1 || r.NATRules[0].Chain != "redirects" || r.NATRules[0].Hook != "prerouting" || r.NATRules[0].Priority != -100 {
		t.Fatalf("rules=%+v", r.NATRules)
	}
}

func TestAnalyzeCarriesJumpTrafficConstraints(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"chain":{"family":"inet","table":"vendor","name":"redirects"}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"jump":{"target":"redirects"}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"redirects","handle":9,"expr":[{"dnat":{"port":9443}}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.NATRules) != 1 || r.NATRules[0].Protocol != "tcp" || !ruleCanMatchPort(r.NATRules[0], 443) || ruleCanMatchPort(r.NATRules[0], 80) {
		t.Fatalf("inherited constraints missing: %+v", r.NATRules)
	}
	if got := Filter(r, Filters{DPort: 80}); len(got.NATRules) != 0 {
		t.Fatalf("port filter admitted unreachable child rule: %+v", got.NATRules)
	}
}

func TestAnalyzePropagatesTerminalJumpOutcome(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"chain":{"family":"inet","table":"vendor","name":"terminal"}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[{"jump":{"target":"terminal"}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","handle":2,"expr":[{"dnat":{"port":9999}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"terminal","expr":[{"accept":null}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.NATRules) != 0 {
		t.Fatalf("rule after terminal child is unreachable: %+v", r.NATRules)
	}
}

func TestAnalyzeDoesNotOverstateMixedChildTermination(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"chain":{"family":"inet","table":"vendor","name":"mixed"}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[{"jump":{"target":"mixed"}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","handle":2,"expr":[{"dnat":{"port":9999}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"mixed","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"mixed","expr":[{"accept":null}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.NATRules) != 1 || r.NATRules[0].Handle != 2 {
		t.Fatalf("mixed child return path hid reachable parent rule: %+v", r.NATRules)
	}
}

func TestAnalyzeDoesNotTreatUnknownConditionalStatementAsUnconditional(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[{"limit":{"rate":1,"per":"second"}},{"accept":null}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","handle":2,"expr":[{"dnat":{"port":9999}}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.NATRules) != 1 || r.NATRules[0].Handle != 2 {
		t.Fatalf("conditional verdict hid reachable rule: %+v", r.NATRules)
	}
}

func TestAnalyzeFlagsNestedNATMapAsIncomplete(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","handle":1,"expr":[{"dnat":{"port":{"map":{"key":{"meta":{"key":"mark"}},"data":{"set":[9000,9001]}}}}}]}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","handle":2,"expr":[{"dnat":{"port":9999}}]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || r.Status != "warning" || !hasFinding(r, "analysis_incomplete") {
		t.Fatalf("nested NAT map did not fail visibly: %+v", r)
	}
}

func TestAnalyzeExcludesDormantTables(t *testing.T) {
	arrayFlags := `{"nftables":[
 {"table":{"family":"inet","name":"cfm_redirect"}},
 {"table":{"family":"inet","name":"vendor","flags":["dormant"]}},
 {"chain":{"family":"inet","table":"cfm_redirect","name":"prerouting","type":"nat","hook":"prerouting","prio":-99}},
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-99}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[{"dnat":{"port":9999}}]}}
]}`
	for name, raw := range map[string]string{
		"array flags":  arrayFlags,
		"scalar flags": strings.Replace(arrayFlags, `["dormant"]`, `"dormant"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := Analyze([]byte(raw), Expected{DNATPriority: -99})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Chains) != 1 || r.Chains[0].Table != "cfm_redirect" || len(r.NATRules) != 0 || hasFinding(r, "same_priority_ambiguity") {
				t.Fatalf("dormant table affected active order: chains=%+v rules=%+v findings=%+v", r.Chains, r.NATRules, r.Findings)
			}
		})
	}
}

func TestAnalyzeMetaProtocolAndPortRange(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"vendor","name":"pre","type":"nat","hook":"prerouting","prio":-100}},
 {"rule":{"family":"inet","table":"vendor","chain":"pre","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
   {"match":{"op":"==","left":{"payload":{"base":"th","offset":16,"len":16}},"right":{"range":[80,443]}}},
   {"redirect":{"port":9000}}
 ]}}
]}`
	r, err := Analyze([]byte(raw), Expected{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.NATRules) != 1 || r.NATRules[0].Protocol != "tcp" || len(r.NATRules[0].Ranges) != 1 || !ruleCanMatchPort(r.NATRules[0], 443) {
		t.Fatalf("rule=%+v", r.NATRules)
	}
}

func TestEvaluateDoesNotHideConflictBeyondPublicationCap(t *testing.T) {
	chains := make([]Chain, 0, maxPublishedChains+2)
	for i := 0; i < maxPublishedChains; i++ {
		chains = append(chains, Chain{Family: "inet", Table: fmt.Sprintf("filler%d", i), Name: "out", Hook: "output", Priority: i, Owner: "other"})
	}
	chains = append(chains,
		Chain{Family: "inet", Table: "cfm_redirect", Name: "prerouting", Hook: "prerouting", Priority: -100, Owner: "cfm"},
		Chain{Family: "ip", Table: "imunify360", Name: "PREROUTING", Hook: "prerouting", Priority: -100, Owner: "imunify"},
	)
	findings, _ := evaluate(chains, nil, Expected{DNATPriority: -99})
	found := false
	for _, f := range findings {
		if f.Code == "same_priority_ambiguity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("conflict beyond row cap was not evaluated: %+v", findings)
	}
}

func TestFilterRunsBeforePublicationLimit(t *testing.T) {
	r := Report{Status: "ok"}
	for i := 0; i < maxPublishedChains; i++ {
		r.Chains = append(r.Chains, Chain{Family: "inet", Table: fmt.Sprintf("filler%d", i), Name: "input", Hook: "input"})
	}
	r.Chains = append(r.Chains, Chain{Family: "inet", Table: "cfm_redirect", Name: "prerouting", Hook: "prerouting", Priority: -99})
	filtered := Limit(Filter(r, Filters{Hook: "prerouting"}))
	if len(filtered.Chains) != 1 || filtered.Chains[0].Table != "cfm_redirect" {
		t.Fatalf("filtered rows were lost behind global cap: %+v", filtered.Chains)
	}
}

func TestValidateFiltersAcceptsNetdevHooks(t *testing.T) {
	for _, hook := range []string{"ingress", "egress"} {
		if err := ValidateFilters(Filters{Hook: hook, Family: "netdev"}); err != nil {
			t.Fatalf("hook %s rejected: %v", hook, err)
		}
	}
}

func hasFinding(r Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
