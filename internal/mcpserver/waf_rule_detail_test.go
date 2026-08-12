package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

const rulesFixture = `{"rules":[
 {"id":320,"name":"rule_sqli","group":3,"group_name":"injection","reason_family":"WAF_SQLI","default_mode":"block"},
 {"id":210,"name":"rule_xss","group":2,"group_name":"xss","reason_family":"WAF_XSS","default_mode":"logonly"}
]}`

const webFixture = `{"hours":24,"total_events":5,"blocked_events":2,"unique_ips":3,"unique_hosts":1,
 "top_rules":[{"key":"WAF_SQLI:BLIND","count":5}],
 "top_ips":[{"key":"203.0.113.7","count":5,"country":"US"}],
 "top_hosts":[{"key":"shop.example.com","count":5}],
 "top_countries":[{"key":"US","count":5}]}`

const panelFixture = `{"ok":true,"summary":{"panel_waf":{"by_rule":[
 {"rule_id":"320","reason":"WAF_SQLI:BLIND","count":4,"scanner_hits":1,"nonscanner_hits":3,"nonscanner_would_block":3,"sample_nonscanner":["203.0.113.7 cpanel.example.com /login?x=1 Firefox/128.0"]},
 {"rule_id":"210","reason":"WAF_XSS","count":2,"scanner_hits":2,"nonscanner_hits":0,"nonscanner_would_block":0}
]}}}`

func TestWebFilterForQuery(t *testing.T) {
	rb := json.RawMessage(rulesFixture)
	if got := webFilterForQuery(rb, "320"); got != "WAF_SQLI" {
		t.Errorf("numeric id → family: got %q want WAF_SQLI", got)
	}
	if got := webFilterForQuery(rb, "sqli"); got != "sqli" {
		t.Errorf("substring passes through: got %q want sqli", got)
	}
	if got := webFilterForQuery(rb, "999"); got != "999" {
		t.Errorf("unknown numeric id passes through: got %q want 999", got)
	}
}

func TestBuildWAFRuleDetail_Family(t *testing.T) {
	out := buildWAFRuleDetail(
		json.RawMessage(webFixture), json.RawMessage(panelFixture), json.RawMessage(rulesFixture),
		"WAF_SQLI", "WAF_SQLI", 24,
	)

	matched, _ := out["matched_rules"].([]wafRuleRow)
	if len(matched) != 1 || matched[0].ID != 320 {
		t.Fatalf("matched_rules: %+v", out["matched_rules"])
	}
	web, _ := out["web"].(map[string]any)
	if web["total_events"].(int) != 5 || web["blocked_events"].(int) != 2 {
		t.Fatalf("web: %+v", web)
	}
	if out["panel_available"] != true {
		t.Fatalf("panel_available: %v", out["panel_available"])
	}
	panel, _ := out["panel"].(map[string]any)
	// Only the WAF_SQLI row must be folded in, not the WAF_XSS one.
	if panel["hits"].(int) != 4 || panel["nonscanner_would_block"].(int) != 3 {
		t.Fatalf("panel agg: %+v", panel)
	}
	ids, _ := panel["matched_rule_ids"].([]string)
	if len(ids) != 1 || ids[0] != "320" {
		t.Fatalf("panel matched ids: %v", ids)
	}
	// Must warn about the non-scanner would-block and the block-tier default.
	notes, _ := out["notes"].([]string)
	var sawFP, sawBlock bool
	for _, n := range notes {
		if strings.Contains(n, "non-scanner") {
			sawFP = true
		}
		if strings.Contains(n, "default_mode=block") {
			sawBlock = true
		}
	}
	if !sawFP || !sawBlock {
		t.Fatalf("expected FP + block-tier notes, got %v", notes)
	}
}

func TestBuildWAFRuleDetail_NumericQueryAndPanelUnavailable(t *testing.T) {
	// Numeric query "320" resolves the panel match by rule_id; panel body is an
	// error stub → panel omitted with a note, web still present.
	out := buildWAFRuleDetail(
		json.RawMessage(webFixture),
		json.RawMessage(`{"error":"no edge error log on this host"}`),
		json.RawMessage(rulesFixture),
		"320", "WAF_SQLI", 24,
	)
	if out["panel_available"] != false {
		t.Fatalf("panel_available should be false, got %v", out["panel_available"])
	}
	if out["panel"] != nil {
		t.Fatalf("panel should be nil when unavailable, got %v", out["panel"])
	}
	matched, _ := out["matched_rules"].([]wafRuleRow)
	if len(matched) != 1 || matched[0].ID != 320 {
		t.Fatalf("numeric query matched_rules: %+v", out["matched_rules"])
	}
	notes, _ := out["notes"].([]string)
	var sawUnavail bool
	for _, n := range notes {
		if strings.Contains(n, "panel burn-in unavailable") {
			sawUnavail = true
		}
	}
	if !sawUnavail {
		t.Fatalf("expected panel-unavailable note, got %v", notes)
	}
}
