package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Emergency rules: match.until (an expiry) and the throttle_total action (one
// budget for all matching clients, per vhost or node).

func emergencyRule(id string, until time.Time, action TrafficRuleAction) TrafficRule {
	r := TrafficRule{
		ID: id, Enabled: true, Priority: 1,
		Scope:  TrafficRuleScope{Vhosts: []string{"*"}},
		Match:  TrafficRuleMatch{UAAny: []string{"*meta-externalagent*"}},
		Action: action,
	}
	if !until.IsZero() {
		r.Match.Until = until.UTC().Format(time.RFC3339)
	}
	return r
}

func TestTrafficRuleUntil(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	ua := "Mozilla/5.0 (compatible; meta-externalagent/1.1)"
	in := TrafficRuleEvalInput{Host: "shop.gr", IP: "57.141.20.1", UA: ua, Path: "/"}

	if _, err := s.Add(emergencyRule("past", time.Now().Add(-time.Minute), TrafficRuleAction{Type: "block"})); err == nil || !strings.Contains(err.Error(), "past") {
		t.Fatalf("a rule with a past until was accepted: %v", err)
	}
	if _, err := s.Add(TrafficRule{ID: "bad", Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{"*"}}, Match: TrafficRuleMatch{UAAny: []string{"*x*"}, Until: "tomorrow"}, Action: TrafficRuleAction{Type: "block"}}); err == nil {
		t.Fatal("a non-RFC3339 until was accepted")
	}
	r, err := s.Add(emergencyRule("deny6h", time.Now().Add(6*time.Hour), TrafficRuleAction{Type: "block"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Simulate(in); !got.Matched || got.Action != "block" {
		t.Fatalf("a live until rule did not match: %+v", got)
	}

	// Past its until it matches nothing (no restart, no write needed).
	s.mu.Lock()
	cur := s.rules[r.ID]
	cur.Match.untilAt = time.Now().Add(-time.Second)
	s.rules[r.ID] = cur
	s.mu.Unlock()
	if got := s.Simulate(in); got.Matched {
		t.Fatalf("an expired rule still enforces: %+v", got)
	}

	// Pruned by a write a day after it expired, not before.
	s.mu.Lock()
	cur.Match.untilAt = time.Now().Add(-expiredRuleKeep - time.Minute)
	s.rules[r.ID] = cur
	s.mu.Unlock()
	if _, err := s.Add(emergencyRule("other", time.Now().Add(time.Hour), TrafficRuleAction{Type: "block"})); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(r.ID); ok {
		t.Fatal("a rule expired over a day ago survived a write")
	}
	if _, ok := s.Get("other"); !ok {
		t.Fatal("the live rule was pruned")
	}

	// until survives a save and a reload.
	s2 := newTrafficRuleStore(s.path)
	got, ok := s2.Get("other")
	if !ok || got.Match.Until == "" || got.Match.untilAt.IsZero() {
		t.Fatalf("reloaded rule lost its until: %+v", got)
	}
}

// The shared matcher honours an until (traffic rules; Challenge Access refuses one at normalize).
func TestUntilInSharedMatcher(t *testing.T) {
	m, err := normalizeMatch(TrafficRuleMatch{UAAny: []string{"*x*"}, Until: time.Now().Add(-time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if ruleMatchFilters(m, netip.MustParseAddr("203.0.113.1"), true, "", "x", "/", "GET", "", "") {
		t.Fatal("ruleMatchFilters matched past an until")
	}
}

func TestTrafficRuleThrottleTotalValidation(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	for _, a := range []TrafficRuleAction{
		{Type: "throttle_total", RateRPS: 0, Per: "node"},
		{Type: "throttle_total", RateRPS: 5, Per: "client"},
		{Type: "throttle_total", RateRPS: 1e6, Per: "vhost"},
	} {
		if _, err := s.Add(emergencyRule(fmt.Sprintf("bad%v%s", a.RateRPS, a.Per), time.Time{}, a)); err == nil {
			t.Fatalf("invalid throttle_total accepted: %+v", a)
		}
	}
	r, err := s.Add(emergencyRule("tt", time.Now().Add(time.Hour), TrafficRuleAction{Type: "THROTTLE_TOTAL", RateRPS: 5, Per: " Node ", Profile: "soft_bot"}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Action.Type != "throttle_total" || r.Action.Per != "node" || r.Action.Profile != "" || r.Action.RateRPS != 5 {
		t.Fatalf("normalized action = %+v", r.Action)
	}
	// Switching the rule to block clears the throttle fields.
	r.Action.Type = "block"
	u, err := s.Update(r.ID, r)
	if err != nil || u.Action.RateRPS != 0 || u.Action.Per != "" {
		t.Fatalf("block kept throttle fields: %+v %v", u.Action, err)
	}
}

func TestBridgeMapsThrottleTotal(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-rule-total.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
		return TrafficRuleEvalResult{
			Matched: true,
			Rule:    TrafficRule{ID: "r_total", Action: TrafficRuleAction{Type: "throttle_total", RateRPS: 5, Per: "node"}},
			Action:  "throttle_total",
		}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/decision?ip=57.141.20.1&host=shop.gr&uri=%2F&method=GET&ua=x", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	var p map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["rule_action"] != "throttle" || p["throttle_rate"] != 5.0 || p["throttle_per"] != "node" || p["rule_id"] != "r_total" {
		t.Fatalf("decision = %v, want rule_action throttle + rate 5 + per node + the rule id", p)
	}
}

func TestTrafficRuleIPAnyCap(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	ips := make([]string, maxIPsPerRule)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	r := emergencyRule("ips", time.Now().Add(time.Hour), TrafficRuleAction{Type: "block"})
	r.Match.IPAny = ips
	if _, err := s.Add(r); err != nil {
		t.Fatalf("%d IPs refused: %v", maxIPsPerRule, err)
	}
	r.ID = "ips2"
	r.Match.IPAny = append(ips, "10.9.9.9")
	if _, err := s.Add(r); err == nil {
		t.Fatalf("%d IPs accepted", maxIPsPerRule+1)
	}
}

// A stored rule whose action carries a key this build does not know is frozen
// (kept verbatim, never enforced), like an unknown match key or action type.
func TestDecodeStoredRuleFreezesUnknownActionKey(t *testing.T) {
	raw := json.RawMessage(`{"id":"x","enabled":true,"priority":1,"scope":{"vhosts":["*"]},"match":{"ua_any":["*a*"]},"action":{"type":"throttle_total","rate_rps":5,"per":"node","burst_shape":"x"}}`)
	if _, frozen := decodeStoredRule(raw); !frozen {
		t.Fatal("an unknown action key was not frozen")
	}
	ok := json.RawMessage(`{"id":"y","enabled":true,"priority":1,"scope":{"vhosts":["*"]},"match":{"ua_any":["*a*"],"until":"2099-01-01T00:00:00Z"},"action":{"type":"throttle_total","rate_rps":5,"per":"node"}}`)
	if _, frozen := decodeStoredRule(ok); frozen {
		t.Fatal("this build froze its own throttle_total / until rule")
	}
	// An until rule survives a reload of a file this build wrote.
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`[`+string(ok)+`]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTrafficRuleStore(path)
	if r, found := s.Get("y"); !found || r.Unsupported || r.Action.Type != "throttle_total" {
		t.Fatalf("reload: %+v found=%v", r, found)
	}
}

// rules-model.js LIMITS mirrors the emergency-rule bounds (the editor refuses
// before the save round-trip; a drift would let the page offer what the
// daemon refuses, or refuse what it takes).
func TestEmergencyLimitsMirroredInRulesModel(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("..", "webui", "static", "assets", "webdet", "rules-model.js"))
	if err != nil {
		t.Skipf("rules-model.js not found: %v", err)
	}
	for key, want := range map[string]string{
		"ipsPerRule":       fmt.Sprint(maxIPsPerRule),
		"throttleTotalMin": fmt.Sprint(minThrottleTotalRPS),
		"throttleTotalMax": fmt.Sprint(maxThrottleTotalRPS),
	} {
		m := regexp.MustCompile(`\n\s*` + key + `:\s*([0-9.]+),`).FindSubmatch(js)
		if m == nil || string(m[1]) != want {
			t.Errorf("rules-model.js LIMITS.%s = %q, want %s (traffic_rules.go)", key, m, want)
		}
	}
	for _, a := range []string{TrafficActionThrottleTotal} {
		if !strings.Contains(string(js), `key: "`+a+`"`) {
			t.Errorf("rules-model.js ACTIONS has no %q", a)
		}
	}
}

// An export taken before an emergency rule expired does not bring it back on
// import; a live one round-trips with its until and total throttle.
func TestTrafficRulesImportUntil(t *testing.T) {
	dst, mux := newTestEngine(t)
	live := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	doc := TrafficRulesExportDoc{Format: trafficRulesExportFormat, Version: 1, Rules: []TrafficRuleExport{
		{Enabled: true, Priority: 5, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Match: TrafficRuleMatch{UAAny: []string{"*x*"}, Until: "2001-01-01T00:00:00Z"}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
	}}
	code, res := importVia(t, mux, true, "", doc)
	if code != http.StatusBadRequest || res.Invalid != 1 || !strings.Contains(res.Items[0].Error, "past") {
		t.Fatalf("expired rule import: %d %+v", code, res)
	}
	doc.Rules[0].Match.Until = live
	doc.Rules[0].Action = TrafficRuleAction{Type: TrafficActionThrottleTotal, RateRPS: 5, Per: "node"}
	if code, res := importVia(t, mux, true, "", doc); code != http.StatusOK || res.Add != 1 {
		t.Fatalf("live rule import: %d %+v", code, res)
	}
	got := dst.TrafficRuleList()
	if len(got) != 1 || got[0].Match.Until != live || got[0].Action.RateRPS != 5 || got[0].Action.Per != "node" {
		t.Fatalf("stored = %+v", got)
	}
}

// An expired rule can still be disabled with its own (past) until; a changed
// past until is refused; Remove prunes like the other writes.
func TestTrafficRuleExpiredStaysEditable(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	r, err := s.Add(emergencyRule("e", time.Now().Add(time.Hour), TrafficRuleAction{Type: "block"}))
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	s.mu.Lock()
	cur := s.rules[r.ID]
	cur.Match.untilAt, cur.Match.Until = past, past.Format(time.RFC3339)
	s.rules[r.ID] = cur
	s.mu.Unlock()

	off := cur
	off.Enabled = false
	if _, err := s.Update(r.ID, off); err != nil {
		t.Fatalf("disabling an expired rule with its own until: %v", err)
	}
	off.Match.Until = past.Add(-time.Minute).Format(time.RFC3339)
	if _, err := s.Update(r.ID, off); err == nil {
		t.Fatal("a changed past until was accepted")
	}

	s.mu.Lock()
	cur = s.rules[r.ID]
	cur.Match.untilAt = time.Now().Add(-expiredRuleKeep - time.Minute)
	s.rules[r.ID] = cur
	s.mu.Unlock()
	o, _ := s.Add(emergencyRule("o", time.Now().Add(time.Hour), TrafficRuleAction{Type: "block"}))
	s.mu.Lock()
	s.rules["stale"] = cur // re-plant one to see Remove prune it
	s.mu.Unlock()
	s.Remove(o.ID)
	if _, ok := s.Get("stale"); ok {
		t.Fatal("Remove did not prune a rule expired over a day ago")
	}
}

func TestRulesCLISummaryShowsEmergencyFields(t *testing.T) {
	m, _ := normalizeMatch(TrafficRuleMatch{IPAny: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"}, Until: "2099-01-01T00:00:00Z"})
	got := rulesMatchSummary(m)
	if !strings.Contains(got, "+1 more") || !strings.Contains(got, "until=2099-01-01T00:00:00Z") {
		t.Fatalf("summary = %q", got)
	}
	if got := rulesMatchSummary(TrafficRuleMatch{Until: "2099-01-01T00:00:00Z"}); !strings.HasPrefix(got, "(none)") {
		t.Fatalf("an until-only match must still read (none): %q", got)
	}
	if d := rulesActionDetail(TrafficRuleAction{Type: TrafficActionThrottleTotal, RateRPS: 2.5, Per: "node"}); d != "2.5r/s/node" {
		t.Fatalf("detail = %q", d)
	}
}

// Challenge Access shares the match grammar but not the emergency extras.
func TestChallengeAccessRefusesEmergencyExtras(t *testing.T) {
	base := ChallengeAccessEntry{Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}}
	e := base
	e.Match.UAAny = []string{"*x*"}
	e.Match.Until = "2099-01-01T00:00:00Z"
	if _, err := normalizeChallengeAccess(e, true); err == nil {
		t.Fatal("an access entry with until was accepted")
	}
	e = base
	for i := 0; i <= maxPatternsPerField; i++ {
		e.Match.IPAny = append(e.Match.IPAny, fmt.Sprintf("10.0.0.%d", i+1))
	}
	if _, err := normalizeChallengeAccess(e, true); err == nil {
		t.Fatal("an access entry over the old ip_any cap was accepted")
	}
	e.Match.IPAny = e.Match.IPAny[:maxPatternsPerField]
	if _, err := normalizeChallengeAccess(e, true); err != nil {
		t.Fatalf("an access entry at the cap: %v", err)
	}
}

// The Web Traffic page's emergency payloads (emergency-model.js
// buildEmergencyRule, as the browser posts them) are rules this daemon takes.
func TestWebTrafficEmergencyPayloadsAccepted(t *testing.T) {
	s := newTrafficRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, body := range []string{
		`{"enabled":true,"priority":1,"scope":{"vhosts":["*"]},"match":{"ua_any":["*meta-externalagent*"],"until":"` + until + `"},"action":{"type":"throttle_total","rate_rps":2.5,"per":"node"},"note":"emergency: meta load"}`,
		`{"enabled":true,"priority":2,"scope":{"vhosts":["shop.gr"]},"match":{"ip_any":["83.212.158.22","2a02:587:1:2::/64"],"until":"` + until + `"},"action":{"type":"block"},"note":"emergency: scraper"}`,
		`{"enabled":true,"priority":3,"scope":{"vhosts":["*"]},"match":{"ua_any":["-"],"until":"` + until + `"},"action":{"type":"throttle","profile":"hard_bot"},"note":"emergency: no UA"}`,
	} {
		var r TrafficRule
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Add(r); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
	}
	got := s.Simulate(TrafficRuleEvalInput{Host: "shop.gr", IP: "2a02:587:1:2::99", UA: "Mozilla/5.0 Chrome/152", Path: "/"})
	if !got.Matched || got.Action != "block" {
		t.Fatalf("an address inside the /64 is not denied: %+v", got)
	}
}
