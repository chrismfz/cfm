package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Traffic-rules action challenge_v2 (arm-surfaces slice B): the rule stores
// and simulates as challenge_v2, the bridge maps it to "challenge" on the
// wire (the edge vocabulary is block/challenge/throttle — anything else falls
// through to allow) while recording a per-(ip,host) v2 mark, and the verify
// gate consumes the mark. The mark store is bounded and fail-open.

func resetChallengeV2Marks(t *testing.T) {
	t.Helper()
	reset := func() {
		challengeV2Marks.mu.Lock()
		challengeV2Marks.m = map[string]time.Time{}
		challengeV2Marks.fullWarn = false
		challengeV2Marks.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func TestNormalizeTrafficRuleAcceptsChallengeV2(t *testing.T) {
	r, err := normalizeTrafficRule(TrafficRule{
		Priority: 250,
		Scope:    TrafficRuleScope{Vhosts: []string{"shop.gr"}},
		Match:    TrafficRuleMatch{PathAny: []string{"/checkout*"}},
		Action:   TrafficRuleAction{Type: "Challenge_V2", Profile: "soft_bot"},
	}, true)
	if err != nil {
		t.Fatalf("challenge_v2 rejected: %v", err)
	}
	if r.Action.Type != TrafficActionChallengeV2 {
		t.Fatalf("action normalized to %q", r.Action.Type)
	}
	if r.Action.Profile != "" {
		t.Fatalf("profile must be cleared for challenge tiers, got %q", r.Action.Profile)
	}
}

func TestChallengeV2MarkStore(t *testing.T) {
	resetChallengeV2Marks(t)

	// Empty inputs are no-ops; unknown pairs answer false.
	MarkChallengeV2("", "shop.gr")
	MarkChallengeV2("203.0.113.9", "")
	if challengeV2Marked("203.0.113.9", "shop.gr") {
		t.Fatalf("unmarked pair answered true")
	}

	MarkChallengeV2("203.0.113.9", "shop.gr")
	if !challengeV2Marked("203.0.113.9", "shop.gr") {
		t.Fatalf("marked pair answered false")
	}
	// Exact (ip, host) key: neither dimension bleeds.
	if challengeV2Marked("203.0.113.9", "other.gr") || challengeV2Marked("203.0.113.10", "shop.gr") {
		t.Fatalf("mark leaked across ip/host")
	}

	// Expiry is honoured (and the expired entry is dropped on read).
	challengeV2Marks.mu.Lock()
	challengeV2Marks.m["203.0.113.9|shop.gr"] = time.Now().Add(-time.Second)
	challengeV2Marks.mu.Unlock()
	if challengeV2Marked("203.0.113.9", "shop.gr") {
		t.Fatalf("expired mark answered true")
	}

	// Bounded: at the cap, unexpired pressure drops NEW marks (fail-open to a
	// plain v1 challenge) while existing marks keep refreshing.
	challengeV2Marks.mu.Lock()
	for i := 0; i < challengeV2MarkMaxKeys; i++ {
		challengeV2Marks.m["10.0.0."+string(rune('a'+i%26))+"|"+time.Duration(i).String()] = time.Now().Add(time.Hour)
	}
	full := len(challengeV2Marks.m)
	challengeV2Marks.mu.Unlock()
	MarkChallengeV2("198.51.100.7", "new.gr")
	if challengeV2Marked("198.51.100.7", "new.gr") {
		t.Fatalf("mark accepted past the cap")
	}
	// A sweep frees space once entries expire.
	challengeV2Marks.mu.Lock()
	for k := range challengeV2Marks.m {
		challengeV2Marks.m[k] = time.Now().Add(-time.Minute)
	}
	challengeV2Marks.mu.Unlock()
	MarkChallengeV2("198.51.100.7", "new.gr")
	if !challengeV2Marked("198.51.100.7", "new.gr") {
		t.Fatalf("mark refused after expiry sweep (store had %d entries)", full)
	}
}

func TestBridgeMapsChallengeV2RuleToChallengeAndMarks(t *testing.T) {
	resetChallengeV2Marks(t)
	b := NewNginxBridge("/tmp/cfm-test-rulev2.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
		return TrafficRuleEvalResult{
			Matched: true,
			Rule:    TrafficRule{ID: "r_v2"},
			Action:  TrafficActionChallengeV2,
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=203.0.113.20&host=shop.gr&uri=%2Fcheckout&method=GET&ua=x", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// On the wire the edge sees plain "challenge" (old and new edges alike)...
	if payload["rule_action"] != TrafficActionChallenge {
		t.Fatalf("rule_action=%v, want challenge", payload["rule_action"])
	}
	if payload["rule_id"] != "r_v2" {
		t.Fatalf("rule_id=%v", payload["rule_id"])
	}
	// ...and the v2 intent is recorded for the verify gate.
	if !challengeV2Marked("203.0.113.20", "shop.gr") {
		t.Fatalf("v2 mark not recorded at decision time")
	}
	// A plain challenge rule must NOT mark.
	resetChallengeV2Marks(t)
	b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
		return TrafficRuleEvalResult{Matched: true, Rule: TrafficRule{ID: "r_v1"}, Action: TrafficActionChallenge}
	}
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=203.0.113.21&host=shop.gr&uri=%2F&method=GET&ua=x", nil)
	req2.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr2, req2)
	if challengeV2Marked("203.0.113.21", "shop.gr") {
		t.Fatalf("plain challenge rule wrote a v2 mark")
	}
}

// The freeze-verbatim net must cover unknown ACTION VALUES, not only unknown
// selector keys: before this fix, load() dropped such a rule (normalize
// rejects it) and the next save DELETED it from disk — a downgraded binary
// would permanently erase a newer cfm's challenge_v2 rule (review finding).
func TestUnknownActionValueIsFrozenNotDeleted(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rules.json"
	raw := `[{"id":"r_future","priority":250,"enabled":true,` +
		`"scope":{"vhosts":["shop.gr"]},"match":{"path_any":["/x"]},` +
		`"action":{"type":"challenge_v9"},"note":"from a newer cfm"}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := newTrafficRuleStore(path)

	// The rule survives load: disabled, unsupported, never evaluated.
	got, ok := s.rules["r_future"]
	if !ok {
		t.Fatalf("unknown-action rule dropped at load")
	}
	if got.Enabled || !got.Unsupported {
		t.Fatalf("unknown-action rule enabled=%v unsupported=%v", got.Enabled, got.Unsupported)
	}
	if _, frozen := s.frozen["r_future"]; !frozen {
		t.Fatalf("unknown-action rule not frozen verbatim")
	}
	if r := s.Simulate(TrafficRuleEvalInput{Host: "shop.gr", Path: "/x", IP: "203.0.113.5"}); r.Matched {
		t.Fatalf("unsupported rule must never match")
	}

	// A save (triggered by adding an ordinary rule) keeps the ORIGINAL bytes.
	if _, err := s.Add(TrafficRule{
		Priority: 300,
		Scope:    TrafficRuleScope{Vhosts: []string{"other.gr"}},
		Match:    TrafficRuleMatch{PathAny: []string{"/y"}},
		Action:   TrafficRuleAction{Type: TrafficActionBlock},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(b), `"challenge_v9"`) || !strings.Contains(string(b), "from a newer cfm") {
		t.Fatalf("save did not keep the frozen original bytes: %s", b)
	}

	// A second store (the upgrade path in reverse) still sees it frozen.
	s2 := newTrafficRuleStore(path)
	if _, frozen := s2.frozen["r_future"]; !frozen {
		t.Fatalf("frozen rule lost across reload")
	}
}

// The panel-port decision probe (scope=panel:<port>) is observe-only for
// challenge tiers — a v2 rule matching a panel probe must NOT write the
// per-(ip,host) mark, or v2 teeth would leak into the panel human-entry
// verify (review finding).
func TestBridgePanelScopeDoesNotWriteV2Mark(t *testing.T) {
	resetChallengeV2Marks(t)
	b := NewNginxBridge("/tmp/cfm-test-rulev2-panel.sock", "tok", time.Minute, time.Minute)
	b.RuleDecision = func(in TrafficRuleEvalInput) TrafficRuleEvalResult {
		return TrafficRuleEvalResult{Matched: true, Rule: TrafficRule{ID: "r_v2"}, Action: TrafficActionChallengeV2}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=203.0.113.30&host=shop.gr&uri=%2F&method=GET&ua=x&scope=panel%3A2083", nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if challengeV2Marked("203.0.113.30", "shop.gr") {
		t.Fatalf("panel-scope decision wrote a v2 mark")
	}
}
