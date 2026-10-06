package webdetector

// also_rule_ids: the OTHER cfm_waf rules that matched a request behind the
// headline. The edge ships them on the ip_push (cfm_waf.also_rule_ids); the
// bridge sanitizes them, the trigger hook logs them, the history payload keeps
// them, and the WAF summary counts a numeric-rule filter's behind-the-headline
// matches. Without this a logonly rule placed after a stronger one (the 421-439
// dropper/backdoor scanners sit behind 402/404) never appears anywhere.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSanitizeAlsoRuleIDs(t *testing.T) {
	cases := []struct {
		name     string
		in       []int
		headline int
		want     []int
	}{
		{"empty", nil, 301, nil},
		{"drops the headline, sorts, de-duplicates", []int{612, 422, 404, 422, 612}, 404, []int{422, 612}},
		{"drops non-positive and out-of-range ids", []int{0, -5, 100000, 433, 10014}, 0, []int{433, 10014}},
		{"only the headline left is nil", []int{404, 404}, 404, nil},
		// The cap keeps the FIRST ids in evaluation order, then sorts: capping
		// after a sort would always drop the high ids (the 10xxx CVE band).
		{"caps at maxAlsoRuleIDs in input order", []int{10014, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}, 0,
			[]int{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10014}},
	}
	for _, c := range cases {
		got := sanitizeAlsoRuleIDs(c.in, c.headline)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: sanitizeAlsoRuleIDs(%v, %d) = %v, want %v", c.name, c.in, c.headline, got, c.want)
		}
	}
}

func TestWAFPushCarriesAlsoRuleIDsToTheHook(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test-also.sock", "tok", time.Minute, time.Minute)
	var got []int
	var gotID int
	b.SetTriggerHook(func(_, _, _ string, _ time.Duration, _, _, _ string, wafRuleID int, _, _, _, _ string, also []int) {
		gotID, got = wafRuleID, also
	})
	code := postIPPush(t, b, `{"ip":"203.0.113.71","action":"challenge_v2","host":"shop.example","uri":"/up.php","method":"post",`+
		`"reason":"WAF_PHP_WEBSHELL_BODY:X","waf_rule_id":404,"ttl_sec":600,"also_rule_ids":[612,422,404,422,-1,999999]}`)
	if code != http.StatusOK {
		t.Fatalf("push rejected: code=%d", code)
	}
	if gotID != 404 || !reflect.DeepEqual(got, []int{422, 612}) {
		t.Fatalf("hook got (waf_rule_id=%d, also=%v), want (404, [422 612])", gotID, got)
	}

	// A malformed also_rule_ids is dropped, never a decode error: the push
	// still stores its decision (telemetry must not break enforcement).
	got = []int{1}
	code = postIPPush(t, b, `{"ip":"203.0.113.75","action":"block","host":"shop.example","uri":"/x","method":"get",`+
		`"reason":"WAF_SQLI:X","waf_rule_id":301,"ttl_sec":600,"also_rule_ids":"oops"}`)
	b.mu.Lock()
	_, stored := b.ipState["203.0.113.75"]
	b.mu.Unlock()
	if code != http.StatusOK || !stored || got != nil {
		t.Fatalf("malformed also_rule_ids: code=%d stored=%v also=%v, want 200, a stored decision and nil", code, stored, got)
	}
	code = postIPPush(t, b, `{"ip":"203.0.113.76","action":"block","host":"shop.example","uri":"/x","method":"get",`+
		`"reason":"WAF_SQLI:X","waf_rule_id":301,"ttl_sec":600,"also_rule_ids":[422.5,"612",433,1e3]}`)
	if code != http.StatusOK || !reflect.DeepEqual(got, []int{433, 1000}) {
		t.Fatalf("mixed also_rule_ids: code=%d also=%v, want 200 and [433 1000]", code, got)
	}

	// An older edge sends no also_rule_ids: the hook gets nil, nothing else changes.
	got = []int{1}
	code = postIPPush(t, b, `{"ip":"203.0.113.72","action":"logonly","host":"shop.example","uri":"/","method":"get",`+
		`"reason":"WAF_FETCH_METADATA:NO_FETCH_META_NO_ACCEPT_LANG","waf_rule_id":612,"ttl_sec":600}`)
	if code != http.StatusOK || got != nil {
		t.Fatalf("push without also_rule_ids: code=%d also=%v, want 200 and nil", code, got)
	}
}

func TestRecordWAFTriggerStoresAlsoRuleIDs(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}
	e.RecordWAFTrigger("203.0.113.73", "shop.example", "/up.php", "post", "challenge_v2",
		"WAF_PHP_WEBSHELL_BODY:X", time.Minute, 0, "", "", "", 404, "ua", "", "", "", []int{422, 612})
	e.RecordWAFTrigger("203.0.113.74", "shop.example", "/", "get", "logonly",
		"WAF_FETCH_METADATA:NO_FETCH_META_NO_ACCEPT_LANG", time.Minute, 0, "", "", "", 612, "ua", "", "", "", nil)

	evs, err := hs.QueryEvents("", "", "waf_trigger", 10)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	var with, without int
	for _, ev := range evs {
		if ids := payloadIntSlice(ev.Payload["also_rule_ids"]); len(ids) > 0 {
			with++
			if !reflect.DeepEqual(ids, []int{422, 612}) {
				t.Fatalf("stored also_rule_ids = %v, want [422 612]", ids)
			}
		} else {
			if _, present := ev.Payload["also_rule_ids"]; present {
				t.Fatalf("an empty also list must not be stored")
			}
			without++
		}
	}
	if with != 1 || without != 1 {
		t.Fatalf("history rows with/without also_rule_ids = %d/%d, want 1/1", with, without)
	}
}

func TestWAFEngineSummaryCountsAlsoMatchesForANumericRule(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()
	// 422 as the headline once, behind 404 twice (in-memory []int and the
	// []any shape a JSON round trip produces), and an unrelated event.
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "a.example", IP: "198.51.100.1", Mode: "logonly",
		Reason: "WAF_DROPPER:WGET_CURL", Payload: map[string]interface{}{"uri": "/x.php", "method": "post", "waf_rule_id": 422}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "a.example", IP: "198.51.100.2", Mode: "challenge_v2",
		Reason: "WAF_PHP_WEBSHELL_BODY:X", Payload: map[string]interface{}{"uri": "/y.php", "method": "post", "waf_rule_id": 404,
			"also_rule_ids": []int{422, 612}}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "b.example", IP: "198.51.100.3", Mode: "challenge_v2",
		Reason: "WAF_PHP_WEBSHELL_BODY:X", Payload: map[string]interface{}{"uri": "/z.php", "method": "post", "waf_rule_id": float64(404),
			"also_rule_ids": []any{float64(422)}}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "b.example", IP: "198.51.100.4", Mode: "block",
		Reason: "WAF_SQLI:X", Payload: map[string]interface{}{"uri": "/q", "method": "get", "waf_rule_id": 301}})

	e := &Engine{history: hs}
	get := func(q string) wafEngineSummary {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/waf/engine/summary?hours=24&limit=20&top=10&"+q, nil)
		req = req.WithContext(adminCtx())
		e.handleWAFEngineSummary(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", q, rr.Code, rr.Body.String())
		}
		var out wafEngineSummary
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return out
	}

	// Without also=1 a numeric filter keeps its headline-only meaning (the
	// cfm-admin WAF page and waf_activity rely on it).
	if out := get("rule=422"); out.TotalEvents != 1 || out.AlsoMatches != 0 {
		t.Fatalf("rule=422: total=%d also_matches=%d, want 1 and 0 (headline only)", out.TotalEvents, out.AlsoMatches)
	}
	out := get("rule=422&also=1")
	if out.TotalEvents != 3 || out.AlsoMatches != 2 {
		t.Fatalf("rule=422&also=1: total=%d also_matches=%d, want 3 and 2", out.TotalEvents, out.AlsoMatches)
	}
	seen := 0
	for _, r := range out.Rows {
		if r.WAFRuleID == 404 && len(r.AlsoRuleIDs) > 0 {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("rule=422: %d rows carry also_rule_ids behind 404, want 2", seen)
	}

	// The headline rule still counts only its own events, none of them "also".
	if out := get("rule=404&also=1"); out.TotalEvents != 2 || out.AlsoMatches != 0 {
		t.Fatalf("rule=404: total=%d also_matches=%d, want 2 and 0", out.TotalEvents, out.AlsoMatches)
	}
	// A family/substring filter keeps its headline-only meaning.
	if out := get("rule=WAF_DROPPER&also=1"); out.TotalEvents != 1 || out.AlsoMatches != 0 {
		t.Fatalf("rule=WAF_DROPPER: total=%d also_matches=%d, want 1 and 0", out.TotalEvents, out.AlsoMatches)
	}
}
