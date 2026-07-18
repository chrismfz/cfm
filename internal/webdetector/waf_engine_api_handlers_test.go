package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestWAFEngineSummaryIncludesTriggerEvents(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "example.com", IP: "1.2.3.4", Mode: "logonly", Reason: "WAF_IP_HOST", Payload: map[string]interface{}{"uri": "/", "method": "get"}})

	e := &Engine{history: hs}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/waf/engine/summary?hours=24&limit=20&top=10", nil)
	ctx := adminCtx()
	req = req.WithContext(ctx)
	e.handleWAFEngineSummary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out wafEngineSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TotalEvents != 1 {
		t.Fatalf("expected total_events=1 got %d", out.TotalEvents)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("expected 1 row got %d", len(out.Rows))
	}
	if out.Rows[0].Reason != "WAF_IP_HOST" {
		t.Fatalf("expected reason WAF_IP_HOST got %q", out.Rows[0].Reason)
	}
}

// TestWAFEngineSummaryCountryAndRuleFilters asserts the country= and rule=
// filters apply BEFORE aggregation, so totals, blocked counts and top lists
// reflect only the matching events (the false-positive-hunting contract).
func TestWAFEngineSummaryCountryAndRuleFilters(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "a.com", IP: "1.1.1.1", Mode: "block", Reason: "WAF_SQLI:42", Payload: map[string]interface{}{"uri": "/x", "method": "get", "country": "CN"}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "b.com", IP: "2.2.2.2", Mode: "logonly", Reason: "WAF_XSS:7", Payload: map[string]interface{}{"uri": "/y", "method": "get", "country": "US"}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "c.com", IP: "3.3.3.3", Mode: "block", Reason: "WAF_SQLI:42", Payload: map[string]interface{}{"uri": "/z", "method": "get", "country": "US"}})

	e := &Engine{history: hs}
	call := func(query string) wafEngineSummary {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/waf/engine/summary?hours=24&limit=20&top=10"+query, nil)
		e.handleWAFEngineSummary(rr, req.WithContext(adminCtx()))
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var out wafEngineSummary
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return out
	}

	// No filter: everything counted.
	all := call("")
	if all.TotalEvents != 3 || all.BlockedEvents != 2 {
		t.Fatalf("unfiltered: total=%d blocked=%d, want 3/2", all.TotalEvents, all.BlockedEvents)
	}
	if len(all.TopCountries) != 2 {
		t.Fatalf("unfiltered top_countries=%v, want CN+US", all.TopCountries)
	}

	// Country filter: only the CN event; blocked count follows.
	cn := call("&country=cn")
	if cn.TotalEvents != 1 || cn.BlockedEvents != 1 || len(cn.Rows) != 1 || cn.Rows[0].Host != "a.com" {
		t.Fatalf("country=cn: %+v", cn)
	}
	if len(cn.TopHosts) != 1 || cn.TopHosts[0].Key != "a.com" {
		t.Fatalf("country=cn top_hosts=%v, want only a.com", cn.TopHosts)
	}
	if len(cn.CountryFilter) != 1 || cn.CountryFilter[0] != "CN" {
		t.Fatalf("country filter echo=%v", cn.CountryFilter)
	}

	// Rule filter matches rule and rule_base, case-insensitive.
	sqli := call("&rule=waf_sqli")
	if sqli.TotalEvents != 2 || len(sqli.Rows) != 2 {
		t.Fatalf("rule=waf_sqli: total=%d rows=%d, want 2/2", sqli.TotalEvents, len(sqli.Rows))
	}

	// Combined: SQLI from US only.
	both := call("&rule=waf_sqli&country=US")
	if both.TotalEvents != 1 || both.Rows[0].Host != "c.com" {
		t.Fatalf("combined filter: %+v", both)
	}
}
