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
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
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

// TestWAFEngineSummaryForensicFilters asserts all filters apply BEFORE
// aggregation, so totals, blocked counts and top lists reflect only the
// matching events (the false-positive-hunting contract).
func TestWAFEngineSummaryForensicFilters(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "a.com", IP: "1.1.1.1", Mode: "block", Reason: "WAF_SQLI:42", Payload: map[string]interface{}{"uri": "/x", "method": "get", "country": "China", "country_iso": "CN"}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "b.com", IP: "2.2.2.2", Mode: "logonly", Reason: "WAF_XSS:7", Payload: map[string]interface{}{"uri": "/y", "method": "get", "country": "United States", "country_iso": "US"}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "c.com", IP: "3.3.3.3", Mode: "block", Reason: "WAF_SQLI:42", Payload: map[string]interface{}{
		"uri": "/checkout?step=pay", "method": "post", "country": "United States", "country_iso": "US", "waf_rule_id": 320,
		"action": "block", "ua": "Mozilla/5.0 Legit Browser", "referer": "https://c.com/Cart?OAuthToken=secret&%74oken=also-secret&View=Full", "ct": "application/x-www-form-urlencoded",
	}})

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
	if len(all.Histogram) != 24 {
		t.Fatalf("histogram buckets = %d, want 24 (one per hour)", len(all.Histogram))
	}
	histTotal, histBlocked := 0, 0
	for _, b := range all.Histogram {
		histTotal += b.Count
		histBlocked += b.Blocked
	}
	if histTotal != all.TotalEvents || histBlocked != all.BlockedEvents {
		t.Fatalf("histogram sums %d/%d != totals %d/%d", histTotal, histBlocked, all.TotalEvents, all.BlockedEvents)
	}
	if len(all.TopCountries) != 2 {
		t.Fatalf("unfiltered top_countries=%v, want China and United States", all.TopCountries)
	}
	if all.TopCountries[0].Key != "United States" || all.TopCountries[0].Count != 2 {
		t.Fatalf("unfiltered top_countries=%v, want one full-name US bucket with count 2", all.TopCountries)
	}

	// Country filter: only the CN event; blocked count follows, and so
	// does the histogram (it is built after the filters).
	cn := call("&country=cn")
	cnHist := 0
	for _, b := range cn.Histogram {
		cnHist += b.Count
	}
	if cnHist != 1 {
		t.Fatalf("filtered histogram sum = %d, want 1", cnHist)
	}
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
	numeric := call("&rule=320")
	if numeric.TotalEvents != 1 || len(numeric.Rows) != 1 || numeric.Rows[0].Host != "c.com" {
		t.Fatalf("rule=320: %+v", numeric)
	}

	// Combined forensic drill-down: one SQLI hit from the requested Greek-style
	// country/IP/vhost/path/UA facet. The row carries the raw evidence needed to
	// correlate it with the bounded access-log tools.
	both := call("&rule=waf_sqli&country=US&ip=3.3.3.3&host=C.COM&path=CHECKOUT&ua=legit%20browser")
	if both.TotalEvents != 1 || both.Rows[0].Host != "c.com" {
		t.Fatalf("combined filter: %+v", both)
	}
	row := both.Rows[0]
	if row.EventType != "waf_trigger" || row.Country != "United States" || row.CountryISO != "US" ||
		row.WAFRuleID != 320 || row.Action != "block" || row.UA != "Mozilla/5.0 Legit Browser" ||
		row.Referer != "https://c.com/Cart?OAuthToken=[redacted]&%74oken=[redacted]&View=Full" || row.ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("forensic row fields missing: %+v", row)
	}
	if both.IPFilter != "3.3.3.3" || both.HostFilter != "c.com" || both.PathFilter != "checkout" || both.UAFilter != "legit browser" {
		t.Fatalf("filter echo mismatch: %+v", both)
	}
}

func TestWAFEngineSummaryUAFilterIncludesObservations(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "shop.example", IP: "1.1.1.1", Reason: "WAF_SQLI", Payload: map[string]interface{}{"ua": "Mozilla/5.0 Legit"}})
	hs.Append(HistoryEvent{TsUnix: now, Type: "waf_observe", Host: "shop.example", IP: "1.1.1.1", Status: http.StatusForbidden, Reason: "WAF_SQLI", Payload: map[string]interface{}{"ua": "Mozilla/5.0 Legit"}})

	e := &Engine{history: hs}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/waf/engine/summary?ua=mozilla", nil).WithContext(adminCtx())
	e.handleWAFEngineSummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out wafEngineSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TotalEvents != 2 || len(out.Rows) != 2 {
		t.Fatalf("UA-filtered total=%d rows=%d, want trigger + observation", out.TotalEvents, len(out.Rows))
	}
}

func TestWAFEngineSummaryIPFilterCanonicalizesIPv6(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	hs.Append(HistoryEvent{TsUnix: time.Now().Unix(), Type: "waf_trigger", Host: "a.com", IP: "2001:0db8:0:0:0:0:0:1", Reason: "WAF_SQLI"})

	e := &Engine{history: hs}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/waf/engine/summary?ip=2001:db8::1", nil).WithContext(adminCtx())
	e.handleWAFEngineSummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out wafEngineSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TotalEvents != 1 {
		t.Fatalf("canonical IPv6 filter returned %d events, want 1", out.TotalEvents)
	}
}

// TestWAFEngineSummary_WindowedTypeFilteredRead is the regression guard for
// the dashboard-pinned-CPU incident: the summary used to read the WHOLE
// history table (every event type, unbounded time) and filter in Go — ~1.4GB
// of allocations per poll on a box with millions of rows. The read must stay
// windowed and type-filtered in SQL.
func TestWAFEngineSummary_WindowedTypeFilteredRead(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()
	// In-window WAF events (both types) — must be returned.
	hs.Append(HistoryEvent{TsUnix: now - 60, Type: "waf_trigger", Host: "a.com", IP: "1.1.1.1", Mode: "block", Reason: "WAF_SQLI:42"})
	hs.Append(HistoryEvent{TsUnix: now - 120, Type: "waf_observe", Host: "b.com", IP: "2.2.2.2", Mode: "logonly", Reason: "WAF_XSS:7"})
	// Noise the SQL filter must drop: non-WAF types in window, WAF out of window.
	hs.Append(HistoryEvent{TsUnix: now - 30, Type: "challenge_decision", Host: "a.com", IP: "3.3.3.3", Reason: "WEB/RPS"})
	hs.Append(HistoryEvent{TsUnix: now - 48*3600, Type: "waf_trigger", Host: "old.com", IP: "4.4.4.4", Mode: "block", Reason: "WAF_RCE:1"})

	hs.mu.Lock()
	got, err := hs.readWAFEventsSinceLocked(now - 24*3600)
	hs.mu.Unlock()
	if err != nil {
		t.Fatalf("readWAFEventsSinceLocked: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows=%d want=2 (non-WAF and out-of-window rows must be excluded in SQL)", len(got))
	}
	if got[0].Reason != "WAF_SQLI:42" || got[1].Reason != "WAF_XSS:7" {
		t.Fatalf("unexpected order/rows: %+v", got)
	}

	// End-to-end: the handler sees the same two events, nothing else.
	e := &Engine{history: hs}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/waf/engine/summary?hours=24&limit=20&top=10", nil).WithContext(adminCtx())
	e.handleWAFEngineSummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out wafEngineSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TotalEvents != 2 {
		t.Fatalf("total_events=%d want=2", out.TotalEvents)
	}
}
