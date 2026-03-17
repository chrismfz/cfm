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
