package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestHistoryEventsEnrichParam asserts enrich=1 is accepted and keeps the
// rows shape (enrichment itself is a no-op without a loaded enricher).
func TestHistoryEventsEnrichParam(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	hs.Append(HistoryEvent{TsUnix: time.Now().Unix(), Type: "waf_trigger", Host: "a.com", IP: "1.2.3.4", Reason: "WAF_X"})

	e := &Engine{history: hs}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webdet/history/events?limit=10&enrich=1", nil)
	e.handleHistoryEvents(rr, req.WithContext(adminCtx()))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Rows []historyEventView `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Rows) != 1 || out.Rows[0].Host != "a.com" {
		t.Fatalf("rows=%+v", out.Rows)
	}
}
