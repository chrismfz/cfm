package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/detectors/health"
)

// A node fault (failed SMART device) is persisted durably and queryable (admin)
// as detection_history type=disk_smart_fail, carrying the severity + device key.
func TestRecordNodeFaultEvent_PersistedAndQueryable(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}

	e.RecordNodeFaultEvent(health.NodeFaultEvent{
		Type:     "disk_smart_fail",
		Severity: "critical",
		Host:     "orion.myip.gr",
		Key:      "/dev/sda",
		Message:  "SMART health FAILED on /dev/sda (WD40)",
		When:     time.Unix(1_700_000_000, 0),
	})

	rr := httptest.NewRecorder()
	e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet,
		"/api/v1/webdet/history/events?type=disk_smart_fail&limit=10", nil).WithContext(adminCtx()))
	if rr.Code != http.StatusOK {
		t.Fatalf("admin query: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Rows []HistoryEvent `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("want 1 disk_smart_fail row, got %d", len(out.Rows))
	}
	row := out.Rows[0]
	if row.Type != "disk_smart_fail" || row.Host != "orion.myip.gr" {
		t.Fatalf("core fields wrong: %+v", row)
	}
	if row.Payload["severity"] != "critical" || row.Payload["key"] != "/dev/sda" {
		t.Fatalf("payload not preserved: %+v", row.Payload)
	}
	if row.Reason == "" {
		t.Fatalf("reason should carry the human summary")
	}
}

// An empty Type is ignored (defensive — never write a typeless history row).
func TestRecordNodeFaultEvent_IgnoresEmptyType(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}
	e.RecordNodeFaultEvent(health.NodeFaultEvent{Type: "", Host: "h", Message: "x"})

	rr := httptest.NewRecorder()
	e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet,
		"/api/v1/webdet/history/events?limit=10", nil).WithContext(adminCtx()))
	var out struct {
		Rows []HistoryEvent `json:"rows"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Rows) != 0 {
		t.Fatalf("typeless fault must not be persisted, got %d rows", len(out.Rows))
	}
}
