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

// A memory-ECC event is persisted durably and then queryable (admin) via the
// history endpoint as type=hardware_ecc — the whole point being that it survives
// the live counters (a reboot resets EDAC; the dmesg ring wraps).
func TestRecordHardwareECCEvent_PersistedAndQueryable(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}

	e.RecordHardwareECCEvent(health.ECCEvent{
		Kind:             "uncorrected",
		Host:             "orion.myip.gr",
		When:             time.Unix(1_700_000_000, 0),
		Corrected:        12,
		Uncorrected:      1,
		DeltaCorrected:   0,
		DeltaUncorrected: 1,
		WorstDIMM:        "CPU0_DIMM_A1",
		Source:           "edac_sysfs",
	})

	rr := httptest.NewRecorder()
	e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet,
		"/api/v1/webdet/history/events?type=hardware_ecc&limit=10", nil).WithContext(adminCtx()))
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
		t.Fatalf("want 1 hardware_ecc row, got %d", len(out.Rows))
	}
	row := out.Rows[0]
	if row.Type != "hardware_ecc" || row.Host != "orion.myip.gr" {
		t.Fatalf("core fields wrong: %+v", row)
	}
	if row.Payload["kind"] != "uncorrected" || row.Payload["worst_dimm"] != "CPU0_DIMM_A1" {
		t.Fatalf("payload not preserved: %+v", row.Payload)
	}
	// The reason line summarises it for a human scanning the timeline.
	if row.Reason == "" {
		t.Fatalf("reason should summarise the event, got empty")
	}
}
