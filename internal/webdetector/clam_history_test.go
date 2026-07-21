package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/clam"
)

// A ClamAV infection is persisted and then queryable, scoped, via the existing
// history endpoint (type=clam_infected). The rich payload notify drops
// (filename/uri/evidence) survives, and a different tenant cannot read it.
func TestRecordClamScanEvent_ScopedIngest(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}

	e.RecordClamScanEvent(clam.ScanEvent{
		EventType: "clam_infected",
		Host:      "victim.example.com",
		IP:        "203.0.113.7",
		URI:       "/wp-content/uploads/x.php",
		FileName:  "x.php",
		Signature: "Php.Malware.Agent",
		Evidence:  "/var/lib/cfm/scanner/infected/x.php",
		When:      time.Unix(1_700_000_000, 0),
	})

	query := "/api/v1/webdet/history/events?type=clam_infected&host=victim.example.com&limit=10"

	// The vhost owner sees the infection with its full payload.
	rr := httptest.NewRecorder()
	e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet, query, nil).WithContext(scopedCtx("victim.example.com")))
	if rr.Code != http.StatusOK {
		t.Fatalf("owner query: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Rows []HistoryEvent `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("want 1 clam_infected row, got %d", len(out.Rows))
	}
	row := out.Rows[0]
	if row.Type != "clam_infected" || row.Host != "victim.example.com" || row.Reason != "Php.Malware.Agent" {
		t.Fatalf("row core fields wrong: %+v", row)
	}
	if row.Payload["filename"] != "x.php" || row.Payload["uri"] != "/wp-content/uploads/x.php" {
		t.Fatalf("payload not preserved: %+v", row.Payload)
	}

	// A different tenant querying that host is refused (scope isolation).
	rr2 := httptest.NewRecorder()
	e.handleHistoryEvents(rr2, httptest.NewRequest(http.MethodGet, query, nil).WithContext(scopedCtx("other.example.com")))
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant clam history query: status=%d, want 403", rr2.Code)
	}
}

// A sig-ignored infection is still persisted (visible, greyed, in the UI) but
// carries the downgrade markers so UI/CLI can distinguish it from an acted-on
// verdict.
func TestRecordClamScanEvent_SigIgnoredPayload(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	e := &Engine{history: hs}

	e.RecordClamScanEvent(clam.ScanEvent{
		EventType:  "clam_infected",
		Host:       "docs.example.com",
		IP:         "203.0.113.9",
		FileName:   "report.docx",
		Signature:  "YARA.SIGNATURE_BASE_Brooxml_Hunting.UNOFFICIAL",
		SigIgnored: true,
		IgnoredBy:  "config:*_Hunting.UNOFFICIAL",
		When:       time.Unix(1_700_000_100, 0),
	})

	rr := httptest.NewRecorder()
	e.handleHistoryEvents(rr, httptest.NewRequest(http.MethodGet,
		"/api/v1/webdet/history/events?type=clam_infected&host=docs.example.com&limit=5", nil).
		WithContext(scopedCtx("docs.example.com")))
	if rr.Code != http.StatusOK {
		t.Fatalf("query: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Rows []HistoryEvent `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(out.Rows))
	}
	p := out.Rows[0].Payload
	if p["sig_ignored"] != true || p["ignored_by"] != "config:*_Hunting.UNOFFICIAL" {
		t.Fatalf("downgrade markers missing from payload: %+v", p)
	}
	// A non-ignored event must NOT carry the markers (absent, not false).
	e.RecordClamScanEvent(clam.ScanEvent{
		EventType: "clam_infected", Host: "docs.example.com", IP: "203.0.113.9",
		Signature: "Win.Trojan.Hide-1", When: time.Unix(1_700_000_200, 0),
	})
	rr2 := httptest.NewRecorder()
	e.handleHistoryEvents(rr2, httptest.NewRequest(http.MethodGet,
		"/api/v1/webdet/history/events?type=clam_infected&host=docs.example.com&limit=5", nil).
		WithContext(scopedCtx("docs.example.com")))
	// Fresh struct: Unmarshal into the reused `out` would MERGE payload map
	// keys of reused row elements and fake a contaminated payload.
	var out2 struct {
		Rows []HistoryEvent `json:"rows"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("unmarshal second query: %v", err)
	}
	for _, row := range out2.Rows {
		if row.Reason == "Win.Trojan.Hide-1" {
			if _, present := row.Payload["sig_ignored"]; present {
				t.Fatalf("real verdict must not carry sig_ignored: %+v", row.Payload)
			}
		}
	}
}
