package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfm/internal/traffic"
)

type staticTrafficSnapshotter struct {
	snapshot traffic.Snapshot
}

func (s staticTrafficSnapshotter) Snapshot() traffic.Snapshot { return s.snapshot }

func TestTrafficSummaryRequiresAdmin(t *testing.T) {
	SetTrafficSnapshotSource(staticTrafficSnapshotter{snapshot: traffic.Snapshot{}})
	t.Cleanup(func() { SetTrafficSnapshotSource(nil) })

	mux := http.NewServeMux()
	RegisterTrafficEndpoints(mux)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/summary", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTrafficSummaryIncludesSchemaAndCapabilities(t *testing.T) {
	SetTrafficSnapshotSource(staticTrafficSnapshotter{snapshot: traffic.Snapshot{
		TsUnix:           123,
		WindowSec:        1,
		ProcessSupported: true,
		ProcessPartial:   true,
		Totals:           traffic.TotalsSnapshot{InBPS: 8, OutBPS: 16, ActiveConnections: 2},
	}})
	t.Cleanup(func() { SetTrafficSnapshotSource(nil) })

	mux := http.NewServeMux()
	RegisterTrafficEndpoints(mux)

	rr := httptest.NewRecorder()
	req := trafficAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/traffic/summary", nil))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["schema_version"] != trafficSchemaVersion {
		t.Fatalf("schema_version mismatch: %#v", out["schema_version"])
	}
	caps, _ := out["capabilities"].(map[string]any)
	if caps["process_attribution"] != true || caps["partial_process_attribution"] != true {
		t.Fatalf("capabilities missing/incorrect: %#v", caps)
	}
}

func TestTrafficConnectionsSortAndLimit(t *testing.T) {
	SetTrafficSnapshotSource(staticTrafficSnapshotter{snapshot: traffic.Snapshot{
		TsUnix: 1, WindowSec: 1,
		Flows: []traffic.FlowSnapshot{
			{FlowID: "a", InBPS: 10, OutBPS: 20, LastSeenUnix: 100},
			{FlowID: "b", InBPS: 80, OutBPS: 1, LastSeenUnix: 300},
			{FlowID: "c", InBPS: 40, OutBPS: 2, LastSeenUnix: 200},
		},
	}})
	t.Cleanup(func() { SetTrafficSnapshotSource(nil) })

	mux := http.NewServeMux()
	RegisterTrafficEndpoints(mux)

	rr := httptest.NewRecorder()
	req := trafficAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/traffic/connections?limit=2&sort=last_seen", nil))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var out struct {
		Rows []traffic.FlowSnapshot `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out.Rows))
	}
	if out.Rows[0].FlowID != "b" || out.Rows[1].FlowID != "c" {
		t.Fatalf("unexpected order: %+v", out.Rows)
	}
}

func TestTrafficHistoryWindow(t *testing.T) {
	SetTrafficSnapshotSource(staticTrafficSnapshotter{snapshot: traffic.Snapshot{
		TsUnix: 11,
		Windows: map[string]traffic.WindowAggSnapshot{
			"60s": {WindowSec: 60, Totals: traffic.TotalsSnapshot{InBytes: 10}},
		},
	}})
	t.Cleanup(func() { SetTrafficSnapshotSource(nil) })

	mux := http.NewServeMux()
	RegisterTrafficEndpoints(mux)

	rr := httptest.NewRecorder()
	req := trafficAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/traffic/history?window=60s", nil))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = trafficAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/traffic/history?window=10s", nil))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown window, got %d", rr.Code)
	}
}
