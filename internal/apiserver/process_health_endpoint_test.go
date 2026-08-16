package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"cfm/internal/procstat"
	webdet "cfm/internal/webdetector"
)

func processHealthAdminRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
	return r.WithContext(ctx)
}

func TestProcessHealthEndpointSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process health reads /proc; linux only")
	}

	mux := http.NewServeMux()
	registerProcessHealthRoute(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, processHealthAdminRequest(http.MethodGet, processHealthPath))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var got struct {
		OK            bool                   `json:"ok"`
		Schema        string                 `json:"schema"`
		ProcessHealth procstat.HealthSummary `json:"process_health"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rr.Body.String())
	}
	if !got.OK {
		t.Fatal("ok = false, want true")
	}
	if got.Schema != "system.process_health.v1" {
		t.Fatalf("schema = %q, want system.process_health.v1", got.Schema)
	}
	if got.ProcessHealth.TotalProcesses <= 0 {
		t.Fatalf("total_processes = %d, want > 0", got.ProcessHealth.TotalProcesses)
	}
	if got.ProcessHealth.TotalThreads <= 0 {
		t.Fatalf("total_threads = %d, want > 0", got.ProcessHealth.TotalThreads)
	}
	if got.ProcessHealth.Scan.PIDsEnumerated <= 0 || got.ProcessHealth.Scan.PIDsReadable != got.ProcessHealth.TotalProcesses {
		t.Fatalf("inconsistent scan summary: scan=%+v total_processes=%d", got.ProcessHealth.Scan, got.ProcessHealth.TotalProcesses)
	}
	if got.ProcessHealth.Scan.PIDsSkipped != got.ProcessHealth.Scan.PIDsEnumerated-got.ProcessHealth.Scan.PIDsReadable || got.ProcessHealth.Scan.PIDsSkipped < 0 {
		t.Fatalf("invalid scan completeness accounting: %+v", got.ProcessHealth.Scan)
	}

	stateTotal := 0
	for _, n := range got.ProcessHealth.States {
		stateTotal += n
	}
	if stateTotal != got.ProcessHealth.TotalProcesses {
		t.Fatalf("state total = %d, total_processes = %d", stateTotal, got.ProcessHealth.TotalProcesses)
	}
	if len(got.ProcessHealth.TopFamiliesByCount) > 20 || len(got.ProcessHealth.TopFamiliesByRSS) > 20 || len(got.ProcessHealth.TopFanout) > 20 {
		t.Fatalf("ranked list exceeded bounded top-20: count=%d rss=%d fanout=%d",
			len(got.ProcessHealth.TopFamiliesByCount), len(got.ProcessHealth.TopFamiliesByRSS), len(got.ProcessHealth.TopFanout))
	}
	if len(got.ProcessHealth.TopFamiliesByState) == 0 {
		t.Fatal("top_families_by_state is empty, want at least the live process states")
	}
	for state, ranked := range got.ProcessHealth.TopFamiliesByState {
		if state == "" || len(ranked) > 20 {
			t.Fatalf("invalid state family ranking %q: %+v", state, ranked)
		}
		for _, f := range ranked {
			if f.Comm == "" || f.Count <= 0 {
				t.Fatalf("invalid state family row for %q: %+v", state, f)
			}
		}
	}
}

func TestProcessHealthEndpointGuards(t *testing.T) {
	mux := http.NewServeMux()
	registerProcessHealthRoute(mux)

	t.Run("admin GET only", func(t *testing.T) {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, processHealthAdminRequest(http.MethodPost, processHealthPath))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST status = %d, want 405", rr.Code)
		}
	})

	t.Run("unauthenticated denied", func(t *testing.T) {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, processHealthPath, nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated status = %d, want 403", rr.Code)
		}
	})
}
