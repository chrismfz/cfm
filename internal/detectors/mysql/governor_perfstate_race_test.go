package mysql

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestPerfCapabilityFlags_NoRaceWithHandleCPU guards the data race between the
// poll goroutine (which writes the perf_schema / userstat capability flags) and
// the HTTP goroutine serving /api/v1/mysql/cpu (which reads them). The flags are
// atomic.Bool; if anyone reverts them to plain bool, `go test -race` turns this
// red — a concurrent write in the writer goroutine against the read in
// handleCPU. handleCPU runs on a bare &Governor{} (PerfDeltas() just returns an
// empty slice under perfDeltaMu; no DB handle needed).
func TestPerfCapabilityFlags_NoRaceWithHandleCPU(t *testing.T) {
	g := &Governor{}
	const iters = 2000

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: mimics the poll goroutine (probePerfSchema/fetchPerfDeltas).
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			on := i%2 == 0
			g.perfSchemaOK.Store(on)
			g.perfHasCPU.Store(on)
			g.perfCPUActive.Store(!on)
			g.userstatsOK.Store(on)
			g.userstatsOff.Store(!on)
		}
	}()

	// Reader: mimics an operator/UI polling /api/v1/mysql/cpu.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/mysql/cpu", nil)
			g.handleCPU(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("handleCPU status = %d, want 200", rr.Code)
				return
			}
		}
	}()

	wg.Wait()
}
