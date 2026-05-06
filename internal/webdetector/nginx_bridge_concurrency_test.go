package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHandleDecision_ShedsAboveSemaphoreCap saturates the decisionSem manually
// (by acquiring all slots before the call) and verifies the handler shed-paths
// the request: instant fail-open allow/allow JSON response, X-CFM-Bridge-Shed
// header set, stats.shedCount incremented. The 8×NumCPU production cap would
// require huge concurrency to trip in a unit test; saturating the channel
// directly is precise and deterministic.
func TestHandleDecision_ShedsAboveSemaphoreCap(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)

	// Saturate every slot in decisionSem so the next request *must* shed.
	cap := decisionConcurrencyCap()
	for i := 0; i < cap; i++ {
		b.decisionSem <- struct{}{}
	}
	defer func() {
		// Drain so other tests aren't affected if this enricher is shared.
		for i := 0; i < cap; i++ {
			<-b.decisionSem
		}
	}()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/nginx/decision?ip=203.0.113.7&host=example.com&scope=web", nil)
	req.Header.Set("X-CFM-Token", "tok")

	start := time.Now()
	b.handleDecision(rr, req)
	elapsed := time.Since(start)

	// Shed path is constant-time: token check + channel select default + JSON
	// encode of a 2-field map. Should be far under 50ms in any reasonable env.
	if elapsed > 50*time.Millisecond {
		t.Fatalf("shed path took %v, expected <50ms", elapsed)
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("shed response status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	if got := rr.Header().Get("X-CFM-Bridge-Shed"); got != "1" {
		t.Fatalf("X-CFM-Bridge-Shed=%q, want %q", got, "1")
	}

	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("shed body not valid JSON: %v body=%s", err, rr.Body.String())
	}
	if payload["ip_action"] != "allow" || payload["vhost_action"] != "allow" {
		t.Fatalf("shed response should be allow/allow, got %+v", payload)
	}

	// Critical: rule_action MUST be set so cfm.lua's decision cache
	// filter (cfm.lua:675 — `not obj.rule_action`) skips caching the
	// shed response. Without this, a brief saturation amplifies into
	// 90 seconds of degraded enforcement via the Lua-side cache.
	if payload["rule_action"] != "shed" {
		t.Fatalf("shed response must include rule_action=shed to bypass Lua cache, got %+v", payload)
	}

	// Counter must reflect this single shed.
	b.stats.mu.Lock()
	shed := b.stats.shedCount
	b.stats.mu.Unlock()
	if shed != 1 {
		t.Fatalf("stats.shedCount=%d, want 1", shed)
	}

	// And it must be visible via the BridgeStats snapshot path that cfm
	// status / JSON API actually use.
	st := b.snapshotBridgeStats(0, 0)
	if st.Timing.SheddedCount != 1 {
		t.Fatalf("BridgeStats.Timing.SheddedCount=%d, want 1", st.Timing.SheddedCount)
	}
}

// TestHandleDecision_NormalLoadDoesNotShed confirms that normal traffic at
// realistic concurrency (well below the cap) does NOT shed. We launch N
// concurrent decision calls where N is much smaller than the cap and assert
// shedCount stays at zero.
func TestHandleDecision_NormalLoadDoesNotShed(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)

	// Realistic burst: 16 concurrent in-flight requests. Even on a 1-core
	// container the cap is 32 (floor), so 16 must NOT shed.
	const N = 16

	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet,
				"/nginx/decision?ip=203.0.113.7&host=example.com&scope=web", nil)
			req.Header.Set("X-CFM-Token", "tok")
			b.handleDecision(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if rr.Header().Get("X-CFM-Bridge-Shed") == "1" {
				t.Errorf("normal-load request was shed")
			}
		}()
	}
	wg.Wait()

	b.stats.mu.Lock()
	shed := b.stats.shedCount
	b.stats.mu.Unlock()
	if shed != 0 {
		t.Fatalf("normal-load shedCount=%d, want 0", shed)
	}
}

// TestHandleDecision_SemaphoreReleasedOnHandlerExit ensures the deferred
// release runs no matter how the handler returns — bypass path, lookup
// path, cache hit, etc. We call the handler many more times than the cap;
// if release leaked, the channel would fill up and subsequent calls would
// shed (which would show up as nonzero shedCount).
func TestHandleDecision_SemaphoreReleasedOnHandlerExit(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)

	cap := decisionConcurrencyCap()
	const Mult = 4 // call cap*Mult times sequentially

	for i := 0; i < cap*Mult; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/nginx/decision?ip=203.0.113.7&host=example.com&scope=web", nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("call %d: status=%d body=%s", i, rr.Code, rr.Body.String())
		}
	}

	// All calls were sequential, so semaphore should never have been
	// pressured; shedCount must be zero.
	b.stats.mu.Lock()
	shed := b.stats.shedCount
	b.stats.mu.Unlock()
	if shed != 0 {
		t.Fatalf("after %d sequential calls, shedCount=%d (semaphore leaked?)",
			cap*Mult, shed)
	}
}

// TestDecisionConcurrencyCap_HasSensibleFloor ensures that even on a 1-CPU
// test container we get a useful cap, not just 8.
func TestDecisionConcurrencyCap_HasSensibleFloor(t *testing.T) {
	got := decisionConcurrencyCap()
	if got < 32 {
		t.Fatalf("decisionConcurrencyCap()=%d, want >=32 (floor)", got)
	}
}

// _ = atomic.LoadInt64 keeps the import alive if a future test wants atomic
// counters; using non-atomic shedCount under stats.mu is fine today.
var _ = atomic.LoadInt64
