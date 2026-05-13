package dnat

import (
	"cfm/internal/firewall"
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// restoreBackend stubs only what RestoreOnStartup touches for ScopeWeb:
// DNATStatus must keep returning false so the loop spins until either
// intent flips, probe succeeds, or the deadline is hit. DNATOn is the
// flag we assert against.
type restoreBackend struct {
	firewall.Backend
	enableCalls int32
}

func (b *restoreBackend) DNATStatus(string, string) (bool, error) { return false, nil }
func (b *restoreBackend) DNATOn(string, string, int, int) error {
	atomic.AddInt32(&b.enableCalls, 1)
	return nil
}
func (b *restoreBackend) DNATOff(string, string) error { return nil }
func (b *restoreBackend) DNATShow(string, string) (string, error) {
	return "", nil
}

// TestRestoreOnStartup_BailsWhenIntentFlipsOffMidLoop verifies that an
// operator running `cfm dnat off` while RestoreOnStartup is still waiting
// for the edge to come up is honored — the cached intent value at function
// entry must not silently override a freshly-persisted OFF. Without the
// per-tick LoadIntent recheck this test would either run to the
// CFM_DNAT_STARTUP_WAIT_MS deadline (logging "startup-timeout") or call
// DNATOn as soon as the probe happens to succeed.
func TestRestoreOnStartup_BailsWhenIntentFlipsOffMidLoop(t *testing.T) {
	dir := t.TempDir()
	orig := webDNATIntentPath
	webDNATIntentPath = filepath.Join(dir, "dnat_enabled")
	t.Cleanup(func() { webDNATIntentPath = orig })

	transitionMu.Lock()
	transitions = map[DNATScope]LastTransition{}
	transitionMu.Unlock()

	if err := PersistIntent(ScopeWeb, true); err != nil {
		t.Fatalf("persist ON: %v", err)
	}

	t.Setenv("CFM_DNAT_STARTUP_WAIT_MS", "2000")
	t.Setenv("CFM_DNAT_STARTUP_STEP_MS", "20")
	// Point the probe at a closed port so probeEdgeHealthy keeps
	// failing — keeps the loop alive long enough for the mid-flight
	// flip to land.
	t.Setenv("HTTP_PORT", "1")
	t.Setenv("HTTPS_PORT", "1")

	backend := &restoreBackend{}
	done := make(chan struct{})
	start := time.Now()
	go func() {
		RestoreOnStartup(context.Background(), ScopeWeb, backend)
		close(done)
	}()

	// Flip intent to OFF after the first iteration has begun. The
	// step is 20ms and probe TCP timeouts cap at ~300ms; 75ms lands
	// inside the first sleep window in nearly all cases.
	time.Sleep(75 * time.Millisecond)
	if err := PersistIntent(ScopeWeb, false); err != nil {
		t.Fatalf("flip OFF: %v", err)
	}

	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("RestoreOnStartup did not return after intent flip")
	}

	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("RestoreOnStartup ran past intent flip (%v); should bail within a step", elapsed)
	}
	if n := atomic.LoadInt32(&backend.enableCalls); n != 0 {
		t.Fatalf("DNATOn called %d times after intent flip; expected 0", n)
	}
	// A regression that didn't re-read intent would either timeout
	// (startup-timeout transition) or succeed-enable. Neither should
	// happen on this code path.
	if lt := GetLastTransition(ScopeWeb); lt.Action == "startup-timeout" || lt.Action == "startup" {
		t.Fatalf("unexpected transition after intent flip: %+v", lt)
	}
}
