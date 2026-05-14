package sslcollector

import (
	"context"
	"testing"
	"time"
)

// TestRunSkipsRefreshWhenAlreadyRefreshed verifies the optimization
// added alongside cmd/cfm/main.go's early-start: if the daemon has
// already invoked Refresh() synchronously before launching Run() in a
// goroutine, Run() must not Refresh again. Without this dedup, every
// cfm boot did the filesystem walk + WriteSnapshot twice.
//
// The audit caught a previous version of this test that asserted only
// `refreshedOnce.Load() == true` after Run returned — a value that
// was already true from the explicit pre-Refresh, so the assertion
// passed regardless of whether Run's internal `if !refreshedOnce`
// guard existed at all. Removing the guard would have been an
// undetected regression. The fix: assert on refreshCallCount so any
// future regression that drops the guard immediately fails this test.
func TestRunSkipsRefreshWhenAlreadyRefreshed(t *testing.T) {
	col := New(Config{
		Enabled:        true,
		CacheDir:       t.TempDir(),
		StatEvery:      1 * time.Hour,
		DiscoveryEvery: 1 * time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxCertCache:   10,
	})

	// Synchronous Refresh — this is what main.go does at startup.
	if err := col.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}
	if got := col.refreshCallCount.Load(); got != 1 {
		t.Fatalf("after first Refresh: refreshCallCount=%d want 1", got)
	}
	if !col.refreshedOnce.Load() {
		t.Fatalf("expected refreshedOnce=true after first Refresh")
	}

	// Run with an immediately-cancelled context. If Run honors the
	// dedup guard it skips its own initial Refresh, the cancelled ctx
	// then immediately stops the loop, and refreshCallCount stays at 1.
	// Without the dedup guard, Run would Refresh once before reaching
	// the select-on-ctx, and refreshCallCount would become 2.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = col.Run(ctx)

	if got := col.refreshCallCount.Load(); got != 1 {
		t.Fatalf("Run did NOT skip the initial Refresh: refreshCallCount=%d want 1 (dedup guard regression)", got)
	}
	if !col.refreshedOnce.Load() {
		t.Fatalf("refreshedOnce flipped back to false during Run")
	}
}

// TestRunRefreshesWhenNotYetRefreshed is the inverse: when the caller
// did NOT pre-Refresh, Run's startup path MUST Refresh once so the
// snapshot lands on disk. This is the legacy code path retained for
// callers that don't follow the early-start convention.
func TestRunRefreshesWhenNotYetRefreshed(t *testing.T) {
	col := New(Config{
		Enabled:        true,
		CacheDir:       t.TempDir(),
		StatEvery:      1 * time.Hour,
		DiscoveryEvery: 1 * time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxCertCache:   10,
	})

	if col.refreshedOnce.Load() {
		t.Fatalf("expected refreshedOnce=false on a fresh Collector")
	}
	if got := col.refreshCallCount.Load(); got != 0 {
		t.Fatalf("expected refreshCallCount=0 on a fresh Collector, got %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = col.Run(ctx)

	if got := col.refreshCallCount.Load(); got != 1 {
		t.Fatalf("Run did NOT call its initial Refresh: refreshCallCount=%d want 1", got)
	}
	if !col.refreshedOnce.Load() {
		t.Fatalf("expected refreshedOnce=true after Run's initial Refresh")
	}
}
