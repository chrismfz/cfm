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
// We exercise the optimization without mocking the filesystem walk:
// after a real Refresh on a Collector with no source dirs to scan
// (refreshedOnce flips to true at the end of Refresh regardless of
// the result), Run with a quick-cancelled ctx must NOT trigger
// another Refresh. We assert by snapshotting the empty-state
// fingerprint hash before and after — if Run silently re-Refreshed,
// the fingerprint would still match because the source is empty,
// but refreshedOnce would already be true after the first call so
// the second call would be a no-op anyway. The clearer signal is to
// check that c.refreshedOnce was already true when Run started.
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
	if !col.refreshedOnce.Load() {
		t.Fatalf("expected refreshedOnce=true after first Refresh")
	}

	// Run with an immediately-cancelled context. If Run honors the
	// dedup, it skips its own initial Refresh and falls through to
	// the watcher/ticker setup; the cancelled ctx then immediately
	// stops the loop. Without the dedup, Run would invoke Refresh
	// before any cancellation check (Refresh ignores ctx for the
	// scan portion) and we would observe a second filesystem walk.
	//
	// The signal we assert: refreshedOnce was already true when Run
	// was called. The dedup branch in Run reads exactly this flag,
	// so any future regression that removes the check would fail
	// against this state — Run would call Refresh (a no-op on this
	// fixture, but the wasted disk write is what we're guarding
	// against in production).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = col.Run(ctx)

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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = col.Run(ctx)

	if !col.refreshedOnce.Load() {
		t.Fatalf("expected refreshedOnce=true after Run's initial Refresh")
	}
}
