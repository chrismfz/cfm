//go:build linux

package lsm

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLoaderAttachOrSkip is the only test in the package that actually
// tries to load the BPF programs into the kernel. It runs by default
// on linux but skips cleanly when the host cannot accept BPF LSM
// programs — that is the normal state for unprivileged CI runners
// and developer laptops.
//
// The contract this test enforces is:
//
//   - On a host that can load: NewLoader succeeds, Start begins
//     draining, Close detaches cleanly without leaking links.
//
//   - On a host that cannot load: NewLoader returns an error that
//     wraps ErrBPFLSMUnavailable; the test reports the specific
//     reason and skips the rest of the assertions. Critically it
//     does NOT t.Fail — a CI runner without `bpf` in
//     /sys/kernel/security/lsm is the common case, and treating it
//     as a failure would make every PR red.
//
// To force this test to fail on a host that should be able to load
// (e.g. a dedicated bpf-load CI runner), set
// CFM_LSM_REQUIRE_LOAD=1 in the environment.
func TestLoaderAttachOrSkip(t *testing.T) {
	if os.Geteuid() != 0 && os.Getenv("CFM_LSM_REQUIRE_LOAD") != "1" {
		t.Skip("not running as root and CFM_LSM_REQUIRE_LOAD not set — BPF LSM load requires privileges")
	}

	// Run preflight first. If preflight FAILs, we know the kernel
	// is the reason — surface that to the operator and skip rather
	// than producing a confusing load error.
	pf := RunPreflight()
	if !pf.OK && os.Getenv("CFM_LSM_REQUIRE_LOAD") != "1" {
		var failures []string
		for _, c := range pf.Checks {
			if c.Status != CheckPass {
				failures = append(failures, c.Name+": "+c.Detail)
			}
		}
		t.Skipf("preflight reports the kernel cannot accept BPF LSM programs:\n  %s",
			strings.Join(failures, "\n  "))
	}

	l, err := NewLoader(LoaderOptions{EventBufferSize: 16})
	if err != nil {
		if os.Getenv("CFM_LSM_REQUIRE_LOAD") == "1" {
			t.Fatalf("CFM_LSM_REQUIRE_LOAD=1 but load failed: %v", err)
		}
		if errors.Is(err, ErrBPFLSMUnavailable) {
			t.Skipf("BPF LSM load rejected by kernel (expected on most runners): %v", err)
		}
		// Unexpected error class — fail loudly.
		t.Fatalf("NewLoader returned a non-ErrBPFLSMUnavailable error: %v", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Loader.Close: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)

	// Give the drain goroutine a tiny window to be ready, then verify
	// the event channel is alive (not closed prematurely).
	select {
	case <-time.After(50 * time.Millisecond):
		// Good — no immediate close, no immediate error.
	case err := <-l.Errors():
		t.Fatalf("drain loop errored immediately: %v", err)
	case _, ok := <-l.Events():
		if !ok {
			t.Fatal("events channel closed before Close was called")
		}
		// A spontaneous event is unlikely but possible on a busy
		// host (some other process triggered memfd exec). Treat as
		// pass — the attach is working.
		t.Log("received a spontaneous memfd exec event during integration test — pass")
	}
}

// TestLoader_GracefulFailWhenObjectsAbsent is intentionally not
// implemented: bpf2go always embeds the .o via go:embed at build
// time, so the loader cannot encounter "objects missing." If the
// build fails, that is caught at compile time, not runtime.
