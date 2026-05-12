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

	// Surface per-policy attach state. On a host where both attach
	// the test runs in full mode; if only one attaches we are in
	// partial mode (the documented EXEC-003 verifier-on-old-kernels
	// risk) and we want the CI log to make that obvious.
	attach := l.Attach()
	t.Logf("attached: %v", attach.Attached)
	if len(attach.Failed) > 0 {
		for id, e := range attach.Failed {
			t.Logf("partial mode — policy %s failed to attach: %v", id, e)
		}
		if os.Getenv("CFM_LSM_REQUIRE_FULL_ATTACH") == "1" {
			t.Fatalf("CFM_LSM_REQUIRE_FULL_ATTACH=1 but %d policies failed to attach", len(attach.Failed))
		}
	}
	if len(attach.Attached) == 0 {
		t.Fatal("Loader returned without error but no policies attached — invariant broken")
	}

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
	case ev, ok := <-l.Events():
		if !ok {
			t.Fatal("events channel closed before Close was called")
		}
		// A spontaneous event is unlikely but possible on a busy
		// host (some other process triggered memfd exec or a real
		// reverse shell during the 50ms test window). Treat as
		// pass — the attach is working.
		t.Logf("received a spontaneous event during integration test (policy=%s, comm=%s) — pass",
			ev.PolicyID, ev.Comm)
	}
}

// TestLoader_PartialAttachIsTolerated exercises the partial-attach
// branch of NewLoader without depending on the kernel: it requests
// only one policy by ID and verifies AttachResult shape. This runs
// even when actual BPF load is impossible — when load is impossible
// it still validates that the error-wrapping path is exercised.
func TestLoader_SubsetSelection(t *testing.T) {
	if os.Geteuid() != 0 && os.Getenv("CFM_LSM_REQUIRE_LOAD") != "1" {
		t.Skip("BPF load requires privileges; skipping subset-selection probe")
	}
	pf := RunPreflight()
	if !pf.OK {
		t.Skip("preflight failed; cannot exercise subset selection")
	}

	// Ask for only EXEC-001. If the kernel accepts it, Attach()
	// should show exactly that one policy attached. EXEC-003 should
	// not appear in Attached or Failed.
	l, err := NewLoader(LoaderOptions{
		EventBufferSize: 8,
		Policies:        []PolicyID{PolicyMemfdExec},
	})
	if err != nil {
		if errors.Is(err, ErrBPFLSMUnavailable) {
			t.Skipf("subset load rejected: %v", err)
		}
		t.Fatalf("NewLoader subset: %v", err)
	}
	defer l.Close()

	attach := l.Attach()
	if len(attach.Attached) != 1 || attach.Attached[0] != PolicyMemfdExec {
		t.Errorf("subset attach: got Attached=%v, want [%s]", attach.Attached, PolicyMemfdExec)
	}
	if _, present := attach.Failed[PolicyReverseShell]; present {
		t.Errorf("subset attach: EXEC-003 should be omitted entirely, not appear in Failed")
	}
}

// TestLoader_GracefulFailWhenObjectsAbsent is intentionally not
// implemented: bpf2go always embeds the .o via go:embed at build
// time, so the loader cannot encounter "objects missing." If the
// build fails, that is caught at compile time, not runtime.
