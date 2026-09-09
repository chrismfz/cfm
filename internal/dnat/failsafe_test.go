package dnat

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func waitUntil(t *testing.T, timeout time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

// startFailSafeForTest starts the fail-safe runner and joins its goroutine at
// test end: it cancels ctx and waits for the returned done channel. This keeps
// the goroutine from outliving the test and racing a later os.Stdout swap under
// `go test -race` (the runner logs via the shared logger). The join runs from
// t.Cleanup — after the test's own `defer mu.Unlock()` — so waiting on the
// goroutine (which may take mu on its way out) cannot deadlock.
func startFailSafeForTest(t *testing.T, ctx context.Context, cancel context.CancelFunc, target dnatFailSafeTarget) {
	t.Helper()
	done := startDNATFailSafe(ctx, target)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("startDNATFailSafe goroutine did not exit within 2s of cancel")
		}
	})
}

func TestStartDNATFailSafeRunnerThresholdCleanupAndReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	on := true
	probes := 0
	cleanups := 0
	counterUpdates := []int{}

	startFailSafeForTest(t, ctx, cancel, dnatFailSafeTarget{
		Name:             "test",
		LogPrefix:        "[dnat:test:failsafe]",
		Interval:         5 * time.Millisecond,
		FailureThreshold: 2,
		StatusCheck: func() (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			return on, nil
		},
		HealthProbe: func() error {
			mu.Lock()
			defer mu.Unlock()
			probes++
			return errors.New("down")
		},
		Cleanup: func(failCount int, probeErr error) {
			mu.Lock()
			defer mu.Unlock()
			if failCount != 2 {
				t.Errorf("cleanup failCount = %d, want 2", failCount)
			}
			if probeErr == nil || probeErr.Error() != "down" {
				t.Errorf("cleanup probeErr = %v, want down", probeErr)
			}
			cleanups++
			on = false
		},
		UpdateFailCount: func(v int) {
			mu.Lock()
			defer mu.Unlock()
			counterUpdates = append(counterUpdates, v)
		},
	})

	waitUntil(t, 200*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return cleanups == 1 && len(counterUpdates) > 0 && counterUpdates[len(counterUpdates)-1] == 0
	})

	mu.Lock()
	defer mu.Unlock()
	if probes < 2 {
		t.Fatalf("expected at least two probes, got %d", probes)
	}
	if cleanups != 1 {
		t.Fatalf("expected one cleanup, got %d", cleanups)
	}
}

func TestStartDNATFailSafeRunnerRecoverPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	on := false
	intent := true
	probeOK := true
	probes := 0
	recoveries := 0
	var recoverCounts []int

	startFailSafeForTest(t, ctx, cancel, dnatFailSafeTarget{
		Name:             "test",
		LogPrefix:        "[dnat:test:failsafe]",
		Interval:         3 * time.Millisecond,
		FailureThreshold: 1,
		StatusCheck: func() (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			return on, nil
		},
		HealthProbe: func() error {
			mu.Lock()
			defer mu.Unlock()
			probes++
			if probeOK {
				return nil
			}
			return errors.New("down")
		},
		Cleanup: func(int, error) {
			t.Errorf("cleanup must not run when status is OFF")
		},
		IntentCheck: func() bool {
			mu.Lock()
			defer mu.Unlock()
			return intent
		},
		RecoverThreshold: 3,
		Recover: func(okCount int) {
			mu.Lock()
			defer mu.Unlock()
			recoveries++
			recoverCounts = append(recoverCounts, okCount)
			on = true
		},
	})

	waitUntil(t, 200*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return recoveries == 1
	})

	mu.Lock()
	if recoveries != 1 {
		t.Fatalf("expected exactly one recovery, got %d", recoveries)
	}
	if recoverCounts[0] < 3 {
		t.Fatalf("expected recover after RecoverThreshold consecutive ok probes, got okCount=%d", recoverCounts[0])
	}
	if probes < 3 {
		t.Fatalf("expected at least RecoverThreshold probes before recover, got %d", probes)
	}
	mu.Unlock()
}

func TestStartDNATFailSafeRunnerRecoverResetsOnProbeFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	probeSeq := []bool{true, true, false, true}
	probeIdx := 0
	recoveries := 0

	startFailSafeForTest(t, ctx, cancel, dnatFailSafeTarget{
		Name:             "test",
		LogPrefix:        "[dnat:test:failsafe]",
		Interval:         3 * time.Millisecond,
		FailureThreshold: 1,
		StatusCheck:      func() (bool, error) { return false, nil },
		HealthProbe: func() error {
			mu.Lock()
			defer mu.Unlock()
			if probeIdx >= len(probeSeq) {
				return errors.New("down")
			}
			ok := probeSeq[probeIdx]
			probeIdx++
			if ok {
				return nil
			}
			return errors.New("transient")
		},
		Cleanup:          func(int, error) {},
		IntentCheck:      func() bool { return true },
		RecoverThreshold: 3,
		Recover: func(int) {
			mu.Lock()
			defer mu.Unlock()
			recoveries++
		},
	})

	waitUntil(t, 200*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return probeIdx >= len(probeSeq)
	})

	// Give the runner a few more ticks past the sequence to confirm no late
	// recovery sneaks in — okCount must have been reset by the failed probe
	// at index 2.
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if recoveries != 0 {
		t.Fatalf("expected zero recoveries after probe-fail resets okCount, got %d", recoveries)
	}
}

func TestStartDNATFailSafeRunnerRecoverSkippedWhenIntentOff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	probes := 0

	startFailSafeForTest(t, ctx, cancel, dnatFailSafeTarget{
		Name:             "test",
		LogPrefix:        "[dnat:test:failsafe]",
		Interval:         3 * time.Millisecond,
		FailureThreshold: 1,
		StatusCheck:      func() (bool, error) { return false, nil },
		HealthProbe: func() error {
			mu.Lock()
			defer mu.Unlock()
			probes++
			return nil
		},
		Cleanup:          func(int, error) {},
		IntentCheck:      func() bool { return false },
		RecoverThreshold: 1,
		Recover: func(int) {
			t.Errorf("recover must not run when intent is OFF")
		},
	})

	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if probes != 0 {
		t.Fatalf("expected zero probes when intent OFF + status OFF, got %d", probes)
	}
}

func TestStartDNATFailSafeRunnerRecoverSkippedWhenRecheckErrors(t *testing.T) {
	// At the RecoverThreshold tick we re-check StatusCheck before
	// firing Recover. If that recheck errors transiently (e.g. nft
	// list table fails), the older code dropped the error and treated
	// zero-value false as "OFF", running Recover anyway. Now we only
	// Recover on a *confirmed* OFF.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	statusCalls := 0
	recoveries := 0

	startFailSafeForTest(t, ctx, cancel, dnatFailSafeTarget{
		Name:             "test",
		LogPrefix:        "[dnat:test:failsafe]",
		Interval:         3 * time.Millisecond,
		FailureThreshold: 1,
		StatusCheck: func() (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			statusCalls++
			// First call each tick is the loop's primary StatusCheck;
			// we keep it returning (false, nil) so the recover arm is
			// reached. The *recheck* calls (every Nth tick at the
			// threshold) return an error to simulate transient nft
			// failure. Pattern: every 2nd call errors.
			if statusCalls%2 == 0 {
				return false, errors.New("nft transient")
			}
			return false, nil
		},
		HealthProbe:      func() error { return nil },
		Cleanup:          func(int, error) {},
		IntentCheck:      func() bool { return true },
		RecoverThreshold: 2,
		Recover: func(int) {
			mu.Lock()
			defer mu.Unlock()
			recoveries++
		},
	})

	waitUntil(t, 200*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return statusCalls >= 8
	})

	mu.Lock()
	defer mu.Unlock()
	if recoveries != 0 {
		t.Fatalf("recover must not fire when the StatusCheck recheck errors, got %d", recoveries)
	}
}

func TestStartDNATFailSafeRunnerOffSkipsProbeAndStatusErrorsDoNotCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	statusCalls := 0
	probes := 0
	cleanups := 0

	startFailSafeForTest(t, ctx, cancel, dnatFailSafeTarget{
		Name:             "test",
		LogPrefix:        "[dnat:test:failsafe]",
		Interval:         5 * time.Millisecond,
		FailureThreshold: 1,
		StatusCheck: func() (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			statusCalls++
			if statusCalls == 1 {
				return false, nil
			}
			return true, errors.New("status unavailable")
		},
		HealthProbe: func() error {
			mu.Lock()
			defer mu.Unlock()
			probes++
			return errors.New("down")
		},
		Cleanup: func(int, error) {
			mu.Lock()
			defer mu.Unlock()
			cleanups++
		},
	})

	waitUntil(t, 100*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return statusCalls >= 3
	})

	mu.Lock()
	defer mu.Unlock()
	if probes != 0 {
		t.Fatalf("probe should not run when status is off or errors, got %d", probes)
	}
	if cleanups != 0 {
		t.Fatalf("cleanup should not run when status is off or errors, got %d", cleanups)
	}
}
