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

func TestStartDNATFailSafeRunnerThresholdCleanupAndReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	on := true
	probes := 0
	cleanups := 0
	counterUpdates := []int{}

	startDNATFailSafe(ctx, dnatFailSafeTarget{
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

	startDNATFailSafe(ctx, dnatFailSafeTarget{
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

	startDNATFailSafe(ctx, dnatFailSafeTarget{
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

	startDNATFailSafe(ctx, dnatFailSafeTarget{
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

func TestStartDNATFailSafeRunnerOffSkipsProbeAndStatusErrorsDoNotCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	statusCalls := 0
	probes := 0
	cleanups := 0

	startDNATFailSafe(ctx, dnatFailSafeTarget{
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
