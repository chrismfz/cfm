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
