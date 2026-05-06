package dnat

import (
	"context"
	"time"

	"cfm/internal/logging"
)

type dnatFailSafeTarget struct {
	Name             string
	LogPrefix        string
	Interval         time.Duration
	FailureThreshold int
	StatusCheck      func() (bool, error)
	HealthProbe      func() error
	Cleanup          func(failCount int, probeErr error)
	UpdateFailCount  func(int)
}

func startDNATFailSafe(ctx context.Context, target dnatFailSafeTarget) {
	if target.Interval <= 0 || target.FailureThreshold <= 0 || target.StatusCheck == nil || target.HealthProbe == nil || target.Cleanup == nil {
		return
	}
	if target.LogPrefix == "" {
		target.LogPrefix = "[dnat:failsafe]"
	}
	if target.UpdateFailCount == nil {
		target.UpdateFailCount = func(int) {}
	}

	t := time.NewTicker(target.Interval)
	go func() {
		defer t.Stop()

		failCount := 0
		resetFails := func() {
			failCount = 0
			target.UpdateFailCount(0)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				on, err := target.StatusCheck()
				if err != nil {
					logging.Logf("%s status check failed: %v", target.LogPrefix, err)
					continue
				}
				if !on {
					resetFails()
					continue
				}

				probeErr := target.HealthProbe()
				if probeErr == nil {
					resetFails()
					continue
				}

				failCount++
				target.UpdateFailCount(failCount)
				if failCount < target.FailureThreshold {
					continue
				}

				if on2, _ := target.StatusCheck(); on2 {
					target.Cleanup(failCount, probeErr)
				}
				resetFails()
			}
		}
	}()
}
