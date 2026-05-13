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

	// IntentCheck reports whether the operator wants DNAT to be ON. When
	// non-nil and returning true, the runner counts consecutive successful
	// probes while the runtime is OFF and calls Recover after RecoverThreshold
	// of them. Leave nil for "no self-heal" semantics.
	IntentCheck      func() bool
	RecoverThreshold int
	Recover          func(okCount int)
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
		okCount := 0
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
					if target.IntentCheck == nil || target.Recover == nil || target.RecoverThreshold <= 0 {
						okCount = 0
						continue
					}
					if !target.IntentCheck() {
						okCount = 0
						continue
					}
					if err := target.HealthProbe(); err != nil {
						okCount = 0
						continue
					}
					okCount++
					if okCount >= target.RecoverThreshold {
						// Recover only on a *confirmed* OFF. The recheck
						// used to drop the StatusCheck error, so a
						// transient nft failure (zero-value on2=false)
						// tripped Recover — the symmetric concern to
						// Cleanup, which already requires a confirmed
						// ON. If StatusCheck errors, skip this tick and
						// let the next one retry.
						if on2, err := target.StatusCheck(); err == nil && !on2 {
							target.Recover(okCount)
						}
						okCount = 0
					}
					continue
				}

				okCount = 0

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
