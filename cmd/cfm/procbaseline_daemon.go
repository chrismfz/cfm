package main

import (
	"context"

	"cfm/internal/logging"
	"cfm/internal/procbaseline"
)

const processBaselineDBPath = "/var/lib/cfm/processbaseline.db"

// startProcessBaseline enables rolling process-family history for the daemon.
// It is deliberately best-effort: failure to open the SQLite store must not
// prevent the firewall/edge daemon from starting.
func startProcessBaseline(ctx context.Context) func() {
	lc, err := procbaseline.Start(ctx, processBaselineDBPath)
	if err != nil {
		logging.Logf("[procbaseline] disabled (store unavailable): %v", err)
		return func() {}
	}
	logging.Logf("[procbaseline] collector started path=%s", processBaselineDBPath)
	return func() {
		if err := lc.Close(); err != nil {
			logging.Logf("[procbaseline] shutdown error: %v", err)
		}
	}
}
