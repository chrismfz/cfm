package main

import (
	"context"
	"time"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

// trafficMixShutdownBudget bounds the shutdown save (it runs after the TTL ban
// snapshot, inside the same signal handler; systemd's stop timeout is longer).
const trafficMixShutdownBudget = 5 * time.Second

// startTrafficMixPersist restores the saved traffic mix (the Web Traffic
// page's 24 h, webdetector/traffic_mix_persist.go) and saves it every
// TrafficMixSaveEvery until ctx ends. Called before the log tailers start, so
// the restored buckets are in place before anything is counted.
func startTrafficMixPersist(ctx context.Context) {
	n, err := webdet.LoadTrafficMix()
	if err != nil {
		logging.Logf("[traffic_mix] restore failed, starting empty: %v", err)
	} else if n > 0 {
		logging.Logf("[traffic_mix] restored %d five-minute buckets", n)
	}
	go func() {
		t := time.NewTicker(webdet.TrafficMixSaveEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := webdet.SaveTrafficMix(); err != nil {
					logging.Logf("[traffic_mix] save failed: %v", err)
				}
			}
		}
	}()
}

// saveTrafficMixOnShutdown is the shutdown save, bounded: reporting data
// never holds a stop up.
func saveTrafficMixOnShutdown(sig string) {
	done := make(chan error, 1)
	go func() { done <- webdet.SaveTrafficMix() }()
	select {
	case err := <-done:
		if err != nil {
			logging.Logf("[traffic_mix] shutdown save failed (%s): %v", sig, err)
		}
	case <-time.After(trafficMixShutdownBudget):
		logging.Logf("[traffic_mix] shutdown save timed out after %s (%s); the last periodic one stands", trafficMixShutdownBudget, sig)
	}
}
