package detectors

import (
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/exim"
)

func init() {
	Register("exim_queues", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		// defaults από global, με fallback στα defaults του detector
		defEvery := kvDur(global, "DEFAULT_EVERY", 60*time.Second)
		defTimeout := kvDur(global, "DEFAULT_TIMEOUT", 8*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		cfg := exim.QueuesConfig{
			TotalCmd:    kvStr(kv, "TOTAL_CMD", "exim -bpc"),
			ListCmd:     kvStr(kv, "LIST_CMD", "exim -bp"),
			Every:       kvDur(kv, "EVERY", defEvery),
			Timeout:     kvDur(kv, "TIMEOUT", defTimeout),
			MaxTotal:    kvInt(kv, "QUEUE_TOTAL_MAX", 500),
			MaxFrozen:   kvInt(kv, "QUEUE_FROZEN_MAX", 200),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
		}
		return exim.NewQueues(cfg), nil
	})
}
