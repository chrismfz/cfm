package detectors

import (
	"strings"
	"time"

	"cfm/internal/apiserver"
	"cfm/internal/detectors/apiabuse"
	core "cfm/internal/detectors/core"
)

func init() {
	Register("api_abuse", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		cfg := apiabuse.Config{
			Every:              kvDur(kv, "EVERY", defEvery),
			Window:             kvDur(kv, "WINDOW", 2*time.Minute),
			SampleLimit:        kvInt(kv, "SAMPLE_LIMIT", 10),
			Stage1Threshold:    kvInt(kv, "STAGE1_THRESHOLD", 8),
			Stage2Threshold:    kvInt(kv, "STAGE2_THRESHOLD", 12),
			Stage3Threshold:    kvInt(kv, "STAGE3_THRESHOLD", 16),
			Stage2ChallengeTTL: kvDur(kv, "STAGE2_CHALLENGE_TTL", 10*time.Minute),
			DryRun:             kvBool(kv, "DRY_RUN", false),
			AllowIPs:           csvKV(kv, "ALLOW_IPS"),
			AllowNets:          csvKV(kv, "ALLOW_NETS"),
			AllowUAContains:    csvKV(kv, "ALLOW_UA_CONTAINS"),
			PathExceptions:     csvKV(kv, "PATH_EXCEPTIONS"),
		}
		d := apiabuse.New(cfg)
		d.SetName(section)
		apiserver.SubscribeAPIAnomalyEvents(func(ev apiserver.APIAnomalyEvent) {
			d.Enqueue(ev.InputEvent())
		})
		return d, nil
	})
}

func csvKV(kv KV, key string) []string {
	raw := strings.TrimSpace(kvStrClean(kv, key, ""))
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
