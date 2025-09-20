package detectors

import (
	"time"
	"strings"
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
			TotalCmd:    kvStrClean(kv, "TOTAL_CMD", "exim -bpc"),
			ListCmd:     kvStrClean(kv, "LIST_CMD", "exim -bp"),
			Every:       kvDur(kv, "EVERY", defEvery),
			Timeout:     kvDur(kv, "TIMEOUT", defTimeout),
			MaxTotal:    kvInt(kv, "QUEUE_TOTAL_MAX", 500),
			MaxFrozen:   kvInt(kv, "QUEUE_FROZEN_MAX", 200),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
		}
		return exim.NewQueues(cfg), nil
	})



Register("exim_security", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
    defEvery    := kvDur(global, "DEFAULT_EVERY",    2*time.Second)
    defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

    // Enrichment: global defaults, allow per-section override
    rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
    var dirs []string
    if rawDirs != "" {
        fields := strings.FieldsFunc(rawDirs, func(r rune) bool { return r == ',' || r == ':' || r == ' ' || r == '\t' })
        for _, f := range fields { if f != "" { dirs = append(dirs, f) } }
    }

        useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
        usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR",    true))

    cfg := exim.SecConfig{
        LogPath:     kvStrClean(kv, "LOG_PATH", ""),
        Every:       kvDur(kv, "EVERY", defEvery),
        Window:      kvDur(kv, "WINDOW", 15*time.Minute),
        SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
        Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),

        RulesPath:   kvStrClean(kv, "RULES", ""),
        UseEnrich:   useEnrich,
        UsePTR:      usePTR,
        EnrichDirs:  dirs,
        Thresholds:  map[string]int{
            "AUTHFAIL_IP":   kvInt(kv, "AUTHFAIL_IP",   0),
            "AUTHFAIL_USER": kvInt(kv, "AUTHFAIL_USER", 0),
        },
    }

    sec := exim.NewSecurity(cfg) // ✅ correct constructor
    sec.SetName(section)         // ensure unique persistence key

    return sec, nil
})












Register("exim_relays", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
    defEvery    := kvDur(global, "DEFAULT_EVERY", 5*time.Second)
    defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

    // Enrichment: global defaults, allow per-section override
    rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
    var dirs []string
    if rawDirs != "" {
        fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
            return r == ',' || r == ':' || r == ' ' || r == '\t'
        })
        for _, f := range fields {
            if f != "" { dirs = append(dirs, f) }
        }
    }

        useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
        usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR",    true))

    cfg := exim.RelaysConfig{
        LogPath:       kvStrClean(kv, "LOG_PATH", ""),
        Every:         kvDur(kv, "EVERY", defEvery),
        Window:        kvDur(kv, "WINDOW", 15*time.Minute),
        SampleLimit:   kvInt(kv, "SAMPLE_LIMIT", 10),
        Cooldown:      kvDur(kv, "COOLDOWN", defCooldown),

        LocalUserMax:  kvInt(kv, "LOCAL_USER_MAX",  50),
        AuthUserMax:   kvInt(kv, "AUTH_USER_MAX",   50),
        AuthIPMax:     kvInt(kv, "AUTH_IP_MAX",     80),
        AuthUserIPMax: kvInt(kv, "AUTH_USERIP_MAX", 40),
        UnauthIPMax:   kvInt(kv, "UNAUTH_IP_MAX",   20),

        UseEnrich:     useEnrich,
        UsePTR:        usePTR,
        EnrichDirs:    dirs,
    }

    rr := exim.NewRelays(cfg) // rr is *exim.Relays
    rr.SetName(section)       // exported setter

    return rr, nil // implicit upcast to core.PeriodicDetector
})

}
