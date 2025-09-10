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


Register("exim_security", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
    defEvery    := kvDur(global, "DEFAULT_EVERY",    2*time.Second)
    defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)
    rawDirs := kvStr(kv, "ENRICH_DIRS", "")
    var dirs []string
    if rawDirs != "" {
        fields := strings.FieldsFunc(rawDirs, func(r rune) bool { return r == ',' || r == ':' || r == ' ' || r == '\t' })
        for _, f := range fields { if f != "" { dirs = append(dirs, f) } }
    }
    cfg := exim.SecConfig{
        LogPath:     kvStr(kv, "LOG_PATH", ""),
        Every:       kvDur(kv, "EVERY", defEvery),
        Window:      kvDur(kv, "WINDOW", 15*time.Minute),
        SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 10),
        Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),

        RulesPath:   kvStr(kv, "RULES", ""),

        UseEnrich:   kvBool(kv, "ENRICH", true),
        UsePTR:      kvBool(kv, "PTR", true),
        EnrichDirs:  dirs,
    }
    return exim.NewSecurity(cfg), nil
})












  Register("exim_relays", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
        // defaults από [global]
        defEvery    := kvDur(global, "DEFAULT_EVERY",   5*time.Second)
        defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)


   // parse ENRICH_DIRS as comma/colon/space-separated list
    rawDirs := kvStr(kv, "ENRICH_DIRS", "")
    var dirs []string
    if rawDirs != "" {
        fields := strings.FieldsFunc(rawDirs, func(r rune) bool { return r == ',' || r == ':' || r == ' ' || r == '\t' })
        for _, f := range fields {
            if f != "" { dirs = append(dirs, f) }
        }
    }



        cfg := exim.RelaysConfig{
            LogPath:       kvStr(kv, "LOG_PATH", ""),
            Every:         kvDur(kv, "EVERY", defEvery),
            Window:        kvDur(kv, "WINDOW", 15*time.Minute),
            SampleLimit:   kvInt(kv, "SAMPLE_LIMIT", 10),
            Cooldown:      kvDur(kv, "COOLDOWN", defCooldown),

            LocalUserMax:  kvInt(kv, "LOCAL_USER_MAX",  50),
            AuthUserMax:   kvInt(kv, "AUTH_USER_MAX",   50),
            AuthIPMax:     kvInt(kv, "AUTH_IP_MAX",     80),
            AuthUserIPMax: kvInt(kv, "AUTH_USERIP_MAX", 40),
            UnauthIPMax:   kvInt(kv, "UNAUTH_IP_MAX",   20),
        UseEnrich:     kvBool(kv, "ENRICH", true),
        UsePTR:        kvBool(kv, "PTR", true),
        EnrichDirs:    dirs,
        }
        return exim.NewRelays(cfg), nil
    })
}








