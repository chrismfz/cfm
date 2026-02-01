// internal/detectors/webdetector_register.go
package detectors

import (
	"os"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

func init() {
	Register("webdetector", func(section string, kv, global KV) (core.PeriodicDetector, error) {
		defEvery    := kvDur(global, "DEFAULT_EVERY",    5*time.Second)
		defWindow   := kvDur(global, "DEFAULT_WINDOW",   120*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR", true))
		rawDirs   := kvStrClean(kv, "ENRICH_DIRS", kvStr(global, "ENRICH_DIRS", ""))

		var dirs []string
		if rawDirs != "" {
			for _, f := range strings.FieldsFunc(rawDirs, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			}) {
				if f != "" {
					dirs = append(dirs, f)
				}
			}
		}



cfg := webdet.Config{
	Mode:        strings.ToLower(kvStrClean(kv, "MODE", "file")),
	LogPath:     kvStrClean(kv, "LOG_PATH", "/var/log/apache2/access_cfm_tsv.log"),
	Every:       kvDur(kv, "EVERY", defEvery),
	Window:      kvDur(kv, "WINDOW", defWindow),
	Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
	SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 20),

	UseEnrich:  useEnrich,
	UsePTR:     usePTR,
	EnrichDirs: dirs,

	LongFactor: kvInt(kv, "LONG_FACTOR", 10),
	MinScore:   kvFlt(kv, "MIN_SCORE", 0.60),

	APIListen: kvStrClean(kv, "API_LISTEN", "127.0.0.1:9070"),

	IP404Count: kvInt(kv, "IP404_COUNT", 0),
	IP403Count: kvInt(kv, "IP403_COUNT", 0),

	AgentCount: kvInt(kv, "AGENT_COUNT", 0),
}

rawAgents := kvStrClean(kv, "AGENT_LIST", "")
if rawAgents != "" {
	for _, a := range strings.FieldsFunc(rawAgents, func(r rune) bool {
		return r == ',' || r == ':' || r == ' ' || r == '\t'
	}) {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			cfg.AgentList = append(cfg.AgentList, a)
		}
	}
}




		engine := webdet.NewEngine(cfg)

		// MODE=file: attach tailer if file exists
		if cfg.Mode == "file" {
			path := cfg.LogPath
			if st, err := os.Stat(path); err == nil && !st.IsDir() {
				logging.Logf("[webdetector] using log: %s", path)
				src := core.NewFileTailer(path)
				engine.SetSource(src)
				if stt, _ := core.LoadState(""); stt != nil {
					key := core.FileStateKey(section, path)
					engine.SetState(stt, key)
				}
			} else {
				logging.Logf("[webdetector] log path not found: %s (set LOG_PATH)", path)
			}
		}

		// Start HTTP API in a goroutine (if API_LISTEN is non-empty).
		if cfg.APIListen != "" {
			go engine.ServeHTTP(cfg.APIListen)
		}

		return engine, nil
	})
}
