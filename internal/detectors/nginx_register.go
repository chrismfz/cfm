// package detectors
package detectors

import (
	"os"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/nginx" // new package you’ll add below
	"cfm/internal/logging"
)

func init() {
	Register("nginx_access", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 5*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 60*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR    := kvBool(kv, "PTR",    kvBool(global, "PTR", true))
		rawDirs   := kvStrClean(kv, "ENRICH_DIRS", kvStr(global, "ENRICH_DIRS", ""))

		var dirs []string
		if rawDirs != "" {
			for _, f := range strings.FieldsFunc(rawDirs, func(r rune) bool { return r==',' || r==':' || r==' ' || r=='\t' }) {
				if f != "" { dirs = append(dirs, f) }
			}
		}

		cfg := nginx.Config{
			Mode:        strings.ToLower(kvStrClean(kv, "MODE", "file")),
			LogPath:     kvStrClean(kv, "LOG_PATH", "/var/log/nginx/access_cfm_combined.log"),
			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 20),

            RPSTotalMin:     kvFlt(kv, "RPS_TOTAL_MIN", 800),
            UniqueIPsMin:    kvInt(kv, "UNIQUE_IPS_MIN", 400),
            ErrRatioMin:     kvFlt(kv, "ERR_RATIO_MIN", 0.20),
            RPS499Min:       kvFlt(kv, "RPS_499_MIN", 120),
            RPS5xxMin:       kvFlt(kv, "RPS_5XX_MIN", 60),
            MedianIPRPSMax:  kvFlt(kv, "MEDIAN_IP_RPS_MAX", 3),

RPS401Min:       kvFlt(kv, "RPS_401_MIN", 0),
Auth401RatioMin: kvFlt(kv, "AUTH401_RATIO_MIN", 0),

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,
		}

		d := nginx.New(cfg)
		d.SetName(section)
		nginx.Publish(d)

		// MODE=file (recommended)
		path := cfg.LogPath
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			logging.Logf("[detectors][nginx] using log: %s", path)
			src := core.NewFileTailer(path)
			d.SetSource(src)
			// resume state
			if st, _ := core.LoadState(""); st != nil {
				key := core.FileStateKey(section, path)
				d.SetState(st, key)
			}

		} else {
			logging.Logf("[detectors][nginx] log path not found: %s (set LOG_PATH)", path)
		}
		return d, nil
	})
}
