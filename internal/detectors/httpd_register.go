// internal/detectors/httpd_register.go
package detectors

import (
	"os"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/httpd"
	"cfm/internal/logging"
)

func init() {
	Register("httpd_access", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		// mirror nginx defaults so behavior is consistent
		defEvery := kvDur(global, "DEFAULT_EVERY", 5*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 60*time.Second)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 10*time.Minute)

		// enrichment flags & dirs, same parsing style as nginx_register.go
		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR := kvBool(kv, "PTR", kvBool(global, "PTR", true))
		rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStr(global, "ENRICH_DIRS", ""))
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
		if len(dirs) == 0 {
			// keep your historical default as fallback
			dirs = []string{"/var/lib/cfm/maxmind"}
		}



		cfg := httpd.Config{
			Mode:        strings.ToLower(kvStrClean(kv, "MODE", "file")),
			LogPath:     kvStrClean(kv, "LOG_PATH", "/var/log/httpd/access_cfm_tsv.log"),
			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 20),

			RPSTotalMin:    kvFlt(kv, "RPS_TOTAL_MIN", 800),
			UniqueIPsMin:   kvInt(kv, "UNIQUE_IPS_MIN", 400),
			ErrRatioMin:    kvFlt(kv, "ERR_RATIO_MIN", 0.20),
			RPS499Min:      kvFlt(kv, "RPS_499_MIN", 0), // httpd/litespeed
			RPS5xxMin:      kvFlt(kv, "RPS_5XX_MIN", 60),
			MedianIPRPSMax: kvFlt(kv, "MEDIAN_IP_RPS_MAX", 3),

			RPS401Min:       kvFlt(kv, "RPS_401_MIN", 0),      // set if you want auth bursts
			Auth401RatioMin: kvFlt(kv, "AUTH401_RATIO_MIN", 0),// eg 0.6 = 60% of 4xx are 401

			UseEnrich:  useEnrich,
			UsePTR:     usePTR,
			EnrichDirs: dirs,
		}

		d := httpd.New(cfg)
		d.SetName(section)
		httpd.Publish(d)


		// MODE=file (mirror nginx behavior): attempt to attach a tailer,
		// but ALWAYS return the detector so the section is considered initialized.
		path := cfg.LogPath
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			logging.Logf("[detectors][httpd] using log: %s", path)
			src := core.NewFileTailer(path)
			// If your nginx tailer sets extra flags, do the same here (StartAtEnd/Follow/etc).
			d.SetSource(src)
			// resume persisted position like nginx
			if st, _ := core.LoadState(""); st != nil {
				key := core.FileStateKey(section, path)
				d.SetState(st, key)
			}
		} else {
			logging.Logf("[detectors][httpd] log path not found: %s (set LOG_PATH)", path)
		}
		return d, nil

	})
}

