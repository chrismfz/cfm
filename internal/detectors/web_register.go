package detectors

import (
	"os"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	web  "cfm/internal/detectors/web"
	"cfm/internal/logging"
)

func registerWebCommon(section string, kv, global KV, kind web.Kind) (core.PeriodicDetector, error) {
	defEvery    := kvDur(global, "DEFAULT_EVERY",    5*time.Second)
	defWindow   := kvDur(global, "DEFAULT_WINDOW",   60*time.Second)
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
	if len(dirs) == 0 {
		dirs = []string{"/var/lib/cfm/maxmind"}
	}

	// defaults per kind (light differences)
	logPath := "/var/log/nginx/access_cfm_combined.log"
	rps499 := 120.0
	if kind == web.KindHTTPD {
		logPath = "/var/log/apache2/access_cfm_tsv.log"
		rps499 = 0.0
	}

	cfg := web.Config{
		Kind:         kind,
		Mode:         strings.ToLower(kvStrClean(kv, "MODE", "file")),
		LogPath:      kvStrClean(kv, "LOG_PATH", logPath),
		Every:        kvDur(kv,  "EVERY",    defEvery),
		Window:       kvDur(kv,  "WINDOW",   defWindow),
		Cooldown:     kvDur(kv,  "COOLDOWN", defCooldown),
		SampleLimit:  kvInt(kv,  "SAMPLE_LIMIT", 20),

		RPSTotalMin:    kvFlt(kv, "RPS_TOTAL_MIN",    800),
		UniqueIPsMin:   kvInt(kv, "UNIQUE_IPS_MIN",   400),
		ErrRatioMin:    kvFlt(kv, "ERR_RATIO_MIN",    0.20),
		RPS499Min:      kvFlt(kv, "RPS_499_MIN",      rps499),
		RPS5xxMin:      kvFlt(kv, "RPS_5XX_MIN",      60),
		MedianIPRPSMax: kvFlt(kv, "MEDIAN_IP_RPS_MAX", 3),

		RPS401Min:       kvFlt(kv, "RPS_401_MIN", 0),
		Auth401RatioMin: kvFlt(kv, "AUTH401_RATIO_MIN", 0),

		UseEnrich:  useEnrich,
		UsePTR:     usePTR,
		EnrichDirs: dirs,
		ProcTimeMax:    kvFlt(kv, "PROC_TIME_MAX", 2), // disabled unless set to 0
	}

	d := web.New(cfg)
	d.SetName(section)
	web.Publish(kind, d)

	// MODE=file: attach tailer if file exists (keep behavior)
	path := cfg.LogPath
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		logging.Logf("[detectors][%s] using log: %s", kind, path)
		src := core.NewFileTailer(path)
		d.SetSource(src)
		if stt, _ := core.LoadState(""); stt != nil {
			key := core.FileStateKey(section, path)
			d.SetState(stt, key)
		}
	} else {
		logging.Logf("[detectors][%s] log path not found: %s (set LOG_PATH)", kind, path)
	}
	return d, nil
}

func init() {
	Register("nginx_access", func(section string, kv, global KV) (core.PeriodicDetector, error) {
		return registerWebCommon(section, kv, global, web.KindNginx)
	})
	Register("httpd_access", func(section string, kv, global KV) (core.PeriodicDetector, error) {
		return registerWebCommon(section, kv, global, web.KindHTTPD)
	})
}
