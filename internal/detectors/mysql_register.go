package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/mysql"
	"cfm/internal/logging"
)

var mysqlState, _ = core.LoadState("")

// pendingGovCfg holds the GovernorConfig parsed from [mysql_governor] in
// detectors.conf.  It is written once during init() when the manager calls
// the factory, and read once by main.go after detpkg.Start() returns.
// No mutex needed: write happens before Start() returns; read happens after.
var (
	pendingGovCfg   mysql.GovernorConfig
	pendingGovReady bool
)

// GetPendingGovernorConfig returns the GovernorConfig parsed from the
// [mysql_governor] section in detectors.conf, and true if that section
// was present and ENABLED=1.
//
// Call this after detpkg.Start() — the factory runs during Start and writes
// pendingGovCfg.  If no [mysql_governor] section exists, returns false and
// the caller should fall back to hardcoded defaults.
func GetPendingGovernorConfig() (mysql.GovernorConfig, bool) {
	return pendingGovCfg, pendingGovReady
}

func init() {
	// ---- [mysql] — brute-force / login detector -------------------------
	Register("mysql", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery    := kvDur(global, "DEFAULT_EVERY",    2*time.Second)
		defWindow   := kvDur(global, "DEFAULT_WINDOW",   10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

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

		logPath := kvStrClean(kv, "LOG_PATH", "auto")
		if logPath == "auto" {
			if auto := mysql.ResolveForAuto(); auto != "" {
				logPath = auto
			}
		}

		cfg := mysql.LoginConfig{
			Mode:        "file",
			LogPath:     logPath,
			Every:       kvDur(kv, "EVERY", defEvery),
			Window:      kvDur(kv, "WINDOW", defWindow),
			Cooldown:    kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit: kvInt(kv, "SAMPLE_LIMIT", 12),

			DeniedPerIP:   kvInt(kv, "DENIED_IP",   10),
			DeniedPerUser: kvInt(kv, "DENIED_USER", 10),
			RootPerIP:     kvInt(kv, "ROOT_IP",     3),
			ScanPerIP:     kvInt(kv, "SCAN_IP",     20),

			UseEnrich:       useEnrich,
			UsePTR:          usePTR,
			EnrichDirs:      dirs,
			IgnoreLocalhost: kvBool(kv, "IGNORE_LOCALHOST",   true),
			IgnoreCpanel:    kvBool(kv, "IGNORE_CPANEL_UTIL", true),
		}

		d := mysql.NewMySQL(cfg)
		d.SetName(section)
		src := core.NewFileTailer(cfg.LogPath)
		d.SetSource(src)
		if mysqlState != nil {
			// key := core.FileStateKey(section, cfg.LogPath); d.SetState(mysqlState, key)
		}

		logging.Logf("[detectors] start %s (log=%s every=%s window=%s cooldown=%s limits: ip=%d user=%d root=%d scan=%d enrich=%t ptr=%t)",
			section, cfg.LogPath, cfg.Every, cfg.Window, cfg.Cooldown,
			cfg.DeniedPerIP, cfg.DeniedPerUser, cfg.RootPerIP, cfg.ScanPerIP,
			cfg.UseEnrich, cfg.UsePTR)

		return d, nil
	})

	// ---- [mysql_governor] — processlist monitor & kill engine -----------
	//
	// The governor is NOT a PeriodicDetector (no log file to tail, no
	// RunOnce loop).  This factory only parses the config and stores it in
	// pendingGovCfg.  main.go calls GetPendingGovernorConfig() after
	// detpkg.Start() to create and start the actual Governor.
	//
	// Returning nil tells the manager "no goroutine needed for this section",
	// which is intentional.
	Register("mysql_governor", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		if !kvBool(kv, "ENABLED", true) {
			pendingGovReady = false
			logging.Logf("[detectors] %s disabled in detectors.conf", section)
			return nil, nil
		}

		// Parse SLEEP_REAPER_EXEMPT = proxysql_monitor, root
		exemptRaw := kvStrClean(kv, "SLEEP_REAPER_EXEMPT", "proxysql_monitor,root")
		var exempt []string
		for _, u := range strings.FieldsFunc(exemptRaw, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			if u = strings.TrimSpace(u); u != "" {
				exempt = append(exempt, u)
			}
		}

		// Percentage values (CONN_WARN_PCT etc.) are always whole numbers in
		// practice, so kvInt + float64 cast avoids needing a separate kvFlt helper.
		pendingGovCfg = mysql.GovernorConfig{
			DSN:     kvStrClean(kv, "DSN", ""), // empty = auto-detect
			Enabled: true,

			PollEvery: kvDur(kv, "POLL_EVERY", 5*time.Second),
			Mode:      kvStrClean(kv, "MODE", "monitor"), // "monitor" | "enforce"

			ConnWarnPct: float64(kvInt(kv, "CONN_WARN_PCT", 70)),
			ConnActPct:  float64(kvInt(kv, "CONN_ACT_PCT",  85)),

			LockFanoutKill: kvInt(kv, "LOCK_FANOUT_KILL", 10),
			LockFanoutTTL:  kvDur(kv, "LOCK_FANOUT_TTL",  30*time.Second),

			SleepReaper:       kvBool(kv, "SLEEP_REAPER",     true),
			SleepReaperAge:    kvDur(kv,  "SLEEP_REAPER_AGE", 180*time.Second),
			SleepReaperExempt: exempt,

			KillPerDBPerWindow: kvInt(kv, "KILL_PER_DB_PER_WINDOW", 5),
			KillTotalPerWindow: kvInt(kv, "KILL_TOTAL_PER_WINDOW",  20),
			KillWindow:         kvDur(kv, "KILL_WINDOW",            10*time.Minute),

			// QueryRules: parsed separately once the config struct gains
			// a multiline-block parser for QUERY_RULES.
		}
		pendingGovReady = true

		logging.Logf("[detectors] %s config loaded (mode=%s poll=%s fanout_kill=%d sleep_reaper=%t exempt=%v)",
			section,
			pendingGovCfg.Mode,
			pendingGovCfg.PollEvery,
			pendingGovCfg.LockFanoutKill,
			pendingGovCfg.SleepReaper,
			pendingGovCfg.SleepReaperExempt,
		)

		return nil, nil // no goroutine; main.go starts the governor
	})
}
