// internal/detectors/mysql_register.go
package detectors

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/mysql"
	"cfm/internal/logging"
)

var mysqlState = core.DefaultState()

var (
	pendingGovCfg   mysql.GovernorConfig
	pendingGovReady bool
)

// GetPendingGovernorConfig returns the parsed GovernorConfig if the
// [mysql_governor] section was found and ENABLED=1.
func GetPendingGovernorConfig() (mysql.GovernorConfig, bool) {
	return pendingGovCfg, pendingGovReady
}

func init() {
	meta.Register(meta.DetectorMeta{TypeKey: "mysql", Title: "MySQL auth", Description: "Detect MySQL login abuse.", DefaultsTemplate: map[string]string{"ENABLED": "1", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "BLOCK": "dryrun"}, LeniencySupported: true})
	meta.Register(meta.DetectorMeta{TypeKey: "mysql_governor", Title: "MySQL governor", Description: "Connection/query governor for MySQL.", DefaultsTemplate: map[string]string{"ENABLED": "1", "EVERY": "5s"}})
	// -------------------------------------------------------------------------
	// [mysql] — brute-force / login detector
	// -------------------------------------------------------------------------
	Register("mysql", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		if !kvBool(kv, "ENABLED", true) {
			logMySQLGovf("[detectors] %s disabled in detectors.conf", section)
			return nil, nil
		}

		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		rawDirs := kvStrClean(kv, "ENRICH_DIRS", kvStrClean(global, "ENRICH_DIRS", ""))
		var dirs []string
		if rawDirs != "" {
			fields := strings.FieldsFunc(rawDirs, func(r rune) bool {
				return r == ',' || r == ':' || r == ' ' || r == '\t'
			})
			for _, f := range fields {
				if f != "" {
					dirs = append(dirs, f)
				}
			}
		}

		useEnrich := kvBool(kv, "ENRICH", kvBool(global, "ENRICH", true))
		usePTR := kvBool(kv, "PTR", kvBool(global, "PTR", true))

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

			DeniedPerIP:   kvInt(kv, "DENIED_IP", 10),
			DeniedPerUser: kvInt(kv, "DENIED_USER", 10),
			RootPerIP:     kvInt(kv, "ROOT_IP", 3),
			ScanPerIP:     kvInt(kv, "SCAN_IP", 20),

			UseEnrich:       useEnrich,
			UsePTR:          usePTR,
			EnrichDirs:      dirs,
			IgnoreLocalhost: kvBool(kv, "IGNORE_LOCALHOST", true),
			IgnoreCpanel:    kvBool(kv, "IGNORE_CPANEL_UTIL", true),
		}

		d := mysql.NewMySQL(cfg)
		d.SetName(section)

		src := core.NewFileTailer(cfg.LogPath)
		d.SetSource(src)

		if mysqlState != nil {
			// key := core.FileStateKey(section, cfg.LogPath)
			// d.SetState(mysqlState, key)
		}

		logMySQLGovf(
			"[detectors] start %s (every=%s window=%s cooldown=%s log=%s limits: ip=%d user=%d root=%d scan=%d enrich=%t ptr=%t dirs=%v)",
			section,
			cfg.Every,
			cfg.Window,
			cfg.Cooldown,
			cfg.LogPath,
			cfg.DeniedPerIP,
			cfg.DeniedPerUser,
			cfg.RootPerIP,
			cfg.ScanPerIP,
			cfg.UseEnrich,
			cfg.UsePTR,
			cfg.EnrichDirs,
		)

		return d, nil
	})

	// -------------------------------------------------------------------------
	// [mysql_governor] — processlist monitor + query/conn rules
	// -------------------------------------------------------------------------
	Register("mysql_governor", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		if !kvBool(kv, "ENABLED", true) {
			pendingGovReady = false
			logMySQLGovf("[detectors] %s disabled in detectors.conf", section)
			return nil, nil
		}

		// ── SLEEP_REAPER_EXEMPT ──────────────────────────────────────────────
		exemptRaw := kvStrClean(kv, "SLEEP_REAPER_EXEMPT", "proxysql_monitor,root")
		var exempt []string
		for _, u := range strings.FieldsFunc(exemptRaw, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			if u = strings.TrimSpace(u); u != "" {
				exempt = append(exempt, u)
			}
		}

		// ── QUERY_RULES multiline block ──────────────────────────────────────
		rawQueryLines := kvLines(kv, "QUERY_RULES")
		queryRules := parseQueryRules(rawQueryLines)
		logMySQLGovf("[detectors] %s mysql_governor QUERY_RULES loaded=%d source=detectors.conf", section, len(queryRules))

		// ── CONN_RULES multiline block ───────────────────────────────────────
		rawConnLines := kvLines(kv, "CONN_RULES")
		connRules := parseConnRules(rawConnLines)
		logMySQLGovf("[detectors] %s mysql_governor CONN_RULES loaded=%d source=detectors.conf", section, len(connRules))

		if logging.DebugEnabled() {
			logMySQLGovf("[detectors] %s raw QUERY_RULES lines=%d raw CONN_RULES lines=%d",
				section, len(rawQueryLines), len(rawConnLines))

			for i, line := range rawQueryLines {
				logMySQLGovf("[detectors] %s QUERY_RULES raw[%d]=%q", section, i, line)
			}
			for i, line := range rawConnLines {
				logMySQLGovf("[detectors] %s CONN_RULES raw[%d]=%q", section, i, line)
			}

			for i, r := range queryRules {
				logMySQLGovf("[detectors] %s query_rule[%d]: user=%q max=%s action=%s lock_fanout=%d conn_pct=%.0f",
					section, i, r.UserPattern, r.MaxTime, queryActionName(r.Action), r.LockFanout, r.ConnPct)
			}

			for i, r := range connRules {
				logMySQLGovf("[detectors] %s conn_rule[%d]: user=%q max=%d action=%s conn_pct=%.0f",
					section, i, r.UserPattern, r.Max, connActionName(r.Action), r.ConnPct)
			}
		}

		// ── Build GovernorConfig ─────────────────────────────────────────────
		pendingGovCfg = mysql.GovernorConfig{
			DSN:     kvStrClean(kv, "DSN", ""),
			Enabled: true,

			PollEvery: kvDur(kv, "POLL_EVERY", 5*time.Second),
			Mode:      kvStrClean(kv, "MODE", "monitor"),

			ConnWarnPct: float64(kvInt(kv, "CONN_WARN_PCT", 70)),
			ConnActPct:  float64(kvInt(kv, "CONN_ACT_PCT", 85)),

			QueryRules: queryRules,
			ConnRules:  connRules,

			LockFanoutKill: kvInt(kv, "LOCK_FANOUT_KILL", 10),
			LockFanoutTTL:  kvDur(kv, "LOCK_FANOUT_TTL", 30*time.Second),

			SleepReaper:       kvBool(kv, "SLEEP_REAPER", true),
			SleepReaperAge:    kvDur(kv, "SLEEP_REAPER_AGE", 180*time.Second),
			SleepReaperExempt: exempt,

			KillPerDBPerWindow: kvInt(kv, "KILL_PER_DB_PER_WINDOW", 5),
			KillTotalPerWindow: kvInt(kv, "KILL_TOTAL_PER_WINDOW", 20),
			KillWindow:         kvDur(kv, "KILL_WINDOW", 10*time.Minute),
		}
		pendingGovReady = true

		logMySQLGovf(
			"[detectors] %s loaded mode=%s poll=%s fanout_kill=%d sleep_reaper=%t query_rules=%d conn_rules=%d exempt=%v",
			section,
			pendingGovCfg.Mode,
			pendingGovCfg.PollEvery,
			pendingGovCfg.LockFanoutKill,
			pendingGovCfg.SleepReaper,
			len(queryRules),
			len(connRules),
			pendingGovCfg.SleepReaperExempt,
		)

		return nil, nil // config-only; main.go starts the governor
	})
}

// ── parseQueryRules ───────────────────────────────────────────────────────────
//
// Parses the QUERY_RULES multiline block.
//
// Each non-empty line has the format:
//
//	<user_pattern> : <max_runtime> : <action> [: condition ...]
func parseQueryRules(lines []string) []mysql.QueryRule {
	var rules []mysql.QueryRule
	for _, line := range lines {
		parts := splitColon(line)
		if len(parts) < 3 {
			logMySQLGovf("[detectors/mysql] QUERY_RULES: skipping malformed line %q", line)
			continue
		}

		userPattern := strings.TrimSpace(parts[0])
		maxTimeStr := strings.TrimSpace(parts[1])
		actionStr := strings.ToLower(strings.TrimSpace(parts[2]))

		var maxTime time.Duration
		if maxTimeStr == "0" {
			maxTime = 0
		} else {
			d, err := parseCfgDuration(maxTimeStr)
			if err != nil {
				logMySQLGovf("[detectors/mysql] QUERY_RULES: bad duration %q in %q", maxTimeStr, line)
				continue
			}
			maxTime = d
		}

		action, ok := parseQueryAction(actionStr)
		if !ok {
			logMySQLGovf("[detectors/mysql] QUERY_RULES: unknown action %q in %q", actionStr, line)
			continue
		}

		r := mysql.QueryRule{
			UserPattern: userPattern,
			MaxTime:     maxTime,
			Action:      action,
		}

		for _, raw := range parts[3:] {
			cond := strings.TrimSpace(raw)
			switch {
			case strings.HasPrefix(cond, "lock_fanout="):
				n, err := strconv.Atoi(strings.TrimPrefix(cond, "lock_fanout="))
				if err == nil {
					r.LockFanout = n
				}
			case strings.HasPrefix(cond, "conn_pct="):
				f, err := strconv.ParseFloat(strings.TrimPrefix(cond, "conn_pct="), 64)
				if err == nil {
					r.ConnPct = f
				}
			default:
				if cond != "" {
					logMySQLGovf("[detectors/mysql] QUERY_RULES: unknown condition %q in %q", cond, line)
				}
			}
		}

		rules = append(rules, r)
	}
	return rules
}

// ── parseConnRules ────────────────────────────────────────────────────────────
//
// Parses the CONN_RULES multiline block.
//
// Each non-empty line has the format:
//
//	<user_pattern> : max=N : <action> [: condition]
func parseConnRules(lines []string) []mysql.ConnRule {
	var rules []mysql.ConnRule
	for _, line := range lines {
		parts := splitColon(line)
		if len(parts) < 3 {
			logMySQLGovf("[detectors/mysql] CONN_RULES: skipping malformed line %q", line)
			continue
		}

		userPattern := strings.TrimSpace(parts[0])
		maxStr := strings.ToLower(strings.TrimSpace(parts[1]))
		actionStr := strings.ToLower(strings.TrimSpace(parts[2]))

		if !strings.HasPrefix(maxStr, "max=") {
			logMySQLGovf("[detectors/mysql] CONN_RULES: expected max=N, got %q in %q", maxStr, line)
			continue
		}

		max, err := strconv.Atoi(strings.TrimPrefix(maxStr, "max="))
		if err != nil || max <= 0 {
			logMySQLGovf("[detectors/mysql] CONN_RULES: invalid max value in %q", line)
			continue
		}

		action, ok := parseConnAction(actionStr)
		if !ok {
			logMySQLGovf("[detectors/mysql] CONN_RULES: unknown action %q in %q", actionStr, line)
			continue
		}

		r := mysql.ConnRule{
			UserPattern: userPattern,
			Max:         max,
			Action:      action,
		}

		for _, raw := range parts[3:] {
			cond := strings.TrimSpace(raw)
			if strings.HasPrefix(cond, "conn_pct=") {
				f, err := strconv.ParseFloat(strings.TrimPrefix(cond, "conn_pct="), 64)
				if err == nil {
					r.ConnPct = f
				}
			}
		}

		rules = append(rules, r)
	}
	return rules
}

// ── helpers ───────────────────────────────────────────────────────────────────

func splitColon(s string) []string {
	raw := strings.Split(s, ":")
	var out []string
	for _, f := range raw {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}

func parseQueryAction(s string) (mysql.RuleAction, bool) {
	switch s {
	case "ignore":
		return mysql.ActionIgnore, true
	case "notify":
		return mysql.ActionNotify, true
	case "kill_query":
		return mysql.ActionKillQuery, true
	case "kill_connection":
		return mysql.ActionKillConnection, true
	}
	return mysql.ActionNone, false
}

func parseConnAction(s string) (mysql.ConnRuleAction, bool) {
	switch s {
	case "notify":
		return mysql.ConnActionNotify, true
	case "reap_sleep":
		return mysql.ConnActionReapSleep, true
	case "alter_user":
		return mysql.ConnActionAlterUser, true
	}
	return mysql.ConnActionNotify, false
}

func fmtRules(n int, kind string) string {
	if n == 0 {
		return fmt.Sprintf("no %s", kind)
	}
	return fmt.Sprintf("%d %s", n, kind)
}

func connActionName(a mysql.ConnRuleAction) string {
	switch a {
	case mysql.ConnActionNotify:
		return "notify"
	case mysql.ConnActionReapSleep:
		return "reap_sleep"
	case mysql.ConnActionAlterUser:
		return "alter_user"
	default:
		return "unknown"
	}
}

func queryActionName(a mysql.RuleAction) string {
	switch a {
	case mysql.ActionIgnore:
		return "ignore"
	case mysql.ActionNotify:
		return "notify"
	case mysql.ActionKillQuery:
		return "kill_query"
	case mysql.ActionKillConnection:
		return "kill_connection"
	default:
		return "unknown"
	}
}

func logMySQLGovf(format string, args ...any) {
	logging.Logf(format, args...)
	logging.LogfMYSQLGOVERNOR(format, args...)
}

func logMySQLDetf(format string, args ...any) {
	logging.Logf(format, args...)
	logging.LogfMYSQLGOVERNOR(format, args...)
}
