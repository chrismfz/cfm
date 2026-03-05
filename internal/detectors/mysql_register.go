// internal/detectors/mysql_register.go
package detectors

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/mysql"
	"cfm/internal/logging"
)

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
	Register("mysql_governor", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		if !kvBool(kv, "ENABLED", true) {
			pendingGovReady = false
			logging.Logf("[detectors] %s disabled in detectors.conf", section)
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
		queryRules := parseQueryRules(kvLines(kv, "QUERY_RULES"))

		// ── CONN_RULES multiline block ───────────────────────────────────────
		connRules := parseConnRules(kvLines(kv, "CONN_RULES"))

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

		logging.Logf(
			"[detectors] %s loaded mode=%s poll=%s fanout_kill=%d sleep_reaper=%t"+
				" query_rules=%d conn_rules=%d exempt=%v",
			section,
			pendingGovCfg.Mode,
			pendingGovCfg.PollEvery,
			pendingGovCfg.LockFanoutKill,
			pendingGovCfg.SleepReaper,
			len(queryRules),
			len(connRules),
			pendingGovCfg.SleepReaperExempt,
		)

		return nil, nil // no goroutine; main.go starts the governor
	})
}

// ── parseQueryRules ───────────────────────────────────────────────────────────
//
// Parses the QUERY_RULES multiline block.
//
// Each non-empty line has the format:
//
//	<user_pattern> : <max_runtime> : <action> [: condition ...]
//
//	user_pattern  — exact name, prefix* wildcard, or * for everyone
//	max_runtime   — duration (30s, 5m, 1h) or 0 to ignore the user entirely
//	action        — notify | kill_query | kill_connection | ignore
//	condition     — lock_fanout=N   (only if blocking >= N others)
//	                conn_pct=N      (only if global conn >= N%)
func parseQueryRules(lines []string) []mysql.QueryRule {
	var rules []mysql.QueryRule
	for _, line := range lines {
		parts := splitColon(line)
		if len(parts) < 3 {
			logging.Logf("[detectors/mysql] QUERY_RULES: skipping malformed line %q", line)
			continue
		}

		userPattern := strings.TrimSpace(parts[0])
		maxTimeStr := strings.TrimSpace(parts[1])
		actionStr := strings.ToLower(strings.TrimSpace(parts[2]))

		// max_runtime: "0" means ignore, otherwise parse duration
		var maxTime time.Duration
		if maxTimeStr == "0" {
			maxTime = 0
		} else {
			d, err := time.ParseDuration(maxTimeStr)
			if err != nil {
				logging.Logf("[detectors/mysql] QUERY_RULES: bad duration %q in %q", maxTimeStr, line)
				continue
			}
			maxTime = d
		}

		action, ok := parseQueryAction(actionStr)
		if !ok {
			logging.Logf("[detectors/mysql] QUERY_RULES: unknown action %q in %q", actionStr, line)
			continue
		}

		r := mysql.QueryRule{
			UserPattern: userPattern,
			MaxTime:     maxTime,
			Action:      action,
		}

		// Optional conditions (4th field onward)
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
					logging.Logf("[detectors/mysql] QUERY_RULES: unknown condition %q in %q", cond, line)
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
//
//	user_pattern  — exact name, prefix* wildcard, or * for everyone
//	max=N         — connection cap (total connections including sleeping)
//	action        — notify | reap_sleep | alter_user
//	condition     — conn_pct=N  (only enforce when global conn >= N%)
//	                             omit for always-active (static) cap
func parseConnRules(lines []string) []mysql.ConnRule {
	var rules []mysql.ConnRule
	for _, line := range lines {
		parts := splitColon(line)
		if len(parts) < 3 {
			logging.Logf("[detectors/mysql] CONN_RULES: skipping malformed line %q", line)
			continue
		}

		userPattern := strings.TrimSpace(parts[0])
		maxStr := strings.ToLower(strings.TrimSpace(parts[1]))
		actionStr := strings.ToLower(strings.TrimSpace(parts[2]))

		if !strings.HasPrefix(maxStr, "max=") {
			logging.Logf("[detectors/mysql] CONN_RULES: expected max=N, got %q in %q", maxStr, line)
			continue
		}
		max, err := strconv.Atoi(strings.TrimPrefix(maxStr, "max="))
		if err != nil || max <= 0 {
			logging.Logf("[detectors/mysql] CONN_RULES: invalid max value in %q", line)
			continue
		}

		action, ok := parseConnAction(actionStr)
		if !ok {
			logging.Logf("[detectors/mysql] CONN_RULES: unknown action %q in %q", actionStr, line)
			continue
		}

		r := mysql.ConnRule{
			UserPattern: userPattern,
			Max:         max,
			Action:      action,
		}

		// Optional condition (4th field)
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

// splitColon splits on ":" but NOT on "::" (URL schemes etc.) and trims
// whitespace from each field.
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

// fmtRules summarises rules for the startup log line (avoid printing every rule).
func fmtRules(n int, kind string) string {
	if n == 0 {
		return fmt.Sprintf("no %s", kind)
	}
	return fmt.Sprintf("%d %s", n, kind)
}
