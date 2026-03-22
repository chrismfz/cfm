// internal/detectors/mysql/governor_conn.go
//
// Per-user connection-limit enforcement.
//
// Two complementary mechanisms:
//
//   reap_sleep   — on every poll: if a user has more connections than their cap,
//                  kill the oldest sleeping ones (by idle time) until back under
//                  the limit. InnoDB open-transaction guard always applied.
//                  Requires only PROCESS privilege.
//
//   alter_user   — issue ALTER USER … WITH MAX_USER_CONNECTIONS N so MariaDB
//                  refuses new connections beyond the cap at the protocol level.
//                  Also falls through to reap_sleep to clean up existing sleepers.
//                  Reversed automatically when the user drops back under limit.
//                  Requires GRANT CREATE USER ON *.* TO 'cfm_governor'@'localhost'.
//
//   notify       — alert only, no kill. Use as an early-warning first stage.
//
// Persistence safety — ALTER USER writes to mysql.user and survives MySQL
// restarts.  Two mechanisms keep caps from getting permanently stuck:
//
//   auditAlterUserOnStartup  — runs once in NewGovernor. Queries mysql.user for
//                              any non-zero MAX_USER_CONNECTIONS that match our
//                              alter_user rules and resets them to 0.  Handles
//                              cfm crash / restart / update scenarios.
//
//   cleanupStaleAlterCaps    — runs every alterAuditInterval (15 min) from poll().
//                              Reverses caps for users that have dropped under
//                              their limit or have zero connections at all (site
//                              offline, account suspended). Handles the edge case
//                              where a user vanishes from the processlist entirely
//                              so enforceConnRules never sees them.
//
// Notify cooldown: a per-user notify is suppressed for connNotifyCooldown after
// the last fire, so a persistently-over-limit user does not flood the log.
//
package mysql

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"cfm/internal/logging"
	"cfm/internal/notify"
)

// ConnRuleAction is the enforcement action for a connection-limit rule.
type ConnRuleAction int

const (
	ConnActionNotify    ConnRuleAction = iota // alert only
	ConnActionReapSleep                       // KILL oldest sleeping connections above cap
	ConnActionAlterUser                       // ALTER USER MAX_USER_CONNECTIONS N (+ reap_sleep)
)

// ConnRule describes one entry in the CONN_RULES list.
type ConnRule struct {
	UserPattern string
	Max         int            // connection cap (total connections for this user)
	Action      ConnRuleAction
	ConnPct     float64        // dynamic trigger: only enforce when global conn >= N%
	                           // 0 = always active (static)
}

// connNotifyCooldown suppresses repeated notify-only alerts for the same user.
const connNotifyCooldown = 10 * time.Minute

// alterAuditInterval controls how often cleanupStaleAlterCaps runs from poll().
const alterAuditInterval = 15 * time.Minute

// ── enforceConnRules ─────────────────────────────────────────────────────────

// enforceConnRules is called from poll() after buildState().
// It checks every user against the CONN_RULES list and acts on violations.
func (g *Governor) enforceConnRules(ctx context.Context, state GovernorState, procs []Process) []KillRecord {
	if len(g.cfg.ConnRules) == 0 {
		return nil
	}

	// Build per-user sorted sleeper list (oldest idle first — kill those first).
	type sleeper struct {
		proc Process
		idle int64
	}
	userSleepers := map[string][]sleeper{}
	for _, p := range procs {
		if p.Command == "Sleep" && !alwaysExemptUsers[p.User] {
			userSleepers[p.User] = append(userSleepers[p.User], sleeper{
				proc: p,
				idle: p.TimeSec,
			})
		}
	}
	for u := range userSleepers {
		sort.Slice(userSleepers[u], func(i, j int) bool {
			return userSleepers[u][i].idle > userSleepers[u][j].idle // oldest first
		})
	}

	var kills []KillRecord

	for _, us := range state.PerUser {
		if alwaysExemptUsers[us.User] {
			continue
		}

		rule, matched := g.matchConnRule(us.User, state)
		if !matched {
			// No matching rule — reverse any previously applied ALTER USER cap.
			g.maybeRestoreAlterUser(ctx, us.User)
			continue
		}

		excess := us.Total - rule.Max
		if excess <= 0 {
			// User is at or under limit — reverse any previously applied ALTER USER.
			if rule.Action == ConnActionAlterUser {
				g.maybeRestoreAlterUser(ctx, us.User)
			}
			continue
		}

		reason := fmt.Sprintf("conn_limit user=%s total=%d max=%d excess=%d",
			us.User, us.Total, rule.Max, excess)

		switch rule.Action {

		case ConnActionNotify:
			if g.connNotifyAllowed(us.User) {
				logging.LogfMYSQLGOVERNOR("[mysql/conn_limit] NOTIFY %s", reason)
				notify.Enqueue(notify.Event{
					Kind:     "MYSQL/CONN_LIMIT",
					Section:  "mysql_governor",
					Reason:   reason,
					Severity: "warn",
				})
			}

		case ConnActionAlterUser:
			// Step 1: apply ALTER USER so MariaDB blocks new connections at the
			// protocol level. applyAlterUser is idempotent — skips if already set.
			logging.LogfMYSQLGOVERNOR("[mysql/conn_limit] ALTER_USER %s", reason)
			notify.Enqueue(notify.Event{
				Kind:     "MYSQL/CONN_LIMIT",
				Section:  "mysql_governor",
				Reason:   "ALTER_USER " + reason,
				Severity: "warn",
			})
			if g.cfg.Mode == "enforce" {
				g.applyAlterUser(ctx, us.User, rule.Max)
			}
			// Step 2: also reap existing sleepers above the cap (fallthrough).
			fallthrough
		case ConnActionReapSleep:
			sleepers := userSleepers[us.User]
			reaped := 0

			for _, s := range sleepers {
				if reaped >= excess {
					break
				}

				// Never kill a sleeping connection with an open InnoDB transaction.
				if g.hasOpenTxn(ctx, s.proc.ID) {
					continue
				}

				if !g.killAllowed(s.proc.DB) {
					logging.LogfMYSQLGOVERNOR(
						"[mysql/conn_limit] rate-limited, skipping reap user=%s pid=%d",
						us.User, s.proc.ID)
					break
				}

				result := "dry-run"
				actionLabel := "WOULD_KILL CONNECTION (monitor mode)"

				if g.cfg.Mode == "enforce" {
					actionLabel = "KILL CONNECTION"
					if _, err := g.db.ExecContext(ctx, fmt.Sprintf("KILL %d", s.proc.ID)); err != nil {
						result = err.Error()
					} else {
						result = "OK"
						g.recordKill(s.proc.DB)
					}
				}

				kr := KillRecord{
					Ts:        time.Now(),
					PID:       s.proc.ID,
					User:      us.User,
					Host:      s.proc.Host,
					DB:        s.proc.DB,
					Runtime:   time.Duration(s.proc.TimeSec) * time.Second,
					State:     s.proc.State,
					Query:     truncate(strings.TrimSpace(s.proc.Info), 300),
					Action:    actionLabel,
					Reason:    fmt.Sprintf("conn_limit: excess=%d max=%d total=%d idle=%ds",
						excess, rule.Max, us.Total, s.proc.TimeSec),
					Result:    result,
					Unblocked: 0,
				}

				kills = append(kills, kr)
				reaped++

				logging.LogfMYSQLGOVERNOR(
					"[mysql/conn_limit] %s pid=%d user=%s host=%s db=%s total=%d max=%d excess=%d idle=%ds state=%q query=%q result=%s",
					kr.Action, kr.PID, kr.User, kr.Host, kr.DB,
					us.Total, rule.Max, excess, s.proc.TimeSec,
					kr.State, truncate(kr.Query, 120), kr.Result)
			}

			// Save ONE forensic snapshot for this conn-limit batch, not one per PID.
			if reaped > 0 {
				g.appendHistoryEvent(GovernorHistoryEvent{
					TsUnix:    time.Now().Unix(),
					EventType: "conn_limit",
					User:      us.User,
					Action:    "reap_sleep",
					Reason:    fmt.Sprintf("conn_limit snapshot user=%s total=%d max=%d reaped=%d", us.User, us.Total, rule.Max, reaped),
					ConnPct:   state.ConnPct,
					TotalConn: state.TotalConn,
					MaxConn:   state.MaxConn,
					Payload:   g.buildSnapshotForUser(state, us.User, ""),
				})
			}

			if rule.Action == ConnActionReapSleep && g.connNotifyAllowed(us.User) {
				notify.Enqueue(notify.Event{
					Kind:     "MYSQL/CONN_LIMIT",
					Section:  "mysql_governor",
					Reason:   fmt.Sprintf("REAP_SLEEP %s reaped=%d", reason, reaped),
					Severity: "warn",
				})
			}






		}
	}

	return kills
}

// matchConnRule finds the first CONN_RULES entry whose user pattern matches
// and whose trigger condition (if any) is met. Returns false if nothing matches.
func (g *Governor) matchConnRule(user string, state GovernorState) (ConnRule, bool) {
	for _, r := range g.cfg.ConnRules {
		if !matchUser(r.UserPattern, user) {
			continue
		}
		// Dynamic trigger: skip if global connection pressure is below threshold.
		if r.ConnPct > 0 && state.ConnPct < r.ConnPct {
			continue
		}
		return r, true
	}
	return ConnRule{}, false
}

// ── ALTER USER helpers ────────────────────────────────────────────────────────

// applyAlterUser sets MAX_USER_CONNECTIONS on the user (both @localhost and @%)
// so MariaDB refuses new connections beyond the cap. Idempotent — skips if the
// same limit is already recorded in alterUserLimits.
func (g *Governor) applyAlterUser(ctx context.Context, user string, max int) {
	g.alterUserMu.Lock()
	defer g.alterUserMu.Unlock()

	if g.alterUserLimits == nil {
		g.alterUserLimits = map[string]int{}
	}
	if g.alterUserLimits[user] == max {
		return // already applied at this cap, no-op
	}

	applied := false
	// cPanel creates users as 'user'@'%'; DirectAdmin as 'user'@'localhost'.
	// We try both and silently ignore "user does not exist" errors.
	for _, host := range []string{"%", "localhost"} {
		sql := fmt.Sprintf(
			"ALTER USER '%s'@'%s' WITH MAX_USER_CONNECTIONS %d",
			strings.ReplaceAll(user, "'", "''"), host, max)
		if _, err := g.db.ExecContext(ctx, sql); err == nil {
			applied = true
			logging.LogfMYSQLGOVERNOR(
				"[mysql/conn_limit] alter_user applied user=%s@%s MAX_USER_CONNECTIONS=%d",
				user, host, max)
		}
	}
	if applied {
		g.alterUserLimits[user] = max
	}
}

// maybeRestoreAlterUser removes a previously applied connection cap by setting
// MAX_USER_CONNECTIONS back to 0 (unlimited).
// Called when a user drops back under their limit or no longer matches any rule.
// Acquires alterUserMu — callers must NOT hold it.
func (g *Governor) maybeRestoreAlterUser(ctx context.Context, user string) {
	g.alterUserMu.Lock()
	defer g.alterUserMu.Unlock()

	if g.alterUserLimits == nil || g.alterUserLimits[user] == 0 {
		return // nothing to restore
	}

	for _, host := range []string{"%", "localhost"} {
		sql := fmt.Sprintf(
			"ALTER USER '%s'@'%s' WITH MAX_USER_CONNECTIONS 0",
			strings.ReplaceAll(user, "'", "''"), host)
		if _, err := g.db.ExecContext(ctx, sql); err == nil {
			logging.LogfMYSQLGOVERNOR(
				"[mysql/conn_limit] alter_user restored user=%s@%s MAX_USER_CONNECTIONS=0",
				user, host)
		}
	}
	g.alterUserLimits[user] = 0
}

// ── Startup audit ─────────────────────────────────────────────────────────────

// auditAlterUserOnStartup queries mysql.user for any accounts that currently
// have a non-zero MAX_USER_CONNECTIONS and match one of our alter_user rules.
// These are caps left behind by a previous cfm run (crash, restart, update).
// We reset them to 0 so the governor starts from a clean slate rather than
// enforcing with state it has no memory of.
//
// Only resets accounts that match an alter_user rule in the current config —
// accounts a DBA capped manually are left untouched.
//
// Called once from NewGovernor, before the poll loop starts.
func (g *Governor) auditAlterUserOnStartup(ctx context.Context) {
	// Quick-exit: no alter_user rules configured — nothing to clean up.
	hasAlterRule := false
	for _, r := range g.cfg.ConnRules {
		if r.Action == ConnActionAlterUser {
			hasAlterRule = true
			break
		}
	}
	if !hasAlterRule {
		return
	}

	rows, err := g.db.QueryContext(ctx,
		`SELECT User, Host FROM mysql.user WHERE MAX_USER_CONNECTIONS > 0`)
	if err != nil {
		// Not fatal — the governor still starts. Worst case: a stale cap persists
		// until cleanupStaleAlterCaps catches it on the first 15-minute sweep.
		logging.LogfMYSQLGOVERNOR(
			"[mysql/conn_limit] startup audit: could not read mysql.user: %v", err)
		return
	}
	defer rows.Close()

	type account struct{ user, host string }
	var stale []account

	for rows.Next() {
		var u, h string
		if err := rows.Scan(&u, &h); err != nil {
			continue
		}
		// Only reset accounts that match one of our alter_user patterns.
		for _, r := range g.cfg.ConnRules {
			if r.Action == ConnActionAlterUser && matchUser(r.UserPattern, u) {
				stale = append(stale, account{u, h})
				break
			}
		}
	}
	if rows.Err() != nil {
		logging.LogfMYSQLGOVERNOR(
			"[mysql/conn_limit] startup audit: row scan error: %v", rows.Err())
		return
	}

	if len(stale) == 0 {
		logging.LogfMYSQLGOVERNOR(
			"[mysql/conn_limit] startup audit: no stale alter_user caps found")
		return
	}

	logging.LogfMYSQLGOVERNOR(
		"[mysql/conn_limit] startup audit: found %d stale cap(s) — resetting", len(stale))

	g.alterUserMu.Lock()
	defer g.alterUserMu.Unlock()

	if g.alterUserLimits == nil {
		g.alterUserLimits = map[string]int{}
	}

	for _, a := range stale {
		sql := fmt.Sprintf(
			"ALTER USER '%s'@'%s' WITH MAX_USER_CONNECTIONS 0",
			strings.ReplaceAll(a.user, "'", "''"), a.host)
		if _, err := g.db.ExecContext(ctx, sql); err != nil {
			logging.LogfMYSQLGOVERNOR(
				"[mysql/conn_limit] startup audit: failed to reset %s@%s: %v",
				a.user, a.host, err)
		} else {
			logging.LogfMYSQLGOVERNOR(
				"[mysql/conn_limit] startup audit: reset stale cap for %s@%s",
				a.user, a.host)
			g.alterUserLimits[a.user] = 0
		}
	}
}

// ── Periodic stale-cap cleanup ────────────────────────────────────────────────

// cleanupStaleAlterCaps reverses ALTER USER caps for users that are currently
// under their cap or have zero connections.
//
// maybeRestoreAlterUser handles the normal "user drops under limit" path inside
// enforceConnRules on every poll. This function handles the edge case where the
// user disappears from the processlist entirely — they won't appear in
// state.PerUser, so enforceConnRules never visits them and maybeRestoreAlterUser
// is never called for them.
//
// Called from poll() every alterAuditInterval (15 minutes).
// Acquires alterUserMu internally — callers must NOT hold it.
func (g *Governor) cleanupStaleAlterCaps(ctx context.Context, state GovernorState) {
	g.alterUserMu.Lock()
	defer g.alterUserMu.Unlock()

	if len(g.alterUserLimits) == 0 {
		return
	}

	// Quick lookup of current total connections per user from the processlist snap.
	active := make(map[string]int, len(state.PerUser))
	for _, u := range state.PerUser {
		active[u.User] = u.Total
	}

	for user, cap := range g.alterUserLimits {
		if cap == 0 {
			continue // already cleared
		}

		conns := active[user] // 0 if user has no connections at all

		if conns < cap {
			// User is under their cap (or offline). Reverse the ALTER USER.
			for _, host := range []string{"%", "localhost"} {
				sql := fmt.Sprintf(
					"ALTER USER '%s'@'%s' WITH MAX_USER_CONNECTIONS 0",
					strings.ReplaceAll(user, "'", "''"), host)
				g.db.ExecContext(ctx, sql) //nolint:errcheck — best-effort, logged below
			}
			g.alterUserLimits[user] = 0
			logging.LogfMYSQLGOVERNOR(
				"[mysql/conn_limit] periodic cleanup: restored %s (was capped at %d, now %d conns)",
				user, cap, conns)
		}
	}
}

// ── Notify cooldown ───────────────────────────────────────────────────────────

// connNotifyAllowed returns true if enough time has elapsed since the last
// notify for this user. Updates the timestamp when returning true.
func (g *Governor) connNotifyAllowed(user string) bool {
	g.connNotifyMu.Lock()
	defer g.connNotifyMu.Unlock()
	if g.connNotifyLast == nil {
		g.connNotifyLast = map[string]time.Time{}
	}
	last := g.connNotifyLast[user]
	if time.Since(last) < connNotifyCooldown {
		return false
	}
	g.connNotifyLast[user] = time.Now()
	return true
}
