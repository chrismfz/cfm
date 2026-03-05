// internal/detectors/mysql/governor_conn.go
//
// Per-user connection-limit enforcement.
//
// Two complementary mechanisms:
//
//   reap_sleep   — on every poll: if a user has more connections than their cap,
//                  kill the oldest sleeping ones (InnoDB open-tx guard applies).
//                  Requires only PROCESS privilege (already needed for KILL).
//
//   alter_user   — issue ALTER USER … WITH MAX_USER_CONNECTIONS N so MariaDB
//                  refuses new connections beyond the cap at the protocol level.
//                  Automatically reversed when the user drops back under limit.
//                  Requires CREATE USER privilege added to cfm_governor.
//                  Falls through to reap_sleep for existing sleeping connections.
//
// notify        — alert only, no kill. Use as a first-stage early-warning rule.
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

// enforceConnRules is called from poll() after buildState().
// It checks every user against the CONN_RULES list and acts on violations.
func (g *Governor) enforceConnRules(ctx context.Context, state GovernorState, procs []Process) []KillRecord {
	if len(g.cfg.ConnRules) == 0 {
		return nil
	}

	// Build per-user sorted sleeper list (oldest idle first — we kill those first).
	type sleeper struct {
		pid  int64
		idle int64
	}
	userSleepers := map[string][]sleeper{}
	for _, p := range procs {
		if p.Command == "Sleep" && !alwaysExemptUsers[p.User] {
			userSleepers[p.User] = append(userSleepers[p.User], sleeper{p.ID, p.TimeSec})
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
			// No matching rule — if we previously applied alter_user, reverse it.
			g.maybeRestoreAlterUser(ctx, us.User)
			continue
		}

		excess := us.Total - rule.Max
		if excess <= 0 {
			// User is under or at limit. Reverse any previously applied ALTER USER.
			if rule.Action == ConnActionAlterUser {
				g.maybeRestoreAlterUser(ctx, us.User)
			}
			continue
		}

		reason := fmt.Sprintf("conn_limit user=%s total=%d max=%d excess=%d",
			us.User, us.Total, rule.Max, excess)

		switch rule.Action {

		case ConnActionNotify:
			// Rate-limited to avoid flooding the log every 5s poll.
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
			// Step 1: apply ALTER USER so MariaDB blocks new connections.
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
				if g.hasOpenTxn(ctx, s.pid) {
					continue
				}
				if !g.killAllowed(us.User) {
					logging.LogfMYSQLGOVERNOR(
						"[mysql/conn_limit] rate-limited, skipping reap user=%s pid=%d",
						us.User, s.pid)
					break
				}

				result := "dry-run"
				actionLabel := "WOULD_KILL CONNECTION (monitor mode)"

				if g.cfg.Mode == "enforce" {
					actionLabel = "KILL CONNECTION"
					if _, err := g.db.ExecContext(ctx,
						fmt.Sprintf("KILL %d", s.pid)); err != nil {
						result = err.Error()
					} else {
						result = "OK"
						g.recordKill(us.User)
						reaped++
					}
				}

				kr := KillRecord{
					Ts:      time.Now(),
					PID:     s.pid,
					User:    us.User,
					Runtime: time.Duration(s.idle) * time.Second,
					State:   "Sleep",
					Action:  actionLabel,
					Reason: fmt.Sprintf("conn_limit: excess=%d max=%d total=%d",
						excess, rule.Max, us.Total),
					Result: result,
				}
				kills = append(kills, kr)

				logging.LogfMYSQLGOVERNOR(
					"[mysql/conn_limit] %s pid=%d user=%s idle=%ds excess=%d result=%s",
					actionLabel, s.pid, us.User, s.idle, excess, result)
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
		// Dynamic trigger: skip if global connection pressure hasn't reached threshold.
		if r.ConnPct > 0 && state.ConnPct < r.ConnPct {
			continue
		}
		return r, true
	}
	return ConnRule{}, false
}

// ── ALTER USER helpers ────────────────────────────────────────────────────────

// applyAlterUser sets MAX_USER_CONNECTIONS on the user (both @localhost and @%)
// so MariaDB refuses new connections beyond the cap. Skips if already applied.
func (g *Governor) applyAlterUser(ctx context.Context, user string, max int) {
	g.alterUserMu.Lock()
	defer g.alterUserMu.Unlock()

	if g.alterUserLimits == nil {
		g.alterUserLimits = map[string]int{}
	}
	if g.alterUserLimits[user] == max {
		return // already applied at this limit, no-op
	}

	applied := false
	// cPanel creates users as 'user'@'%'; DirectAdmin as 'user'@'localhost'.
	// We try both and ignore "user does not exist" errors silently.
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

// maybeRestoreAlterUser removes a previously applied connection cap.
// Called when a user drops back under their limit or no longer matches a rule.
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

// ── Notify cooldown for conn rules ───────────────────────────────────────────

// connNotifyAllowed returns true if enough time has passed since the last
// notify for this user. Updates the last-notify timestamp on true.
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

