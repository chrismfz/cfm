// internal/detectors/mysql/governor.go
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"cfm/internal/logging"
	"cfm/internal/notify"
)

// GovernorConfig mirrors the [mysql_governor] section in cfm.conf.
type GovernorConfig struct {
	// Auth — layered fallback (see openDB)
	DSN string // explicit DSN; empty = auto-detect

	Enabled   bool
	PollEvery time.Duration // default 5s
	Mode      string        // "monitor" | "enforce"  (default: monitor)

	// Connection pressure
	ConnWarnPct float64 // notify at N% of max_connections (default 70)
	ConnActPct  float64 // act at N% (default 85)

	// Per-query kill rules (ordered, first match wins)
	QueryRules []QueryRule

	// Lock fan-out: kill the blocker when it blocks >= N others
	LockFanoutKill int           // default 10
	LockFanoutTTL  time.Duration // must be blocking this long before kill (default 30s)

	// Sleep reaper (fixes Magento/WP connection leaks)
	SleepReaper       bool
	SleepReaperAge    time.Duration // default 180s
	SleepReaperExempt []string      // users to never reap

	// Kill rate limiting (safety)
	KillPerDBPerWindow int           // default 5
	KillTotalPerWindow int           // default 20
	KillWindow         time.Duration // default 10m
}

// RuleAction is the ordered severity of a rule outcome.
type RuleAction int

const (
	ActionNone            RuleAction = iota
	ActionIgnore                     // hard stop — never kill this user
	ActionNotify                     // send alert only
	ActionKillQuery                  // KILL QUERY id (statement dies, connection lives)
	ActionKillConnection             // KILL id (connection dies)
)

// QueryRule describes one entry in the query_rules list.
type QueryRule struct {
	UserPattern string
	MaxTime     time.Duration // 0 = ignore
	Action      RuleAction
	// Optional compound conditions (zero = not required)
	LockFanout int     // only fire if blocking >= N others
	ConnPct    float64 // only fire if conn pressure >= N%
}

// Process mirrors information_schema.PROCESSLIST row.
type Process struct {
	ID      int64
	User    string
	Host    string
	DB      string
	Command string
	TimeSec int64
	State   string
	Info    string // query text (may be truncated by MySQL)
}

// GovernorState is the snapshot read by the API and CLI.
type GovernorState struct {
	Ts          time.Time
	MaxConn     int
	TotalConn   int
	ActiveConn  int
	SleepConn   int
	LockedConn  int
	ConnPct     float64
	PerUser     []UserStat
	Running     []Process    // active + waiting, sorted by time desc
	LockGraph   []LockGroup  // blocker -> waiters
	RecentKills []KillRecord
	PerfDeltas  []UserPerfDelta // per-user CPU/query stats from performance_schema (nil if unavailable)
	Flavor      string // "10.11.7-MariaDB" | "8.0.36"
	Mode        string // "monitor" | "enforce" — copied from GovernorConfig each poll
}

// UserStat is per-user connection summary.
type UserStat struct {
	User        string
	Total       int
	Active      int
	Sleeping    int
	Locked      int
	MaxSleepSec int64
}

// LockGroup groups a blocking query with its waiters.
type LockGroup struct {
	Blocker Process
	Waiters []Process
}

// KillRecord is the audit entry for every governor action.
type KillRecord struct {
	Ts        time.Time
	PID       int64
	User      string
	DB        string
	Runtime   time.Duration
	State     string
	Query     string
	Action    string // "KILL QUERY" | "KILL CONNECTION" | "SLEEP REAP"
	Reason    string
	Result    string // "OK" | error text
	Unblocked int    // how many waiters were freed
}

// Governor is the MySQL monitoring / optional kill engine.
type Governor struct {
	cfg GovernorConfig
	db  *sql.DB

	mu    sync.RWMutex
	state GovernorState

	// kill rate limiting
	killLog []killEntry
	killMu  sync.Mutex

	maxConn int    // cached from @@max_connections
	flavor  string // detected once at startup

	// ring buffer for recent kills (last 100)
	killRing   []KillRecord
	killRingMu sync.Mutex

	// pressure notification cooldown — prevents re-alerting every 5s poll tick
	// during sustained connection pressure. Each severity level has its own timer.
	lastPressureWarn time.Time
	lastPressureCrit time.Time

	// history ring buffer — one entry per poll tick, retained for 24 h.
	// Used by TopUserHistory() for long-window "busiest user" queries.
	historySamples []HistorySample
	historyMu      sync.Mutex

	// performance_schema CPU / query tracking
	perfSchemaOK  bool                       // set once by probePerfSchema at startup
	perfHasCPU    bool                       // true on MySQL 8+; false on MariaDB (no SUM_CPU_TIME)
	perfCPUActive bool                       // true once we see at least one non-zero SUM_CPU_TIME delta
	perfRetryAt   time.Time                  // next time to re-probe when perfSchemaOK is false
	lastPerfRaw   map[string]perfRawRow      // cumulative counters from last poll
	perfDeltas    []UserPerfDelta            // most recent per-poll deltas
	perfDeltaMu   sync.RWMutex

	// MariaDB userstat — information_schema.USER_STATISTICS
	// Provides real CPU_TIME on MariaDB where SUM_CPU_TIME is absent.
	// userstatsOff=true means MariaDB was detected but userstat=OFF (show hint).
	userstatsOK      bool
	userstatsOff     bool
	lastUserstatRaw  map[string]userstatRawRow
}

type killEntry struct {
	ts time.Time
	db string
}

// alwaysExemptUsers are never killed regardless of rules — cPanel/DA/system internals.
var alwaysExemptUsers = map[string]bool{
	"root":              true,
	"cpanel":            true,
	"cpanelroundcube":   true,
	"cpaneleximscanner": true,
	"da_admin":          true,
	"debian-sys-maint":  true,
	"proxysql_monitor":  true,
	"mysql.sys":         true,
	"mysql.session":     true,
	"mariadb.sys":       true,
	"event_scheduler":   true,
}

// NewGovernor initialises the governor and verifies the DB connection.
func NewGovernor(cfg GovernorConfig) (*Governor, error) {
	// Apply defaults
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 5 * time.Second
	}
	if cfg.Mode == "" {
		cfg.Mode = "monitor"
	}
	if cfg.ConnWarnPct <= 0 {
		cfg.ConnWarnPct = 70
	}
	if cfg.ConnActPct <= 0 {
		cfg.ConnActPct = 85
	}
	if cfg.LockFanoutKill <= 0 {
		cfg.LockFanoutKill = 10
	}
	if cfg.LockFanoutTTL <= 0 {
		cfg.LockFanoutTTL = 30 * time.Second
	}
	if cfg.SleepReaperAge <= 0 {
		cfg.SleepReaperAge = 180 * time.Second
	}
	if cfg.KillPerDBPerWindow <= 0 {
		cfg.KillPerDBPerWindow = 5
	}
	if cfg.KillTotalPerWindow <= 0 {
		cfg.KillTotalPerWindow = 20
	}
	if cfg.KillWindow <= 0 {
		cfg.KillWindow = 10 * time.Minute
	}

	db, err := openDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("mysql_governor: cannot connect: %w", err)
	}
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	g := &Governor{cfg: cfg, db: db}
	if err := g.detectFlavor(); err != nil {
		logging.LogfMYSQLGOVERNOR("[mysql/governor] flavor detect failed: %v", err)
	}
	ctx := context.Background()
	g.probePerfSchema(ctx)
	return g, nil
}

// Run is the main polling loop. Blocks until ctx is cancelled.
func (g *Governor) Run(ctx context.Context) {
	logging.LogfMYSQLGOVERNOR("[mysql/governor] started mode=%s poll=%s flavor=%s",
		g.cfg.Mode, g.cfg.PollEvery, g.flavor)
	t := time.NewTicker(g.cfg.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.poll(ctx)
		}
	}
}

func (g *Governor) poll(ctx context.Context) {
	procs, err := g.fetchProcesslist(ctx)
	if err != nil {
		logging.LogfMYSQLGOVERNOR("[mysql/governor] processlist error: %v", err)
		return
	}

	maxConn := g.cachedMaxConn(ctx)
	state := g.buildState(procs, maxConn)

	// Evaluate rules and act
	kills := g.evaluate(ctx, state, procs)
	if len(kills) > 0 {
		g.appendKills(kills)
	}
	state.RecentKills = g.recentKills()

	// performance_schema CPU / query deltas (nil if perf_schema unavailable)
	state.PerfDeltas = g.fetchPerfDeltas(ctx)

	// Notify on connection pressure
	g.checkConnPressure(state)

	g.mu.Lock()
	g.state = state
	g.mu.Unlock()

	// Append to history ring buffer *after* state is published so the
	// snapshot the API returns and the one stored in history are identical.
	g.pushHistory(state)
}

// buildState computes GovernorState from a raw processlist snapshot.
func (g *Governor) buildState(procs []Process, maxConn int) GovernorState {
	now := time.Now()
	s := GovernorState{
		Ts:      now,
		MaxConn: maxConn,
		Flavor:  g.flavor,
		// Mode is copied into state so the API/CLI can read it without
		// needing access to the private cfg field.
		Mode: g.cfg.Mode,
	}

	userMap := map[string]*UserStat{}
	ensureUser := func(u string) *UserStat {
		if _, ok := userMap[u]; !ok {
			userMap[u] = &UserStat{User: u}
		}
		return userMap[u]
	}

	for _, p := range procs {
		s.TotalConn++
		u := ensureUser(p.User)
		u.Total++
		switch p.Command {
		case "Sleep":
			s.SleepConn++
			u.Sleeping++
			if p.TimeSec > u.MaxSleepSec {
				u.MaxSleepSec = p.TimeSec
			}
		case "Query":
			if isLockState(p.State) {
				s.LockedConn++
				u.Locked++
			} else {
				s.ActiveConn++
				u.Active++
			}
		}
	}

	if maxConn > 0 {
		s.ConnPct = float64(s.TotalConn) / float64(maxConn) * 100
	}

	// Per-user slice sorted by total desc
	for _, u := range userMap {
		s.PerUser = append(s.PerUser, *u)
	}
	sort.Slice(s.PerUser, func(i, j int) bool {
		return s.PerUser[i].Total > s.PerUser[j].Total
	})

	// Running queries (active + locked), sorted by time desc
	for _, p := range procs {
		if p.Command == "Query" {
			s.Running = append(s.Running, p)
		}
	}
	sort.Slice(s.Running, func(i, j int) bool {
		return s.Running[i].TimeSec > s.Running[j].TimeSec
	})

	// Build lock graph:
	// Simple heuristic: oldest non-waiting Query per DB is the probable blocker
	// for any lock-waiters in the same DB.
	dbOldest := map[string]Process{}
	for _, p := range procs {
		if p.Command == "Query" && !isLockState(p.State) {
			if cur, ok := dbOldest[p.DB]; !ok || p.TimeSec > cur.TimeSec {
				dbOldest[p.DB] = p
			}
		}
	}
	waitersByBlocker := map[int64][]Process{}
	blockerSeen := map[int64]bool{}
	for _, p := range procs {
		if isLockState(p.State) {
			if blocker, ok := dbOldest[p.DB]; ok {
				blockerSeen[blocker.ID] = true
				waitersByBlocker[blocker.ID] = append(waitersByBlocker[blocker.ID], p)
			}
		}
	}
	for bid := range blockerSeen {
		blocker := processBy(procs, bid)
		s.LockGraph = append(s.LockGraph, LockGroup{
			Blocker: blocker,
			Waiters: waitersByBlocker[bid],
		})
	}
	sort.Slice(s.LockGraph, func(i, j int) bool {
		return len(s.LockGraph[i].Waiters) > len(s.LockGraph[j].Waiters)
	})

	return s
}

// evaluate checks every running query against rules and acts.
func (g *Governor) evaluate(ctx context.Context, state GovernorState, procs []Process) []KillRecord {
	var kills []KillRecord

	for _, p := range procs {
		if p.Command != "Query" {
			continue
		}
		if alwaysExemptUsers[p.User] {
			continue
		}
		if isSystemDB(p.DB) {
			continue
		}

		action, reason := g.matchRules(p, state)
		if action == ActionNone || action == ActionIgnore {
			continue
		}

		if action == ActionNotify {
			notify.Enqueue(notify.Event{
				Kind:     "MYSQL/GOVERNOR",
				Section:  "mysql_governor",
				SrcIP:    "",
				Reason:   fmt.Sprintf("long query user=%s db=%s time=%ds state=%s", p.User, p.DB, p.TimeSec, p.State),
				Severity: "warn",
				Samples:  []string{truncate(p.Info, 200)},
			})
			continue
		}

		// Kill actions — check rate limits first
		if !g.killAllowed(p.DB) {
			logging.LogfMYSQLGOVERNOR("[mysql/governor] kill rate limited: user=%s db=%s pid=%d", p.User, p.DB, p.ID)
			continue
		}

		// Count waiters that will be freed
		unblocked := 0
		for _, lg := range state.LockGraph {
			if lg.Blocker.ID == p.ID {
				unblocked = len(lg.Waiters)
				break
			}
		}

		killSQL := "KILL QUERY"
		if action == ActionKillConnection {
			killSQL = "KILL"
		}

		result := "dry-run"
		actionLabel := "WOULD_" + killSQL + " (monitor mode)"

		if g.cfg.Mode == "enforce" {
			actionLabel = killSQL
			_, err := g.db.ExecContext(ctx, fmt.Sprintf("%s %d", killSQL, p.ID))
			if err != nil {
				result = err.Error()
			} else {
				result = "OK"
				g.recordKill(p.DB)
			}
		}

		kr := KillRecord{
			Ts:        time.Now(),
			PID:       p.ID,
			User:      p.User,
			DB:        p.DB,
			Runtime:   time.Duration(p.TimeSec) * time.Second,
			State:     p.State,
			Query:     truncate(p.Info, 300),
			Action:    actionLabel,
			Reason:    reason,
			Result:    result,
			Unblocked: unblocked,
		}

		logging.LogfMYSQLGOVERNOR("[mysql/governor] %s pid=%d user=%s db=%s runtime=%ds reason=%q unblocked=%d result=%s",
			kr.Action, kr.PID, kr.User, kr.DB, p.TimeSec, kr.Reason, kr.Unblocked, kr.Result)

		notify.Enqueue(notify.Event{
			Kind:    "MYSQL/GOVERNOR",
			Section: "mysql_governor",
			Reason: fmt.Sprintf("%s pid=%d user=%s db=%s runtime=%ds unblocked=%d",
				kr.Action, kr.PID, kr.User, kr.DB, p.TimeSec, kr.Unblocked),
			Severity: "critical",
			Samples:  []string{kr.Query, "reason: " + kr.Reason, "result: " + kr.Result},
		})

		kills = append(kills, kr)
	}

	// Sleep reaper (only under connection pressure in enforce mode)
	if g.cfg.SleepReaper && g.cfg.Mode == "enforce" && state.ConnPct > g.cfg.ConnActPct {
		for _, p := range procs {
			if p.Command != "Sleep" {
				continue
			}
			if alwaysExemptUsers[p.User] {
				continue
			}
			if isExempt(p.User, g.cfg.SleepReaperExempt) {
				continue
			}
			if time.Duration(p.TimeSec)*time.Second < g.cfg.SleepReaperAge {
				continue
			}
			// Guard: never kill a sleeping connection with an open InnoDB transaction
			if g.hasOpenTxn(ctx, p.ID) {
				continue
			}
			if !g.killAllowed(p.DB) {
				continue
			}

			result := "OK"
			if _, err := g.db.ExecContext(ctx, fmt.Sprintf("KILL %d", p.ID)); err != nil {
				result = err.Error()
			} else {
				g.recordKill(p.DB)
			}

			kr := KillRecord{
				Ts:      time.Now(),
				PID:     p.ID,
				User:    p.User,
				DB:      p.DB,
				Runtime: time.Duration(p.TimeSec) * time.Second,
				State:   "Sleep",
				Action:  "KILL CONNECTION",
				Reason:  fmt.Sprintf("sleep reaper: idle %ds > %s", p.TimeSec, g.cfg.SleepReaperAge),
				Result:  result,
			}
			kills = append(kills, kr)
			logging.LogfMYSQLGOVERNOR("[mysql/governor] sleep reap pid=%d user=%s db=%s idle=%ds result=%s",
				p.ID, p.User, p.DB, p.TimeSec, result)
		}
	}

	return kills
}

// matchRules evaluates the ordered rule list and returns the highest-severity action.
func (g *Governor) matchRules(p Process, state GovernorState) (RuleAction, string) {
	best := ActionNone
	bestReason := ""

	for _, r := range g.cfg.QueryRules {
		if !matchUser(r.UserPattern, p.User) {
			continue
		}
		// MaxTime == 0 means "ignore this user unconditionally"
		if r.MaxTime == 0 {
			return ActionIgnore, "rule:ignore"
		}
		if time.Duration(p.TimeSec)*time.Second < r.MaxTime {
			continue
		}
		// Optional compound conditions
		if r.LockFanout > 0 && g.lockWaitersFor(state, p.ID) < r.LockFanout {
			continue
		}
		if r.ConnPct > 0 && state.ConnPct < r.ConnPct {
			continue
		}
		if r.Action > best {
			best = r.Action
			bestReason = fmt.Sprintf("rule %q: %s runtime=%ds",
				r.UserPattern, actionName(r.Action), p.TimeSec)
		}
	}

	// Auto lock fan-out kill (takes over if rules haven't already escalated higher)
	fanout := g.lockWaitersFor(state, p.ID)
	if fanout >= g.cfg.LockFanoutKill &&
		time.Duration(p.TimeSec)*time.Second >= g.cfg.LockFanoutTTL &&
		best < ActionKillQuery {
		best = ActionKillQuery
		bestReason = fmt.Sprintf("lock_fanout=%d runtime=%ds", fanout, p.TimeSec)
	}

	return best, bestReason
}

// State returns a copy of the current snapshot (safe for concurrent reads).
func (g *Governor) State() GovernorState {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.state
}

// ---- internal helpers ----

func (g *Governor) detectFlavor() error {
	row := g.db.QueryRow("SELECT VERSION()")
	var v string
	if err := row.Scan(&v); err != nil {
		return err
	}
	g.flavor = v
	logging.LogfMYSQLGOVERNOR("[mysql/governor] connected, version=%s", v)
	return nil
}

func (g *Governor) cachedMaxConn(ctx context.Context) int {
	if g.maxConn > 0 {
		return g.maxConn
	}
	row := g.db.QueryRowContext(ctx, "SELECT @@max_connections")
	_ = row.Scan(&g.maxConn)
	return g.maxConn
}

func (g *Governor) fetchProcesslist(ctx context.Context) ([]Process, error) {
	rows, err := g.db.QueryContext(ctx,
		`SELECT ID, USER, HOST, COALESCE(DB,''), COMMAND, TIME,
		        COALESCE(STATE,''), COALESCE(INFO,'')
		 FROM information_schema.PROCESSLIST
		 WHERE USER != 'system user'
		 ORDER BY TIME DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var procs []Process
	for rows.Next() {
		var p Process
		if err := rows.Scan(&p.ID, &p.User, &p.Host, &p.DB,
			&p.Command, &p.TimeSec, &p.State, &p.Info); err != nil {
			continue
		}
		procs = append(procs, p)
	}
	return procs, rows.Err()
}

// hasOpenTxn checks information_schema.INNODB_TRX to protect sleeping connections
// that are mid-transaction (committing would be incorrect if we kill them).
func (g *Governor) hasOpenTxn(ctx context.Context, pid int64) bool {
	row := g.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.INNODB_TRX
		 WHERE TRX_MYSQL_THREAD_ID = ?`, pid)
	var n int
	_ = row.Scan(&n)
	return n > 0
}

// pressureNotifyCooldown is the minimum time between two pressure alerts of the
// same severity.  Without this, every 5s poll during a sustained high-connection
// event would enqueue a notify — wasteful and noisy.
const pressureNotifyCooldown = 5 * time.Minute

// checkConnPressure fires notify alerts when connections approach max_connections.
// Re-alerts at most once per pressureNotifyCooldown per severity level.
func (g *Governor) checkConnPressure(state GovernorState) {
	now := time.Now()

	if state.ConnPct >= g.cfg.ConnActPct {
		if now.Sub(g.lastPressureCrit) < pressureNotifyCooldown {
			return
		}
		g.lastPressureCrit = now
		g.lastPressureWarn = now // crit supersedes warn; reset both

		top := ""
		if len(state.PerUser) > 0 {
			top = fmt.Sprintf("  top user: %s (%d conns)", state.PerUser[0].User, state.PerUser[0].Total)
		}
		notify.Enqueue(notify.Event{
			Kind:    "MYSQL/CONN_PRESSURE",
			Section: "mysql_governor",
			Reason: fmt.Sprintf("CRITICAL %d/%d (%.0f%%)%s",
				state.TotalConn, state.MaxConn, state.ConnPct, top),
			Severity: "critical",
		})
		return
	}

	if state.ConnPct >= g.cfg.ConnWarnPct {
		if now.Sub(g.lastPressureWarn) < pressureNotifyCooldown {
			return
		}
		g.lastPressureWarn = now
		notify.Enqueue(notify.Event{
			Kind:    "MYSQL/CONN_PRESSURE",
			Section: "mysql_governor",
			Reason: fmt.Sprintf("WARNING %d/%d (%.0f%%)",
				state.TotalConn, state.MaxConn, state.ConnPct),
			Severity: "warn",
		})
	}
}

func (g *Governor) killAllowed(db string) bool {
	g.killMu.Lock()
	defer g.killMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-g.cfg.KillWindow)

	// Prune old entries
	valid := g.killLog[:0]
	for _, e := range g.killLog {
		if e.ts.After(cutoff) {
			valid = append(valid, e)
		}
	}
	g.killLog = valid

	dbCount, total := 0, len(g.killLog)
	for _, e := range g.killLog {
		if e.db == db {
			dbCount++
		}
	}

	if total >= g.cfg.KillTotalPerWindow {
		return false
	}
	if dbCount >= g.cfg.KillPerDBPerWindow {
		return false
	}
	return true
}

func (g *Governor) recordKill(db string) {
	g.killMu.Lock()
	g.killLog = append(g.killLog, killEntry{ts: time.Now(), db: db})
	g.killMu.Unlock()
}

func (g *Governor) appendKills(kr []KillRecord) {
	g.killRingMu.Lock()
	defer g.killRingMu.Unlock()
	g.killRing = append(kr, g.killRing...)
	if len(g.killRing) > 100 {
		g.killRing = g.killRing[:100]
	}
}

func (g *Governor) recentKills() []KillRecord {
	g.killRingMu.Lock()
	defer g.killRingMu.Unlock()
	out := make([]KillRecord, len(g.killRing))
	copy(out, g.killRing)
	return out
}

func (g *Governor) lockWaitersFor(state GovernorState, pid int64) int {
	for _, lg := range state.LockGraph {
		if lg.Blocker.ID == pid {
			return len(lg.Waiters)
		}
	}
	return 0
}

// ---- pure utility functions ----

func isLockState(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "lock") || strings.Contains(s, "waiting")
}

func isSystemDB(db string) bool {
	switch strings.ToLower(db) {
	case "information_schema", "mysql", "performance_schema", "sys", "":
		return true
	}
	return false
}

func isExempt(user string, exempts []string) bool {
	for _, e := range exempts {
		if e == user {
			return true
		}
	}
	return false
}

func matchUser(pattern, user string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(user, pattern[:len(pattern)-1])
	}
	return pattern == user
}

func actionName(a RuleAction) string {
	switch a {
	case ActionIgnore:
		return "ignore"
	case ActionNotify:
		return "notify"
	case ActionKillQuery:
		return "kill_query"
	case ActionKillConnection:
		return "kill_connection"
	}
	return "none"
}

func processBy(procs []Process, id int64) Process {
	for _, p := range procs {
		if p.ID == id {
			return p
		}
	}
	return Process{}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
