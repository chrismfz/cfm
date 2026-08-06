// internal/detectors/mysql/governor_history.go
package mysql

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"cfm/internal/logging"
)

// ---------------------------------------------------------------------------
// Historical connection samples — sliding-window "busiest user" queries
// ---------------------------------------------------------------------------

// HistorySample captures the per-user connection snapshot from one poll tick.
// A copy of PerUser is stored so the ring-buffer entries are immutable after
// insertion.
type HistorySample struct {
	Ts      time.Time
	PerUser []UserStat
}

// UserHistoryStat is the aggregated view of one user across a time window.
type UserHistoryStat struct {
	User       string  `json:"user"`
	PeakConns  int     `json:"peak_conns"`
	AvgConns   float64 `json:"avg_conns"`
	PeakActive int     `json:"peak_active"`
	AvgActive  float64 `json:"avg_active"`
	PeakLocked int     `json:"peak_locked"`
	Samples    int     `json:"samples"` // how many poll ticks the user was seen
}

// pushHistory appends one snapshot to the history ring buffer and prunes
// entries older than 24 h.  At the default 5 s poll interval this caps out at
// ~17,280 samples (~1–2 MB RAM).
func (g *Governor) pushHistory(s GovernorState) {
	sample := HistorySample{
		Ts:      s.Ts,
		PerUser: make([]UserStat, len(s.PerUser)),
	}
	copy(sample.PerUser, s.PerUser)

	g.historyMu.Lock()
	defer g.historyMu.Unlock()

	g.historySamples = append(g.historySamples, sample)

	// Trim samples older than 24 h.  Samples are appended in chronological
	// order so the oldest are always at the front.
	cutoff := time.Now().Add(-24 * time.Hour)
	i := 0
	for i < len(g.historySamples) && g.historySamples[i].Ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		// Avoid memory leak from the underlying array growing forever.
		trimmed := make([]HistorySample, len(g.historySamples)-i)
		copy(trimmed, g.historySamples[i:])
		g.historySamples = trimmed
	}
}

// TopUserHistory aggregates history samples within the requested window and
// returns per-user stats sorted by peak connections descending.
// Pass topN=0 to return all users.
func (g *Governor) TopUserHistory(window time.Duration, topN int) []UserHistoryStat {
	cutoff := time.Now().Add(-window)

	g.historyMu.Lock()
	// Find first sample inside the window.
	start := len(g.historySamples) // default: none in window
	for i, s := range g.historySamples {
		if !s.Ts.Before(cutoff) {
			start = i
			break
		}
	}
	// Shallow-copy so we drop the lock before aggregating.
	snap := make([]HistorySample, len(g.historySamples)-start)
	copy(snap, g.historySamples[start:])
	g.historyMu.Unlock()

	type acc struct {
		peakConns  int
		sumConns   int64
		peakActive int
		sumActive  int64
		peakLocked int
		count      int
	}
	agg := map[string]*acc{}

	for _, s := range snap {
		for _, u := range s.PerUser {
			a, ok := agg[u.User]
			if !ok {
				a = &acc{}
				agg[u.User] = a
			}
			a.count++
			a.sumConns += int64(u.Total)
			if u.Total > a.peakConns {
				a.peakConns = u.Total
			}
			a.sumActive += int64(u.Active)
			if u.Active > a.peakActive {
				a.peakActive = u.Active
			}
			if u.Locked > a.peakLocked {
				a.peakLocked = u.Locked
			}
		}
	}

	out := make([]UserHistoryStat, 0, len(agg))
	for user, a := range agg {
		stat := UserHistoryStat{
			User:       user,
			PeakConns:  a.peakConns,
			PeakActive: a.peakActive,
			PeakLocked: a.peakLocked,
			Samples:    a.count,
		}
		if a.count > 0 {
			stat.AvgConns = float64(a.sumConns) / float64(a.count)
			stat.AvgActive = float64(a.sumActive) / float64(a.count)
		}
		out = append(out, stat)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].PeakConns > out[j].PeakConns
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// HistorySampleCount returns how many poll-tick samples are currently retained.
// Useful for the API to report the effective history depth.
func (g *Governor) HistorySampleCount() int {
	g.historyMu.Lock()
	defer g.historyMu.Unlock()
	return len(g.historySamples)
}

// ---------------------------------------------------------------------------
// performance_schema + userstat CPU / query tracking
//
// Three source paths, selected at probe time and fixed for the lifetime of
// the process (unless a re-probe fires after a MySQL restart):
//
//   Path A — MySQL 8+
//     performance_schema.events_statements_summary_by_user_by_event_name
//     Provides: SUM_CPU_TIME, COUNT_STAR, SUM_TIMER_WAIT
//     Requires: performance_schema=ON  +  statement instruments enabled
//
//   Path B — MariaDB with userstat=ON
//     performance_schema  →  COUNT_STAR, SUM_TIMER_WAIT  (query count + latency)
//     information_schema.USER_STATISTICS  →  CPU_TIME, ROWS_READ, ROWS_SENT
//     Requires: performance_schema=ON  +  userstat=ON
//
//   Path C — MariaDB with userstat=OFF  (fallback / hint mode)
//     performance_schema  →  COUNT_STAR, SUM_TIMER_WAIT only
//     CPU column is always 0; CLI shows how to enable userstat.
// ---------------------------------------------------------------------------

// perfRawRow holds one user's cumulative counters from
// events_statements_summary_by_user_by_event_name.
// All times are in picoseconds (MariaDB and MySQL both use pico).
// CPUPico is only populated on MySQL 8+ (Path A); stays 0 on MariaDB.
type perfRawRow struct {
	CPUPico   int64 // SUM_CPU_TIME (MySQL 8+ only; 0 on MariaDB)
	CountStar int64 // COUNT_STAR       — total query invocations
	WaitPico  int64 // SUM_TIMER_WAIT   — total elapsed wall time
}

// userstatRawRow holds one user's cumulative counters from
// information_schema.USER_STATISTICS (MariaDB userstat=ON, Path B).
// CPU_TIME and BUSY_TIME are in seconds (float), not picoseconds.
type userstatRawRow struct {
	CPUSec   float64 // CPU_TIME  — CPU seconds consumed
	BusySec  float64 // BUSY_TIME — wall-clock seconds connection was active
	RowsRead int64   // ROWS_READ
	RowsSent int64   // ROWS_SENT
}

// UserPerfDelta is the per-poll-window delta for one user, ready for display.
// Included in GovernorState so the API and CLI can expose it.
//
// Source mapping:
//
//	CPUSec       — Path A: SUM_CPU_TIME/1e12   Path B: CPU_TIME delta   Path C: 0
//	QueryCount   — Path A+B+C: COUNT_STAR delta
//	AvgQueryMsec — Path A+B+C: SUM_TIMER_WAIT delta / COUNT_STAR delta / 1e9
//	RowsRead     — Path B only (userstat); omitted (0) on Path A and C
//	RowsSent     — Path B only (userstat); omitted (0) on Path A and C
type UserPerfDelta struct {
	User         string  `json:"user"`
	CPUSec       float64 `json:"cpu_sec"`             // CPU seconds in the last poll window
	BusySec      float64 `json:"busy_sec,omitempty"`  // wall-clock busy seconds (MariaDB userstat only)
	QueryCount   int64   `json:"query_count"`         // queries executed in the last poll window
	AvgQueryMsec float64 `json:"avg_query_msec"`      // mean wall-time latency per query, ms
	RowsRead     int64   `json:"rows_read,omitempty"` // rows read (MariaDB userstat only)
	RowsSent     int64   `json:"rows_sent,omitempty"` // rows sent (MariaDB userstat only)
}

// probePerfSchema checks once at startup (and on retry) which data sources
// are available and selects the appropriate query path (A, B, or C — see
// file header).  Called from NewGovernor and from fetchPerfDeltas on retry.
//
// Compatibility notes:
//   - @@performance_schema is INT 0/1 on both MariaDB and MySQL 8.
//     We scan into sql.NullInt64 first; fall back to SHOW VARIABLES on error.
//   - SUM_CPU_TIME exists on MySQL 8+ but NOT on MariaDB — we probe
//     information_schema.COLUMNS to distinguish rather than running the SELECT.
//   - @@userstat is MariaDB-only; the column simply does not exist on MySQL.
func (g *Governor) probePerfSchema(ctx context.Context) {
	// Reset all flags so a re-probe starts from a clean state.
	g.perfSchemaOK = false
	g.perfHasCPU = false
	g.perfCPUActive = false
	g.userstatsOK = false
	g.userstatsOff = false

	// ---- Step 1: is performance_schema ON? --------------------------------
	var psInt sql.NullInt64
	if err := g.db.QueryRowContext(ctx, "SELECT @@performance_schema").Scan(&psInt); err == nil {
		if !psInt.Valid || psInt.Int64 != 1 {
			logging.Logf("[mysql/governor] performance_schema is OFF — query stats disabled")
			return
		}
	} else {
		// Fallback: SHOW VARIABLES returns ("performance_schema", "ON"/"OFF")
		var varName, varValue string
		if err2 := g.db.QueryRowContext(ctx,
			"SHOW VARIABLES LIKE 'performance_schema'").Scan(&varName, &varValue); err2 != nil {
			logging.Logf("[mysql/governor] cannot read @@performance_schema (%v; %v) — query stats disabled", err, err2)
			return
		}
		if varValue != "ON" && varValue != "1" && varValue != "YES" {
			logging.Logf("[mysql/governor] performance_schema is OFF (%q) — query stats disabled", varValue)
			return
		}
	}

	// ---- Step 2: does the summary table exist? ----------------------------
	var tableExists int
	if err := g.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM   information_schema.TABLES
		WHERE  TABLE_SCHEMA = 'performance_schema'
		  AND  TABLE_NAME   = 'events_statements_summary_by_user_by_event_name'`,
	).Scan(&tableExists); err != nil || tableExists == 0 {
		logging.Logf("[mysql/governor] performance_schema.events_statements_summary_by_user_by_event_name missing — query stats disabled")
		return
	}

	// performance_schema is usable from here — query count + latency work on
	// both MySQL and MariaDB regardless of the CPU path chosen below.
	g.perfSchemaOK = true

	// ---- Step 3: does SUM_CPU_TIME exist? → MySQL 8+ (Path A) ------------
	var cpuColExists int
	if err := g.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM   information_schema.COLUMNS
		WHERE  TABLE_SCHEMA = 'performance_schema'
		  AND  TABLE_NAME   = 'events_statements_summary_by_user_by_event_name'
		  AND  COLUMN_NAME  = 'SUM_CPU_TIME'`,
	).Scan(&cpuColExists); err != nil {
		logging.Logf("[mysql/governor] cannot probe SUM_CPU_TIME column (%v) — continuing without CPU time", err)
	}

	if cpuColExists > 0 {
		// Path A: MySQL 8+ — SUM_CPU_TIME available.
		// perfCPUActive will flip to true the first time we see a non-zero delta
		// (instruments may still need enabling; we report that in the CLI hint).
		g.perfHasCPU = true
		logging.Logf("[mysql/governor] Path A (MySQL 8+): performance_schema CPU + query tracking enabled (flavor: %s)", g.flavor)
		return
	}

	// ---- Step 4: MariaDB — probe information_schema.USER_STATISTICS -------
	// userstat=ON gives us real CPU_TIME and row counts.  userstat=OFF means
	// we stay on Path C (query-only) and show a hint in the CLI.

	// Check if the variable exists at all (it's MariaDB-only).
	var userstatName, userstatValue string
	err := g.db.QueryRowContext(ctx,
		"SHOW VARIABLES LIKE 'userstat'").Scan(&userstatName, &userstatValue)

	if err != nil {
		// Variable doesn't exist → this is MySQL without SUM_CPU_TIME (old build).
		// Stay on Path C.
		logging.Logf("[mysql/governor] Path C (no CPU source): query count + latency only (flavor: %s)", g.flavor)
		return
	}

	// Variable exists — this is MariaDB.
	if userstatValue != "ON" && userstatValue != "1" && userstatValue != "YES" {
		// Path C with hint: userstat is there but disabled.
		g.userstatsOff = true
		logging.Logf("[mysql/governor] Path C (MariaDB, userstat=OFF): query count + latency only — enable userstat for CPU tracking (flavor: %s)", g.flavor)
		return
	}

	// userstat=ON — verify the table is actually readable.
	var dummy int
	if err := g.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM information_schema.USER_STATISTICS",
	).Scan(&dummy); err != nil {
		logging.Logf("[mysql/governor] information_schema.USER_STATISTICS unreadable (%v) — CPU tracking disabled", err)
		return
	}

	// Path B: MariaDB with userstat=ON.
	g.userstatsOK = true
	logging.Logf("[mysql/governor] Path B (MariaDB + userstat): CPU + query + rows tracking enabled (flavor: %s)", g.flavor)
}

// probeUserstatEnabled checks whether userstat is available but off, without
// doing a full probe.  Used by the API to populate the hint flag even when
// the full probe hasn't re-run yet.
func (g *Governor) probeUserstatEnabled(ctx context.Context) (exists, enabled bool) {
	var name, value string
	if err := g.db.QueryRowContext(ctx,
		"SHOW VARIABLES LIKE 'userstat'").Scan(&name, &value); err != nil {
		return false, false
	}
	return true, value == "ON" || value == "1" || value == "YES"
}

// fetchPerfDeltas is called every poll tick.  It selects the appropriate path
// based on the flags set by probePerfSchema and merges the data sources.
//
// Auto-retry: when perfSchemaOK is false, re-probes every 5 minutes so cfm
// self-heals after a MySQL restart or after performance_schema is enabled
// without restarting cfm.  The baseline is reset on a successful re-probe
// so the first delta doesn't produce a false spike.
// userstatRetryEvery bounds how often fetchPerfDeltas re-checks @@userstat while
// it's off, so a runtime enable is picked up promptly without a per-poll query.
const userstatRetryEvery = 60 * time.Second

func (g *Governor) fetchPerfDeltas(ctx context.Context) []UserPerfDelta {
	if !g.perfSchemaOK {
		if time.Now().Before(g.perfRetryAt) {
			return nil
		}
		g.perfRetryAt = time.Now().Add(5 * time.Minute)
		g.probePerfSchema(ctx)
		if !g.perfSchemaOK {
			return nil
		}
		g.lastPerfRaw = nil
		g.lastUserstatRaw = nil
	}

	// ---- Live upgrade to Path B when userstat is enabled at runtime ----
	// probePerfSchema only runs at startup (and while perfSchemaOK is false), so
	// a `SET GLOBAL userstat=ON` issued after cfm started is otherwise invisible
	// until a restart. When we're on MariaDB with userstat currently off, re-check
	// @@userstat cheaply on a cadence and upgrade to Path B (CPU/busy/rows) live.
	if g.userstatsOff && !g.userstatsOK && !time.Now().Before(g.userstatRetryAt) {
		g.userstatRetryAt = time.Now().Add(userstatRetryEvery)
		if exists, enabled := g.probeUserstatEnabled(ctx); exists && enabled {
			var dummy int
			if err := g.db.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM information_schema.USER_STATISTICS").Scan(&dummy); err == nil {
				g.userstatsOK = true
				g.userstatsOff = false
				g.lastUserstatRaw = nil // reset baseline so the first delta isn't a false spike
				logging.Logf("[mysql/governor] userstat enabled at runtime — upgrading to Path B (CPU/busy/rows tracking)")
			}
		}
	}

	// ---- Fetch perf_schema counters (query count + latency, all paths) ----
	var perfQuery string
	if g.perfHasCPU {
		// Path A: include SUM_CPU_TIME
		perfQuery = `
			SELECT   USER,
			         COALESCE(SUM(SUM_CPU_TIME),  0),
			         COALESCE(SUM(COUNT_STAR),     0),
			         COALESCE(SUM(SUM_TIMER_WAIT), 0)
			FROM     performance_schema.events_statements_summary_by_user_by_event_name
			WHERE    USER IS NOT NULL
			GROUP BY USER`
	} else {
		// Path B / C: no SUM_CPU_TIME column; substitute literal 0
		perfQuery = `
			SELECT   USER,
			         0,
			         COALESCE(SUM(COUNT_STAR),     0),
			         COALESCE(SUM(SUM_TIMER_WAIT), 0)
			FROM     performance_schema.events_statements_summary_by_user_by_event_name
			WHERE    USER IS NOT NULL
			GROUP BY USER`
	}

	rows, err := g.db.QueryContext(ctx, perfQuery)
	if err != nil {
		logging.Logf("[mysql/governor] performance_schema query failed, disabling query stats: %v", err)
		g.perfSchemaOK = false
		return nil
	}

	currentPerf := make(map[string]perfRawRow)
	for rows.Next() {
		var user string
		var r perfRawRow
		if err := rows.Scan(&user, &r.CPUPico, &r.CountStar, &r.WaitPico); err != nil {
			continue
		}
		currentPerf[user] = r
	}
	rows.Close()
	if rows.Err() != nil {
		return nil
	}

	// ---- Fetch userstat counters (Path B only) ----------------------------
	// cpu (seconds float) + rows — merged into the per-user delta below.
	var currentUserstat map[string]userstatRawRow
	if g.userstatsOK {
		currentUserstat = g.fetchUserstatRaw(ctx)
		if currentUserstat == nil {
			// Table became unreadable — fall back to Path C quietly.
			logging.Logf("[mysql/governor] USER_STATISTICS read failed, falling back to query-only tracking")
			g.userstatsOK = false
			g.userstatsOff = true
		}
	}

	// ---- Compute deltas ---------------------------------------------------
	prevPerf := g.lastPerfRaw
	prevUserstat := g.lastUserstatRaw
	g.lastPerfRaw = currentPerf
	g.lastUserstatRaw = currentUserstat

	if prevPerf == nil {
		// First successful call — establish baseline, return nothing yet.
		return nil
	}

	var out []UserPerfDelta
	for user, cur := range currentPerf {
		p := prevPerf[user]

		cpuDelta := cur.CPUPico - p.CPUPico
		countDelta := cur.CountStar - p.CountStar
		waitDelta := cur.WaitPico - p.WaitPico

		// Counter rollback = server restart.
		if cpuDelta < 0 {
			cpuDelta = cur.CPUPico
		}
		if countDelta < 0 {
			countDelta = cur.CountStar
		}
		if waitDelta < 0 {
			waitDelta = cur.WaitPico
		}

		if cpuDelta == 0 && countDelta == 0 {
			continue
		}

		// Path A: detect instruments going live for the first time.
		if g.perfHasCPU && cpuDelta > 0 && !g.perfCPUActive {
			g.perfCPUActive = true
			logging.Logf("[mysql/governor] SUM_CPU_TIME is being populated — CPU tracking active")
		}

		d := UserPerfDelta{
			User:       user,
			CPUSec:     float64(cpuDelta) / 1e12,
			QueryCount: countDelta,
		}
		if countDelta > 0 {
			d.AvgQueryMsec = float64(waitDelta) / float64(countDelta) / 1e9
		}

		// Path B: overlay CPU + rows from USER_STATISTICS.
		// The userstat delta replaces the zero CPUSec from the perf_schema row.
		if g.userstatsOK && currentUserstat != nil && prevUserstat != nil {
			cu := currentUserstat[user]
			pu := prevUserstat[user]

			cpuSecDelta := cu.CPUSec - pu.CPUSec
			busySecDelta := cu.BusySec - pu.BusySec
			rowsReadDelta := cu.RowsRead - pu.RowsRead
			rowsSentDelta := cu.RowsSent - pu.RowsSent

			if cpuSecDelta < 0 {
				cpuSecDelta = cu.CPUSec
			}
			if busySecDelta < 0 {
				busySecDelta = cu.BusySec
			}
			if rowsReadDelta < 0 {
				rowsReadDelta = cu.RowsRead
			}
			if rowsSentDelta < 0 {
				rowsSentDelta = cu.RowsSent
			}

			d.CPUSec = cpuSecDelta
			d.BusySec = busySecDelta
			d.RowsRead = rowsReadDelta
			d.RowsSent = rowsSentDelta

			if cpuSecDelta > 0 && !g.perfCPUActive {
				g.perfCPUActive = true
				logging.Logf("[mysql/governor] USER_STATISTICS CPU_TIME is being populated — CPU tracking active")
			}
		}

		out = append(out, d)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CPUSec != out[j].CPUSec {
			return out[i].CPUSec > out[j].CPUSec
		}
		return out[i].QueryCount > out[j].QueryCount
	})

	g.perfDeltaMu.Lock()
	g.perfDeltas = out
	g.perfDeltaMu.Unlock()

	return out
}

// fetchUserstatRaw reads the current cumulative USER_STATISTICS counters.
// Returns nil on any error so the caller can fall back gracefully.
func (g *Governor) fetchUserstatRaw(ctx context.Context) map[string]userstatRawRow {
	rows, err := g.db.QueryContext(ctx, `
		SELECT USER,
		       CPU_TIME,
		       BUSY_TIME,
		       ROWS_READ,
		       ROWS_SENT
		FROM   information_schema.USER_STATISTICS
		WHERE  USER IS NOT NULL`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make(map[string]userstatRawRow)
	for rows.Next() {
		var user string
		var r userstatRawRow
		if err := rows.Scan(&user, &r.CPUSec, &r.BusySec, &r.RowsRead, &r.RowsSent); err != nil {
			continue
		}
		out[user] = r
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// PerfDeltas returns a snapshot of the most recently computed CPU/query deltas.
// Safe for concurrent reads (used by the API).
func (g *Governor) PerfDeltas() []UserPerfDelta {
	g.perfDeltaMu.RLock()
	defer g.perfDeltaMu.RUnlock()
	out := make([]UserPerfDelta, len(g.perfDeltas))
	copy(out, g.perfDeltas)
	return out
}
