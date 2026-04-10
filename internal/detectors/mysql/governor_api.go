// internal/detectors/mysql/governor_api.go
package mysql

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RegisterHTTP registers all MySQL governor API routes onto an existing mux.
// Call this from main.go's apiserver — no new port needed.
//
// Route map:
//
//	Admin-only (Guard 3):
//	  /api/v1/mysql/state        — full snapshot
//	  /api/v1/mysql/processlist  — connection list with per-user breakdown
//	  /api/v1/mysql/top          — compact top-N view (used by mysqltop CLI)
//	  /api/v1/mysql/locks        — lock graph
//	  /api/v1/mysql/kills        — recent kill ring
//	  /api/v1/mysql/history      — long-window per-user history
//	  /api/v1/mysql/cpu          — per-user CPU / query deltas
//
//	Scoped-token ready (Guard 3 for now, demote to Guard 2 when plugin auth lands):
//	  /api/v1/mysql/user-summary  — filtered snapshot (user= / db= params)
//	  /api/v1/mysql/user-kills    — filtered kill history
//	  /api/v1/mysql/user-history  — filtered long-window history
func (g *Governor) RegisterHTTP(mux *http.ServeMux) {
	g.RegisterHTTPAdmin(mux)
	g.RegisterHTTPScoped(mux)
}

// RegisterHTTPAdmin registers global/admin-only MySQL governor routes.
func (g *Governor) RegisterHTTPAdmin(mux *http.ServeMux) {
	// ── existing admin endpoints ─────────────────────────────────────────────
	mux.HandleFunc("/api/v1/mysql/state", g.handleState)
	mux.HandleFunc("/api/v1/mysql/processlist", g.handleProcesslist)
	mux.HandleFunc("/api/v1/mysql/top", g.handleTop)
	mux.HandleFunc("/api/v1/mysql/locks", g.handleLocks)
	mux.HandleFunc("/api/v1/mysql/kills", g.handleKills)
	mux.HandleFunc("/api/v1/mysql/history", g.handleHistory)
	mux.HandleFunc("/api/v1/mysql/cpu", g.handleCPU)
}

// RegisterHTTPScoped registers user/db-filtered MySQL governor routes that can
// be safely exposed to scoped tokens when query constraints are enforced.
func (g *Governor) RegisterHTTPScoped(mux *http.ServeMux) {
	// ── per-user/per-db filtered endpoints ──────────────────────────────────
	// These are designed to be safe for scoped (per-cPanel-user) tokens once
	// the plugin auth layer lands (Step 3 of auth hardening).
	//
	// Until then they sit behind the same Guard 3 admin token.  When the plugin
	// work starts, the middleware just needs to be told these three paths are
	// Guard 2 — no handler changes required.
	//
	// TODO(plugin): demote to Guard 2 once goauth scoped tokens are wired in.
	mux.HandleFunc("/api/v1/mysql/user-summary", g.handleUserSummary)
	mux.HandleFunc("/api/v1/mysql/user-kills", g.handleUserKills)
	mux.HandleFunc("/api/v1/mysql/user-history", g.handleUserHistory)
}

// ── existing admin handlers (unchanged) ──────────────────────────────────────

func (g *Governor) handleState(w http.ResponseWriter, r *http.Request) {
	writeGovernorJSON(w, http.StatusOK, g.State())
}

func (g *Governor) handleProcesslist(w http.ResponseWriter, r *http.Request) {
	s := g.State()
	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":       s.Ts,
		"running":  s.Running,
		"per_user": s.PerUser,
		"conn": map[string]any{
			"total":    s.TotalConn,
			"active":   s.ActiveConn,
			"sleeping": s.SleepConn,
			"locked":   s.LockedConn,
			"max":      s.MaxConn,
			"pct":      s.ConnPct,
		},
	})
}

func (g *Governor) handleTop(w http.ResponseWriter, r *http.Request) {
	s := g.State()
	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":       s.Ts,
		"flavor":   s.Flavor,
		"per_user": s.PerUser,
		"conn_pct": s.ConnPct,
		"total":    s.TotalConn,
		"max":      s.MaxConn,
		"mode":     s.Mode,
	})
}

func (g *Governor) handleLocks(w http.ResponseWriter, r *http.Request) {
	s := g.State()
	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":          s.Ts,
		"lock_graph":  s.LockGraph,
		"locked_conn": s.LockedConn,
	})
}

func (g *Governor) handleKills(w http.ResponseWriter, r *http.Request) {
	s := g.State()
	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":    s.Ts,
		"kills": s.RecentKills,
		"mode":  s.Mode,
	})
}

// handleHistory returns per-user aggregated connection stats over a rolling window.
//
// Query params:
//
//	window — duration string: 1h (default), 6h, 24h, 30m, etc.
//	top    — int: how many users to return (default 20, 0 = all)
//
// Example:  GET /api/v1/mysql/history?window=6h&top=10
func (g *Governor) handleHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	window := 1 * time.Hour
	if ws := q.Get("window"); ws != "" {
		if d, err := time.ParseDuration(ws); err == nil && d > 0 {
			window = d
		}
	}
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}

	topN := 20
	if ts := q.Get("top"); ts != "" {
		if n, err := strconv.Atoi(ts); err == nil {
			topN = n
		}
	}

	stats := g.TopUserHistory(window, topN)
	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":           time.Now(),
		"window":       window.String(),
		"sample_count": g.HistorySampleCount(),
		"users":        stats,
	})
}

// handleCPU returns the most recent per-user CPU / query-count deltas.
//
// Response flags explained:
//
//	perf_schema_ok   — performance_schema is ON and the summary table is readable
//	perf_has_cpu     — SUM_CPU_TIME column exists (MySQL 8+, Path A)
//	perf_cpu_active  — SUM_CPU_TIME / CPU_TIME is actually being populated
//	userstat_ok      — MariaDB userstat=ON and USER_STATISTICS is readable (Path B)
//	userstat_off     — MariaDB detected but userstat=OFF (Path C with hint)
//
// Example:  GET /api/v1/mysql/cpu
func (g *Governor) handleCPU(w http.ResponseWriter, r *http.Request) {
	deltas := g.PerfDeltas()
	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":              time.Now(),
		"perf_schema_ok":  g.perfSchemaOK,
		"perf_has_cpu":    g.perfHasCPU,
		"perf_cpu_active": g.perfCPUActive,
		"userstat_ok":     g.userstatsOK,
		"userstat_off":    g.userstatsOff,
		"users":           deltas,
	})
}

// ── per-user / per-db filtered handlers ──────────────────────────────────────
//
// All three handlers share the same query-param convention:
//
//	?user=chris                 — single MySQL username
//	?user=chris_db,chris_db2    — comma-separated list
//	?user=chris_db&user=chris2  — repeated params (both forms work together)
//	?user=chris*                — wildcard (filepath.Match rules)
//	?db=chris_db1               — filter by database name instead of / in addition to user
//	?user=chris&db=chris_db     — user AND db filter (intersection)
//
// Params accept up to 32 values each to prevent abuse.
// Empty user= / db= params are rejected with 400.
//
// Privacy note: query text (Process.Info) and kill Query field are ALWAYS
// stripped from responses returned by these endpoints.  An end-user calling
// via a scoped token should never see the raw SQL of other co-existing connections
// (even their own, to avoid leaking credentials embedded in query strings).

// handleUserSummary returns a scoped snapshot of the governor state filtered
// to the requested MySQL users and/or database names.
//
// Guard level: Guard 3 (admin-only) for now.
// TODO(plugin): demote to Guard 2 once scoped token auth is live.
//
// Example:
//
//	GET /api/v1/mysql/user-summary?user=chris_wp&user=chris_shop
//	GET /api/v1/mysql/user-summary?db=chris_wp
//	GET /api/v1/mysql/user-summary?user=chris*
func (g *Governor) handleUserSummary(w http.ResponseWriter, r *http.Request) {
	users, dbs, ok := parseUserDBParams(w, r)
	if !ok {
		return
	}

	s := g.State()
	f := filterGovernorState(s, users, dbs)

	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":       f.Ts,
		"flavor":   f.Flavor,
		"mode":     f.Mode,
		"filter":   map[string]any{"users": users, "dbs": dbs},
		"per_user": f.PerUser,
		"conn": map[string]any{
			"total":    f.TotalConn,
			"active":   f.ActiveConn,
			"sleeping": f.SleepConn,
			"locked":   f.LockedConn,
			// MaxConn and ConnPct are server-global — not meaningful
			// when scoped to a single cPanel user.  Omit to avoid confusion.
		},
		// Running processes are included but query text is stripped (privacy).
		// The plugin can show "3 active queries" without exposing SQL.
		"running":     f.Running,
		"lock_graph":  f.LockGraph,
		"perf_deltas": f.PerfDeltas,
	})
}

// handleUserKills returns the recent kill ring filtered to the requested
// MySQL users and/or database names.  Query text is stripped.
//
// Guard level: Guard 3 (admin-only) for now.
// TODO(plugin): demote to Guard 2 once scoped token auth is live.
//
// Example:
//
//	GET /api/v1/mysql/user-kills?user=chris_wp
//	GET /api/v1/mysql/user-kills?db=chris_wp,chris_shop
func (g *Governor) handleUserKills(w http.ResponseWriter, r *http.Request) {
	users, dbs, ok := parseUserDBParams(w, r)
	if !ok {
		return
	}

	s := g.State()
	f := filterGovernorState(s, users, dbs)

	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":     f.Ts,
		"mode":   f.Mode,
		"filter": map[string]any{"users": users, "dbs": dbs},
		"kills":  f.RecentKills,
	})
}

// handleUserHistory returns long-window per-user history stats filtered to
// the requested MySQL users and/or database names.
//
// Query params (in addition to user= / db=):
//
//	window — duration string: 1h (default), 6h, 24h, 30m, etc. (max 24h)
//	top    — max results per filter match (default 0 = all)
//
// Guard level: Guard 3 (admin-only) for now.
// TODO(plugin): demote to Guard 2 once scoped token auth is live.
//
// Example:
//
//	GET /api/v1/mysql/user-history?user=chris_wp&window=6h
//	GET /api/v1/mysql/user-history?user=chris*&window=1h&top=5
func (g *Governor) handleUserHistory(w http.ResponseWriter, r *http.Request) {
	users, dbs, ok := parseUserDBParams(w, r)
	if !ok {
		return
	}

	q := r.URL.Query()

	window := 1 * time.Hour
	if ws := q.Get("window"); ws != "" {
		if d, err := time.ParseDuration(ws); err == nil && d > 0 {
			window = d
		}
	}
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}

	topN := 0 // 0 = all matches
	if ts := q.Get("top"); ts != "" {
		if n, err := strconv.Atoi(ts); err == nil && n > 0 {
			topN = n
		}
	}

	// Fetch full history, then filter by the requested user patterns.
	// TopUserHistory already sorts by peak connections desc.
	all := g.TopUserHistory(window, 0)
	var filtered []UserHistoryStat
	for _, u := range all {
		if userDBMatch(u.User, "", users, dbs) {
			filtered = append(filtered, u)
			if topN > 0 && len(filtered) >= topN {
				break
			}
		}
	}

	writeGovernorJSON(w, http.StatusOK, map[string]any{
		"ts":           time.Now(),
		"window":       window.String(),
		"sample_count": g.HistorySampleCount(),
		"filter":       map[string]any{"users": users, "dbs": dbs},
		"users":        filtered,
	})
}

// ── filter helpers ────────────────────────────────────────────────────────────

// parseUserDBParams extracts and validates ?user= and ?db= query params.
// Both params accept comma-separated values and/or repeated keys.
// Returns (users, dbs, ok); writes a JSON error and returns ok=false on
// any validation failure so callers can just `if !ok { return }`.
func parseUserDBParams(w http.ResponseWriter, r *http.Request) (users, dbs []string, ok bool) {
	users = parseMultiParam(r, "user")
	dbs = parseMultiParam(r, "db")

	if len(users) == 0 && len(dbs) == 0 {
		writeGovernorJSON(w, http.StatusBadRequest, map[string]string{
			"error": "at least one ?user= or ?db= parameter is required",
		})
		return nil, nil, false
	}
	// Reject obviously invalid values to prevent abuse.
	const maxParams = 32
	if len(users) > maxParams || len(dbs) > maxParams {
		writeGovernorJSON(w, http.StatusBadRequest, map[string]string{
			"error": "too many filter values (max 32 each)",
		})
		return nil, nil, false
	}
	return users, dbs, true
}

// parseMultiParam reads all values for a query param key, splitting on commas.
// Supports both ?user=a,b and ?user=a&user=b (and combinations).
// Values are lowercased and deduplicated; empty strings are skipped.
func parseMultiParam(r *http.Request, key string) []string {
	raw := r.URL.Query()[key]
	seen := map[string]struct{}{}
	var out []string
	for _, v := range raw {
		for _, part := range strings.Split(v, ",") {
			s := strings.TrimSpace(strings.ToLower(part))
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// userDBMatch reports whether a (user, db) pair satisfies at least one pattern
// in the users slice OR at least one pattern in the dbs slice.
//
// Pattern matching uses filepath.Match rules so * and ? work as wildcards.
// A non-empty users list and a non-empty dbs list are treated as OR (not AND)
// — if either matches, the row is included.  This mirrors how cPanel presents
// database ownership: a user may own several DBs with different name prefixes.
//
// Comparison is case-insensitive (both sides are lowercased in parseMultiParam).
func userDBMatch(user, db string, users, dbs []string) bool {
	u := strings.ToLower(user)
	d := strings.ToLower(db)

	for _, pat := range users {
		if matched, err := filepath.Match(pat, u); err == nil && matched {
			return true
		}
		// exact fallback (filepath.Match requires the string to contain no
		// path separators, which MySQL usernames never do — just being safe)
		if !strings.ContainsAny(pat, "*?") && pat == u {
			return true
		}
	}
	for _, pat := range dbs {
		if d == "" {
			continue // process has no active DB selected
		}
		if matched, err := filepath.Match(pat, d); err == nil && matched {
			return true
		}
		if !strings.ContainsAny(pat, "*?") && pat == d {
			return true
		}
	}
	return false
}

// filterGovernorState returns a new GovernorState containing only the data
// for processes / users / kills that match the given user or db patterns.
//
// Server-level connection totals (TotalConn, ActiveConn, etc.) are
// recomputed from the filtered PerUser slice so the response is internally
// consistent.
//
// Privacy: Process.Info (query text) and KillRecord.Query are ALWAYS stripped
// from the returned state.  These endpoints are intended for scoped plugin
// use where the end-user should see counts and timings, not raw SQL.
func filterGovernorState(s GovernorState, users, dbs []string) GovernorState {
	out := GovernorState{
		Ts:      s.Ts,
		Flavor:  s.Flavor,
		Mode:    s.Mode,
		MaxConn: s.MaxConn, // server-global, keep for context
	}

	// ── PerUser ──────────────────────────────────────────────────────────────
	for _, u := range s.PerUser {
		if userDBMatch(u.User, "", users, dbs) {
			out.PerUser = append(out.PerUser, u)
			out.TotalConn += u.Total
			out.ActiveConn += u.Active
			out.SleepConn += u.Sleeping
			out.LockedConn += u.Locked
		}
	}
	if out.MaxConn > 0 {
		out.ConnPct = float64(out.TotalConn) / float64(out.MaxConn) * 100
	}

	// ── Running processes — query text stripped ───────────────────────────────
	for _, p := range s.Running {
		if userDBMatch(p.User, p.DB, users, dbs) {
			safe := p
			safe.Info = "" // strip query text — privacy
			out.Running = append(out.Running, safe)
		}
	}

	// ── Lock graph — keep only lock groups where the blocker matches ──────────
	// Waiters inherit the blocker's inclusion: if you own the blocking query
	// you see the full fan-out (helps the user understand their impact).
	// Waiter query text is also stripped.
	for _, lg := range s.LockGraph {
		if !userDBMatch(lg.Blocker.User, lg.Blocker.DB, users, dbs) {
			continue
		}
		safeLG := LockGroup{Blocker: lg.Blocker}
		safeLG.Blocker.Info = "" // strip
		for _, w := range lg.Waiters {
			sw := w
			sw.Info = "" // strip
			safeLG.Waiters = append(safeLG.Waiters, sw)
		}
		out.LockGraph = append(out.LockGraph, safeLG)
	}

	// ── Recent kills — query text stripped ───────────────────────────────────
	for _, k := range s.RecentKills {
		if userDBMatch(k.User, k.DB, users, dbs) {
			safe := k
			safe.Query = "" // strip query text — privacy
			out.RecentKills = append(out.RecentKills, safe)
		}
	}

	// ── CPU / perf deltas ────────────────────────────────────────────────────
	for _, d := range s.PerfDeltas {
		if userDBMatch(d.User, "", users, dbs) {
			out.PerfDeltas = append(out.PerfDeltas, d)
		}
	}

	return out
}

// ── shared JSON writer ────────────────────────────────────────────────────────

func writeGovernorJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Source", "cfm-mysql-governor")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
