// internal/detectors/mysql/governor_api.go
package mysql

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// RegisterHTTP registers all mysql governor API routes onto an existing mux.
// Call this from main.go's startDebug mux — no new port needed.
func (g *Governor) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/mysql/state", g.handleState)
	mux.HandleFunc("/api/v1/mysql/processlist", g.handleProcesslist)
	mux.HandleFunc("/api/v1/mysql/top", g.handleTop)
	mux.HandleFunc("/api/v1/mysql/locks", g.handleLocks)
	mux.HandleFunc("/api/v1/mysql/kills", g.handleKills)
	mux.HandleFunc("/api/v1/mysql/history", g.handleHistory)
	mux.HandleFunc("/api/v1/mysql/history/events", g.handleHistoryEvents)
	mux.HandleFunc("/api/v1/mysql/history/summary", g.handleHistorySummary)
	mux.HandleFunc("/api/v1/mysql/history/prune", g.handleHistoryPrune)
	mux.HandleFunc("/api/v1/mysql/history/truncate", g.handleHistoryTruncate)
	mux.HandleFunc("/api/v1/mysql/cpu", g.handleCPU)
}

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

func (g *Governor) handleHistoryEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			limit = n
		}
	}
	rows, err := g.QueryHistoryEvents(q.Get("user"), q.Get("db"), q.Get("type"), limit)
	if err != nil {
		writeGovernorJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeGovernorJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

func (g *Governor) handleHistorySummary(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if s := r.URL.Query().Get("hours"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			hours = n
		}
	}
	res, err := g.SummarizeHistory(hours)
	if err != nil {
		writeGovernorJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeGovernorJSON(w, http.StatusOK, res)
}

func (g *Governor) handleHistoryPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeGovernorJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	days := 30
	if s := r.URL.Query().Get("days"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			days = n
		}
	}
	n, err := g.PruneHistory(days)
	if err != nil {
		writeGovernorJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeGovernorJSON(w, http.StatusOK, map[string]any{"rows_deleted": n, "days": days})
}

func (g *Governor) handleHistoryTruncate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeGovernorJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if r.URL.Query().Get("confirm") != "yes" {
		writeGovernorJSON(w, http.StatusBadRequest, map[string]string{"error": "missing confirm=yes"})
		return
	}
	n, err := g.TruncateHistory()
	if err != nil {
		writeGovernorJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeGovernorJSON(w, http.StatusOK, map[string]int64{"rows_deleted": n})
}

func writeGovernorJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Source", "cfm-mysql-governor")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
