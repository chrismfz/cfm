package mysql

import (
    "net/http"
    "encoding/json"
    "time"
)

// RegisterHTTP registers all mysql governor API routes onto an existing mux.
// Call this from main.go's startDebug mux — no new port needed.
func (g *Governor) RegisterHTTP(mux *http.ServeMux) {
    mux.HandleFunc("/api/v1/mysql/state",       g.handleState)
    mux.HandleFunc("/api/v1/mysql/processlist", g.handleProcesslist)
    mux.HandleFunc("/api/v1/mysql/top",         g.handleTop)
    mux.HandleFunc("/api/v1/mysql/locks",       g.handleLocks)
    mux.HandleFunc("/api/v1/mysql/kills",       g.handleKills)
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
        "mode":     g.cfg.Mode,
    })
}

func (g *Governor) handleLocks(w http.ResponseWriter, r *http.Request) {
    s := g.State()
    writeGovernorJSON(w, http.StatusOK, map[string]any{
        "ts":         s.Ts,
        "lock_graph": s.LockGraph,
        "locked_conn": s.LockedConn,
    })
}

func (g *Governor) handleKills(w http.ResponseWriter, r *http.Request) {
    s := g.State()
    writeGovernorJSON(w, http.StatusOK, map[string]any{
        "ts":    s.Ts,
        "kills": s.RecentKills,
        "mode":  g.cfg.Mode,
    })
}

func writeGovernorJSON(w http.ResponseWriter, code int, v any) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("X-Source", "cfm-mysql-governor")
    w.WriteHeader(code)
    _ = json.NewEncoder(w).Encode(v)
}

// GovernorTopResponse is what cfm mysqltop reads.
type GovernorTopResponse struct {
    Ts      time.Time   `json:"ts"`
    Flavor  string      `json:"flavor"`
    ConnPct float64     `json:"conn_pct"`
    Total   int         `json:"total"`
    Max     int         `json:"max"`
    Mode    string      `json:"mode"`
    PerUser []UserStat  `json:"per_user"`
}
