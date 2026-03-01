package mysql

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strconv"
    "strings"
    "text/tabwriter"
    "time"
)

// RunMySQLTop is the CLI entrypoint for `cfm mysqltop`.
// baseURL matches the debug server: "http://127.0.0.1:6060"
func RunMySQLTop(baseURL string, args []string) error {
    if len(args) == 0 {
        return runMySQLTopDefault(baseURL)
    }

    switch args[0] {
    case "top":
        n := 20
        if len(args) > 1 {
            if v, err := strconv.Atoi(args[1]); err == nil && v > 0 { n = v }
        }
        return runMySQLTopUsers(baseURL, n)
    case "locks":
        return runMySQLTopLocks(baseURL)
    case "kills":
        return runMySQLTopKills(baseURL)
    case "ps", "processlist":
        return runMySQLProcesslist(baseURL)
    case "help", "-h", "--help":
        printMySQLTopHelp()
        return nil
    }
    return fmt.Errorf("unknown subcommand: %s", args[0])
}

func printMySQLTopHelp() {
    fmt.Println("Usage:")
    fmt.Println("  cfm mysqltop                  # full summary")
    fmt.Println("  cfm mysqltop top [N]          # top N users by connections")
    fmt.Println("  cfm mysqltop locks            # lock graph (blockers + waiters)")
    fmt.Println("  cfm mysqltop kills            # recent governor kills")
    fmt.Println("  cfm mysqltop ps               # full processlist (running + waiting)")
}

func runMySQLTopDefault(baseURL string) error {
    var state GovernorState
    if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/state", &state); err != nil {
        return err
    }

    riskIcon := func(pct float64) string {
        if pct >= 85 { return "🔴" }
        if pct >= 70 { return "🟡" }
        return "🟢"
    }

    fmt.Printf("[mysqltop] %s  %s  flavor=%s  mode=%s\n",
        state.Ts.Format("15:04:05"), state.Flavor, state.Flavor, "")
    fmt.Printf("\nCONNECTIONS: %d/%d (%.0f%%) %s   Active=%d  Sleep=%d  Locked=%d\n",
        state.TotalConn, state.MaxConn, state.ConnPct,
        riskIcon(state.ConnPct),
        state.ActiveConn, state.SleepConn, state.LockedConn)

    if len(state.PerUser) > 0 {
        fmt.Println()
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        fmt.Fprintln(w, "USER\tCONNS\tACTIVE\tSLEEP\tLOCKED\tMAX_IDLE\tRISK")
        for _, u := range state.PerUser {
            risk := "🟢"
            if u.Locked > 0 { risk = "🔴" }
            if u.MaxSleepSec > 300 { risk = "🟡" }
            fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%s\t%s\n",
                u.User, u.Total, u.Active, u.Sleeping, u.Locked,
                formatAge(u.MaxSleepSec), risk)
        }
        w.Flush()
    }

    if len(state.LockGraph) > 0 {
        fmt.Printf("\nLOCK GRAPH (%d blockers)\n", len(state.LockGraph))
        for _, lg := range state.LockGraph {
            fmt.Printf("  ⚡ BLOCKER #%d %s  db=%s  %ds  state=%s\n",
                lg.Blocker.ID, lg.Blocker.User, lg.Blocker.DB,
                lg.Blocker.TimeSec, lg.Blocker.State)
            fmt.Printf("     Query: %s\n", truncate(lg.Blocker.Info, 120))
            fmt.Printf("     └─ %d waiters\n", len(lg.Waiters))
        }
    }

    if len(state.Running) > 0 {
        fmt.Printf("\nRUNNING QUERIES (top 10)\n")
        w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
        fmt.Fprintln(w, "PID\tUSER\tDB\tTIME\tSTATE\tQUERY")
        shown := state.Running
        if len(shown) > 10 { shown = shown[:10] }
        for _, p := range shown {
            lock := ""
            if isLockState(p.State) { lock = " 🔒" }
            fmt.Fprintf(w, "%d\t%s\t%s\t%ds\t%s%s\t%s\n",
                p.ID, p.User, p.DB, p.TimeSec, p.State, lock,
                truncate(p.Info, 80))
        }
        w.Flush()
    }

    if len(state.RecentKills) > 0 {
        fmt.Printf("\nGOVERNOR ACTIONS (last %d)\n", len(state.RecentKills))
        for _, k := range state.RecentKills {
            fmt.Printf("  %s  %s  pid=%d user=%s db=%s runtime=%s  %s\n",
                k.Ts.Format("15:04:05"), k.Action,
                k.PID, k.User, k.DB,
                k.Runtime.Round(time.Second), k.Reason)
        }
    }

    return nil
}

func runMySQLTopUsers(baseURL string, n int) error {
    type topResp struct {
        Ts      time.Time  `json:"ts"`
        Flavor  string     `json:"flavor"`
        ConnPct float64    `json:"conn_pct"`
        Total   int        `json:"total"`
        Max     int        `json:"max"`
        Mode    string     `json:"mode"`
        PerUser []UserStat `json:"per_user"`
    }
    var r topResp
    if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/top", &r); err != nil {
        return err
    }

    fmt.Printf("[mysqltop top] %s  %d/%d (%.0f%%)  mode=%s\n",
        r.Ts.Format("15:04:05"), r.Total, r.Max, r.ConnPct, r.Mode)

    rows := r.PerUser
    if len(rows) > n { rows = rows[:n] }

    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "USER\tCONNS\tACTIVE\tSLEEP\tLOCKED\tMAX_IDLE\tRISK")
    for _, u := range rows {
        risk := "🟢 OK"
        if u.Locked > 0 { risk = "🔴 LOCKED" }
        if u.MaxSleepSec > 300 { risk = "🟡 STALE" }
        fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%s\t%s\n",
            u.User, u.Total, u.Active, u.Sleeping, u.Locked,
            formatAge(u.MaxSleepSec), risk)
    }
    w.Flush()
    return nil
}

func runMySQLTopLocks(baseURL string) error {
    type locksResp struct {
        Ts         time.Time   `json:"ts"`
        LockGraph  []LockGroup `json:"lock_graph"`
        LockedConn int         `json:"locked_conn"`
    }
    var r locksResp
    if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/locks", &r); err != nil {
        return err
    }
    if len(r.LockGraph) == 0 {
        fmt.Printf("[mysqltop locks] %s  no locks\n", r.Ts.Format("15:04:05"))
        return nil
    }
    fmt.Printf("[mysqltop locks] %s  %d blockers  %d locked connections\n",
        r.Ts.Format("15:04:05"), len(r.LockGraph), r.LockedConn)
    for _, lg := range r.LockGraph {
        fmt.Printf("\n  ⚡ BLOCKER pid=%d user=%s db=%s time=%ds\n",
            lg.Blocker.ID, lg.Blocker.User, lg.Blocker.DB, lg.Blocker.TimeSec)
        fmt.Printf("     State: %s\n", lg.Blocker.State)
        fmt.Printf("     Query: %s\n", truncate(lg.Blocker.Info, 150))
        fmt.Printf("     Waiters: %d\n", len(lg.Waiters))
        for i, w := range lg.Waiters {
            if i > 5 { fmt.Printf("       ... +%d more\n", len(lg.Waiters)-5); break }
            fmt.Printf("       🔒 pid=%d %s %ds %s\n", w.ID, w.User, w.TimeSec, truncate(w.Info, 60))
        }
    }
    return nil
}

func runMySQLTopKills(baseURL string) error {
    type killsResp struct {
        Ts    time.Time    `json:"ts"`
        Mode  string       `json:"mode"`
        Kills []KillRecord `json:"kills"`
    }
    var r killsResp
    if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/kills", &r); err != nil {
        return err
    }
    fmt.Printf("[mysqltop kills] %s  mode=%s\n", r.Ts.Format("15:04:05"), r.Mode)
    if len(r.Kills) == 0 {
        fmt.Println("  (no kills recorded)")
        return nil
    }
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "TIME\tACTION\tPID\tUSER\tDB\tRUNTIME\tUNBLOCKED\tRESULT\tREASON")
    for _, k := range r.Kills {
        fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\n",
            k.Ts.Format("15:04:05"), k.Action,
            k.PID, k.User, k.DB,
            k.Runtime.Round(time.Second),
            k.Unblocked, k.Result,
            truncate(k.Reason, 60))
    }
    w.Flush()
    return nil
}

func runMySQLProcesslist(baseURL string) error {
    var r map[string]any
    if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/processlist", &r); err != nil {
        return err
    }
    b, _ := json.MarshalIndent(r, "", "  ")
    fmt.Println(string(b))
    return nil
}

func fetchGovernorJSON(baseURL, path string, out any) error {
    url := strings.TrimRight(baseURL, "/") + path
    resp, err := http.Get(url)
    if err != nil {
        return fmt.Errorf("mysqltop: cannot reach %s: %w\n(is cfm daemon running?)", url, err)
    }
    defer resp.Body.Close()
    return json.NewDecoder(resp.Body).Decode(out)
}

func formatAge(secs int64) string {
    if secs == 0 { return "-" }
    d := time.Duration(secs) * time.Second
    if d < time.Minute { return fmt.Sprintf("%ds", secs) }
    if d < time.Hour   { return fmt.Sprintf("%.0fm", d.Minutes()) }
    return fmt.Sprintf("%.1fh", d.Hours())
}
