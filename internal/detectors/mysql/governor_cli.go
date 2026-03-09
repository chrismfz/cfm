// internal/detectors/mysql/governor_cli.go
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
	"golang.org/x/term"
)

// RunMySQLTop is the CLI entrypoint for `cfm mysqltop`.
// baseURL matches the debug server: "http://127.0.0.1:6060"
func RunMySQLTop(baseURL string, args []string) error {
	if len(args) == 0 {
		if !isTTY() {
			return runMySQLTopDefault(baseURL)
		}
		return runMySQLLive(baseURL)
	}

	switch args[0] {
	case "text":
		return runMySQLTopDefault(baseURL)
	case "live":
		if !isTTY() {
			return runMySQLTopDefault(baseURL)
		}
		return runMySQLLive(baseURL)
	case "top":
		n := 20
		if len(args) > 1 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				n = v
			}
		}
		return runMySQLTopUsers(baseURL, n)
	case "locks":
		return runMySQLTopLocks(baseURL)
	case "kills":
		return runMySQLTopKills(baseURL)
	case "ps", "processlist":
		return runMySQLProcesslist(baseURL)
	case "history":
		// cfm mysqltop history [window] [topN]
		// window: 1h (default), 30m, 6h, 24h
		// topN:   20 (default)
		window := "1h"
		topN := 20
		if len(args) > 1 {
			window = args[1]
		}
		if len(args) > 2 {
			if n, err := strconv.Atoi(args[2]); err == nil && n > 0 {
				topN = n
			}
		}
		return runMySQLHistory(baseURL, window, topN)
	case "cpu":
		return runMySQLCPU(baseURL)
	case "help", "-h", "--help":
		printMySQLTopHelp()
		return nil
	}
	return fmt.Errorf("unknown subcommand: %s", args[0])
}


func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// runMySQLLive starts the termui live dashboard.
func runMySQLLive(baseURL string) error {
	return mysqlLiveUI(baseURL)
}


func printMySQLTopHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm mysqltop                        # live UI (falls back to text if not a TTY)")
	fmt.Println("  cfm mysqltop text                   # full summary (text)")
	fmt.Println("  cfm mysqltop live                   # force live UI")
	fmt.Println("  cfm mysqltop top [N]                # top N users by connections (live)")
	fmt.Println("  cfm mysqltop locks                  # lock graph (blockers + waiters)")
	fmt.Println("  cfm mysqltop kills                  # recent governor kills")
	fmt.Println("  cfm mysqltop ps                     # full processlist (running + waiting)")
	fmt.Println("  cfm mysqltop history [window] [N]   # busiest N users over window (e.g. 1h, 6h, 24h)")
	fmt.Println("  cfm mysqltop cpu                    # per-user CPU + query stats")
	fmt.Println("                                      #   MySQL 8+: uses performance_schema SUM_CPU_TIME")
	fmt.Println("                                      #   MariaDB:  uses information_schema.USER_STATISTICS (userstat=ON)")
	fmt.Println("                                      #   Shows how to enable CPU tracking if not yet active")
}

func runMySQLTopDefault(baseURL string) error {
	var state GovernorState
	if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/state", &state); err != nil {
		return err
	}

	riskIcon := func(pct float64) string {
		if pct >= 85 {
			return "🔴"
		}
		if pct >= 70 {
			return "🟡"
		}
		return "🟢"
	}

	fmt.Printf("[mysqltop] %s  flavor=%s  mode=%s\n",
		state.Ts.Format("15:04:05"), state.Flavor, state.Mode)
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
			if u.Locked > 0 {
				risk = "🔴"
			}
			if u.MaxSleepSec > 300 {
				risk = "🟡"
			}
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
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, p := range shown {
			lock := ""
			if isLockState(p.State) {
				lock = " 🔒"
			}
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
	if len(rows) > n {
		rows = rows[:n]
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tCONNS\tACTIVE\tSLEEP\tLOCKED\tMAX_IDLE\tRISK")
	for _, u := range rows {
		risk := "🟢 OK"
		if u.Locked > 0 {
			risk = "🔴 LOCKED"
		}
		if u.MaxSleepSec > 300 {
			risk = "🟡 STALE"
		}
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
			if i > 5 {
				fmt.Printf("       ... +%d more\n", len(lg.Waiters)-5)
				break
			}
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

// runMySQLHistory shows the busiest users over a historical window.
//
//	cfm mysqltop history [window] [N]
//	cfm mysqltop history 6h 10
func runMySQLHistory(baseURL, window string, topN int) error {
	type histResp struct {
		Ts          time.Time         `json:"ts"`
		Window      string            `json:"window"`
		SampleCount int               `json:"sample_count"`
		Users       []UserHistoryStat `json:"users"`
	}
	var r histResp
	path := fmt.Sprintf("/api/v1/mysql/history?window=%s&top=%d", window, topN)
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}

	if len(r.Users) == 0 {
		fmt.Printf("[mysqltop history] %s  window=%s  no data yet (%d samples)\n",
			r.Ts.Format("15:04:05"), r.Window, r.SampleCount)
		return nil
	}

	fmt.Printf("[mysqltop history] %s  window=%s  samples=%d\n",
		r.Ts.Format("15:04:05"), r.Window, r.SampleCount)
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tPEAK_CONNS\tAVG_CONNS\tPEAK_ACTIVE\tAVG_ACTIVE\tPEAK_LOCKED\tSAMPLES")
	for _, u := range r.Users {
		lockedFlag := ""
		if u.PeakLocked > 0 {
			lockedFlag = " 🔒"
		}
		fmt.Fprintf(w, "%s\t%d\t%.1f\t%d\t%.1f\t%d%s\t%d\n",
			u.User,
			u.PeakConns, u.AvgConns,
			u.PeakActive, u.AvgActive,
			u.PeakLocked, lockedFlag,
			u.Samples)
	}
	w.Flush()
	return nil
}

// runMySQLCPU shows per-user CPU and query stats from performance_schema.
//
//	cfm mysqltop cpu
func runMySQLCPU(baseURL string) error {
	type cpuResp struct {
		Ts            time.Time       `json:"ts"`
		PerfSchemaOK  bool            `json:"perf_schema_ok"`
		PerfHasCPU    bool            `json:"perf_has_cpu"`
		PerfCPUActive bool            `json:"perf_cpu_active"`
		UserstatOK    bool            `json:"userstat_ok"`
		UserstatOff   bool            `json:"userstat_off"`
		Users         []UserPerfDelta `json:"users"`
	}
	var r cpuResp
	if err := fetchGovernorJSON(baseURL, "/api/v1/mysql/cpu", &r); err != nil {
		return err
	}

	ts := r.Ts.Format("15:04:05")

	// ---- Path: performance_schema completely unavailable ------------------
	if !r.PerfSchemaOK {
		fmt.Printf("[mysqltop cpu] %s  performance_schema is disabled on this server\n\n", ts)
		fmt.Println("  To enable it, add to /etc/my.cnf (or /etc/mysql/my.cnf) and restart MySQL/MariaDB:")
		fmt.Println()
		fmt.Println("    [mysqld]")
		fmt.Println("    performance_schema = ON")
		return nil
	}

	// ---- Path A: MySQL 8+, instruments disabled ---------------------------
	if r.PerfHasCPU && !r.PerfCPUActive {
		fmt.Printf("[mysqltop cpu] %s  query tracking only  (SUM_CPU_TIME present but instruments are OFF)\n\n", ts)
		fmt.Println("  To enable CPU tracking on MySQL 8, run once as root:")
		fmt.Println()
		fmt.Println("    UPDATE performance_schema.setup_instruments")
		fmt.Println("      SET ENABLED='YES', TIMED='YES'")
		fmt.Println("      WHERE NAME LIKE 'statement/%';")
		fmt.Println()
		fmt.Println("    UPDATE performance_schema.setup_consumers")
		fmt.Println("      SET ENABLED='YES'")
		fmt.Println("      WHERE NAME LIKE 'events_statements%';")
		fmt.Println()
		fmt.Println("  These changes take effect immediately and survive until MySQL restarts.")
		fmt.Println("  To make them permanent across restarts, add to /etc/my.cnf:")
		fmt.Println()
		fmt.Println("    performance-schema-instrument='statement/%=ON'")
		fmt.Println("    performance-schema-consumer-events-statements-history=ON")
		fmt.Println()
	}

	// ---- Path C: MariaDB, userstat=OFF ------------------------------------
	if r.UserstatOff {
		fmt.Printf("[mysqltop cpu] %s  query tracking only  (MariaDB detected, userstat is OFF)\n\n", ts)
		fmt.Println("  To enable real CPU time tracking on MariaDB, run once as root:")
		fmt.Println()
		fmt.Println("    SET GLOBAL userstat = ON;")
		fmt.Println()
		fmt.Println("  This takes effect immediately — no restart needed.")
		fmt.Println("  To make it permanent across restarts, add to /etc/my.cnf:")
		fmt.Println()
		fmt.Println("    [mysqld]")
		fmt.Println("    userstat = ON")
		fmt.Println()
		fmt.Println("  With userstat=ON you also get ROWS_READ and ROWS_SENT per user.")
		fmt.Println()
	}

	if len(r.Users) == 0 {
		fmt.Printf("[mysqltop cpu] %s  no activity in last poll window\n", ts)
		return nil
	}

	// ---- Choose display mode ----------------------------------------------
	// showCPU: we actually have non-zero CPU data to display
	showCPU  := r.PerfCPUActive                  // Path A active, or Path B active
	showRows := r.UserstatOK                      // Path B: rows columns available

	// Header line (only if we haven't already printed a hint above)
	switch {
	case showCPU && showRows:
		fmt.Printf("[mysqltop cpu] %s  CPU + query + rows  (MariaDB userstat)  sort: CPU desc\n\n", ts)
	case showCPU:
		fmt.Printf("[mysqltop cpu] %s  CPU + query tracking  (MySQL 8+)  sort: CPU desc\n\n", ts)
	default:
		// hint already printed above; just print the table
		if !r.PerfHasCPU && !r.UserstatOff {
			// No hint was printed — plain "query only" header
			fmt.Printf("[mysqltop cpu] %s  query tracking only  sort: queries desc\n\n", ts)
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	switch {
	case showCPU && showRows:
		fmt.Fprintln(w, "USER\tCPU_SEC\tBUSY_SEC\tWAIT%\tQUERIES\tAVG_MS\tROWS_READ\tROWS_SENT\tLOAD")
		for _, u := range r.Users {
			fmt.Fprintf(w, "%s\t%.4f\t%.4f\t%s\t%d\t%.2f\t%d\t%d\t%s\n",
				u.User, u.CPUSec, u.BusySec, waitPct(u.CPUSec, u.BusySec),
				u.QueryCount, u.AvgQueryMsec,
				u.RowsRead, u.RowsSent, cpuBar(u.CPUSec))
		}
	case showCPU:
		fmt.Fprintln(w, "USER\tCPU_SEC\tQUERIES\tAVG_MS\tLOAD")
		for _, u := range r.Users {
			fmt.Fprintf(w, "%s\t%.4f\t%d\t%.2f\t%s\n",
				u.User, u.CPUSec, u.QueryCount, u.AvgQueryMsec, cpuBar(u.CPUSec))
		}
	default:
		fmt.Fprintln(w, "USER\tQUERIES\tAVG_MS\tACTIVITY")
		for _, u := range r.Users {
			fmt.Fprintf(w, "%s\t%d\t%.2f\t%s\n",
				u.User, u.QueryCount, u.AvgQueryMsec, queryBar(u.QueryCount, r.Users))
		}
	}
	w.Flush()
	return nil
}

// waitPct returns a formatted wait percentage string: (busy-cpu)/busy*100.
// Shows "-" when busy is zero (user had no activity this window).
// A high percentage means the user's queries are spending most of their time
// waiting on I/O, locks, or network rather than burning CPU.
func waitPct(cpuSec, busySec float64) string {
	if busySec <= 0 {
		return "-"
	}
	wait := (busySec - cpuSec) / busySec * 100
	if wait < 0 {
		wait = 0 // shouldn't happen; guard against float rounding
	}
	// Colour-code the severity in the terminal using a simple text flag.
	switch {
	case wait >= 80:
		return fmt.Sprintf("%.0f%% ⚠", wait)
	case wait >= 50:
		return fmt.Sprintf("%.0f%% ~", wait)
	default:
		return fmt.Sprintf("%.0f%%", wait)
	}
}

// cpuBar returns a simple ASCII bar proportional to CPU seconds consumed.
// The bar is scaled so that 1.0 CPU-second = full bar (10 chars).
// Useful for a quick visual ranking in the terminal.
func cpuBar(cpuSec float64) string {
	const maxBar = 10
	n := int(cpuSec * float64(maxBar))
	if n > maxBar {
		n = maxBar
	}
	if n < 0 {
		n = 0
	}
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", maxBar-n) + "]"
}

// queryBar renders a bar proportional to this user's query count relative to
// the busiest user in the slice.  Used on MariaDB where CPU time is unavailable.
func queryBar(count int64, all []UserPerfDelta) string {
	const maxBar = 10
	if len(all) == 0 || all[0].QueryCount == 0 {
		return "[" + strings.Repeat("░", maxBar) + "]"
	}
	n := int(float64(count) / float64(all[0].QueryCount) * float64(maxBar))
	if n > maxBar {
		n = maxBar
	}
	if n < 0 {
		n = 0
	}
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", maxBar-n) + "]"
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
	if secs == 0 {
		return "-"
	}
	d := time.Duration(secs) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", secs)
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}
