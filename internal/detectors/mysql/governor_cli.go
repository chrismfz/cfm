// internal/detectors/mysql/governor_cli.go
package mysql

import (
	"bufio"
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"golang.org/x/term"
	"net/http"
	"net/url"
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
		if !isTTY() {
			return runMySQLTopDefault(baseURL)
		}
		return runMySQLLive(baseURL, nil)
	}

	switch args[0] {
	case "text":
		return runMySQLTopDefault(baseURL)

	case "live":
		if !isTTY() {
			return runMySQLTopDefault(baseURL)
		}
		return runMySQLLive(baseURL, args[1:])
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
		return runMySQLTopKills(baseURL, args[1:])
	case "watch":
		return runMySQLWatch(baseURL, args[1:])
	case "ps", "processlist":
		return runMySQLProcesslist(baseURL, args[1:])
	case "cpu":
		return runMySQLCPU(baseURL)

	case "user-summary", "usersummary":
		return runMySQLUserSummary(baseURL, args[1:])
	case "user-kills", "userkills":
		return runMySQLUserKills(baseURL, args[1:])
	case "user-history", "userhistory":
		return runMySQLUserHistory(baseURL, args[1:])

	case "history":
		if len(args) > 1 {
			switch args[1] {
			case "events":
				return runMySQLHistoryEvents(baseURL, args[2:])
			case "summary":
				return runMySQLHistorySummary(baseURL, args[2:])
			case "prune":
				return runMySQLHistoryPrune(baseURL, args[2:])
			case "truncate":
				return runMySQLHistoryTruncate(baseURL, args[2:])
			case "timeline":
				return runMySQLHistoryTimeline(baseURL, args[2:])
			}
		}

		// defaults
		window := "1h"
		topN := 20

		// detect positional args safely
		pos := []string{}
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "-") {
				break
			}
			pos = append(pos, a)
		}

		if len(pos) >= 1 {
			window = pos[0]
		}
		if len(pos) >= 2 {
			if n, err := strconv.Atoi(pos[1]); err == nil && n > 0 {
				topN = n
			}
		}

		return runMySQLHistory(baseURL, window, topN, args[1:])

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
func runMySQLLive(baseURL string, args []string) error {
	user, db, _, _ := parseMySQLFilters(args)
	return mysqlLiveUI(baseURL, user, db)
}

func printMySQLTopHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm mysqltop                              # live UI (falls back to text if not a TTY)")
	fmt.Println("  cfm mysqltop text                         # full summary (text)")
	fmt.Println("  cfm mysqltop live                         # force live UI")
	fmt.Println("  cfm mysqltop top [N]                      # top N users by connections")
	fmt.Println("  cfm mysqltop locks                        # lock graph (blockers + waiters)")
	fmt.Println("  cfm mysqltop kills                        # recent governor kills")
	fmt.Println("  cfm mysqltop ps                           # full processlist (running + waiting)")
	fmt.Println("  cfm mysqltop history [window] [N]         # busiest N users over window (1h, 6h, 24h)")
	fmt.Println("  cfm mysqltop history events [--user=u --db=d --type=t --limit=N]")
	fmt.Println("  cfm mysqltop history summary [--hours=24]")
	fmt.Println("  cfm mysqltop history prune [days]          # POST prune durable history")
	fmt.Println("  cfm mysqltop history truncate --yes        # POST truncate durable history")
	fmt.Println("  cfm mysqltop history timeline [--user=u --db=d --type=t --limit=N]")
	fmt.Println("  cfm mysqltop cpu                          # per-user CPU + query stats")
	fmt.Println()
	fmt.Println("Compatibility note:")
	fmt.Println("  cfm mysqltop history {events|summary|prune|truncate|timeline}")
	fmt.Println("    removed in this release (corresponding /api/v1/mysql/history/* routes are not served)")
	fmt.Println()
	fmt.Println("Per-user / per-db filtered views (plugin-ready):")
	fmt.Println("  cfm mysqltop user-summary --user=chris*")
	fmt.Println("  cfm mysqltop user-summary --user=chris_wp,chris_shop")
	fmt.Println("  cfm mysqltop user-summary --db=chris_wp")
	fmt.Println("  cfm mysqltop user-summary --user=chris* --db=chris_db  # OR semantics")
	fmt.Println()
	fmt.Println("  cfm mysqltop user-kills   --user=chris_wp")
	fmt.Println("  cfm mysqltop user-kills   --db=chris_wp,chris_shop")
	fmt.Println()
	fmt.Println("  cfm mysqltop user-history --user=chris*")
	fmt.Println("  cfm mysqltop user-history --user=chris_wp --window=6h --top=5")
	fmt.Println()
	fmt.Println("  Flags accepted by all user-* subcommands:")
	fmt.Println("    --user=<pattern>[,<pattern>...]   MySQL username(s); * wildcard OK")
	fmt.Println("    --db=<pattern>[,<pattern>...]     Database name(s);  * wildcard OK")
	fmt.Println("  user-history also accepts:")
	fmt.Println("    --window=<duration>               1h (default), 30m, 6h, 24h")
	fmt.Println("    --top=<N>                         limit results (default: all matches)")
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

func runMySQLTopKills(baseURL string, args []string) error {
	type killsResp struct {
		Ts    time.Time    `json:"ts"`
		Mode  string       `json:"mode"`
		Kills []KillRecord `json:"kills"`
	}
	var r killsResp
	user, db, _, _ := parseMySQLFilters(args)
	path := buildMySQLPath("/api/v1/mysql/kills", user, db)
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}
	fmt.Printf("[mysqltop kills] %s  mode=%s\n", r.Ts.Format("15:04:05"), r.Mode)
	if len(r.Kills) == 0 {
		fmt.Println("  (no kills recorded)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tACTION\tPID\tUSER\tHOST\tDB\tRUNTIME\tUNBLOCKED\tRESULT\tREASON")
	for _, k := range r.Kills {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			k.Ts.Format("15:04:05"), k.Action,
			k.PID, k.User, k.Host, k.DB,
			k.Runtime.Round(time.Second),
			k.Unblocked, k.Result,
			truncate(k.Reason, 60))
	}
	w.Flush()
	return nil
}

func runMySQLProcesslist(baseURL string, args []string) error {
	var r map[string]any
	user, db, _, _ := parseMySQLFilters(args)
	path := buildMySQLPath("/api/v1/mysql/processlist", user, db)
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
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
func runMySQLHistory(baseURL, window string, topN int, args []string) error {
	type histResp struct {
		Ts          time.Time         `json:"ts"`
		Window      string            `json:"window"`
		SampleCount int               `json:"sample_count"`
		Users       []UserHistoryStat `json:"users"`
	}
	var r histResp
	user, _, _, _ := parseMySQLFilters(args)
	path := fmt.Sprintf("/api/v1/mysql/history?window=%s&top=%d", url.QueryEscape(window), topN)
	if user != "" {
		path += "&user=" + url.QueryEscape(user)
	}
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
	showCPU := r.PerfCPUActive // Path A active, or Path B active
	showRows := r.UserstatOK   // Path B: rows columns available

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

func parseMySQLFilters(args []string) (user, db string, interval time.Duration, logPath string) {
	interval = 5 * time.Second
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--user" && i+1 < len(args):
			user = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--user="):
			user = strings.TrimPrefix(args[i], "--user=")
		case args[i] == "--db" && i+1 < len(args):
			db = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--db="):
			db = strings.TrimPrefix(args[i], "--db=")
		case args[i] == "--interval" && i+1 < len(args):
			if d, err := time.ParseDuration(args[i+1]); err == nil && d > 0 {
				interval = d
			}
			i++
		case strings.HasPrefix(args[i], "--interval="):
			if d, err := time.ParseDuration(strings.TrimPrefix(args[i], "--interval=")); err == nil && d > 0 {
				interval = d
			}
		case args[i] == "--log" && i+1 < len(args):
			logPath = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--log="):
			logPath = strings.TrimPrefix(args[i], "--log=")
		}
	}
	return
}

func buildMySQLPath(path, user, db string) string {
	q := url.Values{}
	if user != "" {
		q.Set("user", user)
	}
	if db != "" {
		q.Set("db", db)
	}
	if enc := q.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

func runMySQLWatch(baseURL string, args []string) error {
	user, db, interval, logPath := parseMySQLFilters(args)
	if user == "" && db == "" {
		return fmt.Errorf("watch requires at least --user or --db")
	}

	type watchSnapshot struct {
		Ts   time.Time      `json:"ts"`
		Proc map[string]any `json:"processlist"`
		Kill map[string]any `json:"kills"`
	}

	var f *os.File
	var err error
	if logPath != "" {
		f, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
	}

	fmt.Printf("[mysqltop watch] user=%q db=%q interval=%s log=%q\n", user, db, interval, logPath)
	tk := time.NewTicker(interval)
	defer tk.Stop()

	for {
		var proc map[string]any
		var kills map[string]any

		if err := fetchGovernorJSON(baseURL, buildMySQLPath("/api/v1/mysql/processlist", user, db), &proc); err != nil {
			return err
		}
		if err := fetchGovernorJSON(baseURL, buildMySQLPath("/api/v1/mysql/kills", user, db), &kills); err != nil {
			return err
		}

		snap := watchSnapshot{
			Ts:   time.Now(),
			Proc: proc,
			Kill: kills,
		}

		b, _ := json.Marshal(snap)
		fmt.Println(string(b))

		if f != nil {
			bw := bufio.NewWriter(f)
			_, _ = bw.Write(append(b, '\n'))
			_ = bw.Flush()
		}

		<-tk.C
	}
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
	resp, err := clihttp.Get(url)
	if err != nil {
		return fmt.Errorf("mysqltop: cannot reach %s: %w\n(is cfm daemon running?)", url, err)
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func postGovernorJSON(baseURL, path string, out any) error {
	target := strings.TrimRight(baseURL, "/") + path
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := clihttp.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mysqltop: POST %s failed: HTTP %d", u.String(), resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func runMySQLHistoryEvents(baseURL string, args []string) error {
	user := ""
	db := ""
	eventType := ""
	limit := 100
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--user" && i+1 < len(args):
			user = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--user="):
			user = strings.TrimPrefix(args[i], "--user=")
		case args[i] == "--db" && i+1 < len(args):
			db = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--db="):
			db = strings.TrimPrefix(args[i], "--db=")
		case args[i] == "--type" && i+1 < len(args):
			eventType = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--type="):
			eventType = strings.TrimPrefix(args[i], "--type=")
		case args[i] == "--limit" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				limit = n
			}
			i++
		case strings.HasPrefix(args[i], "--limit="):
			if n, err := strconv.Atoi(strings.TrimPrefix(args[i], "--limit=")); err == nil {
				limit = n
			}
		}
	}

	type respT struct {
		Rows []GovernorHistoryEvent `json:"rows"`
	}
	var r respT
	path := fmt.Sprintf("/api/v1/mysql/history/events?limit=%d", limit)
	if user != "" {
		path += "&user=" + url.QueryEscape(user)
	}
	if db != "" {
		path += "&db=" + url.QueryEscape(db)
	}
	if eventType != "" {
		path += "&type=" + url.QueryEscape(eventType)
	}
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TS\tTYPE\tUSER\tDB\tACTION\tRESULT\tREASON")
	for _, ev := range r.Rows {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			ev.TsUnix, ev.EventType, ev.User, ev.DB, ev.Action, ev.Result, truncate(ev.Reason, 80))
	}
	return w.Flush()
}

func runMySQLHistorySummary(baseURL string, args []string) error {
	hours := 24
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--hours" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				hours = n
			}
			i++
		case strings.HasPrefix(args[i], "--hours="):
			if n, err := strconv.Atoi(strings.TrimPrefix(args[i], "--hours=")); err == nil {
				hours = n
			}
		}
	}
	var s GovernorHistorySummary
	if err := fetchGovernorJSON(baseURL, fmt.Sprintf("/api/v1/mysql/history/summary?hours=%d", hours), &s); err != nil {
		return err
	}
	fmt.Printf("mysql governor history summary (%dh): total=%d kill_query=%d kill_connection=%d sleep_reap=%d conn_warn=%d conn_critical=%d\n",
		hours, s.TotalEvents, s.KillQuery, s.KillConnection, s.SleepReap, s.ConnPressureWarn, s.ConnPressureCrit)
	return nil
}

func runMySQLHistoryPrune(baseURL string, args []string) error {
	days := 30
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			days = n
		}
	}
	var out map[string]any
	if err := postGovernorJSON(baseURL, fmt.Sprintf("/api/v1/mysql/history/prune?days=%d", days), &out); err != nil {
		return err
	}
	fmt.Printf("mysql history pruned days=%d rows_deleted=%v\n", days, out["rows_deleted"])
	return nil
}

func runMySQLHistoryTruncate(baseURL string, args []string) error {
	confirm := false
	for _, a := range args {
		if a == "--yes" {
			confirm = true
		}
	}
	if !confirm {
		return fmt.Errorf("refusing to truncate without --yes")
	}
	var out map[string]any
	if err := postGovernorJSON(baseURL, "/api/v1/mysql/history/truncate?confirm=yes", &out); err != nil {
		return err
	}
	fmt.Printf("mysql history truncated rows_deleted=%v\n", out["rows_deleted"])
	return nil
}

func runMySQLHistoryTimeline(baseURL string, args []string) error {
	user := ""
	db := ""
	eventType := ""
	limit := 200
	full := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--user" && i+1 < len(args):
			user = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--user="):
			user = strings.TrimPrefix(args[i], "--user=")
		case args[i] == "--db" && i+1 < len(args):
			db = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--db="):
			db = strings.TrimPrefix(args[i], "--db=")
		case args[i] == "--type" && i+1 < len(args):
			eventType = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--type="):
			eventType = strings.TrimPrefix(args[i], "--type=")
		case args[i] == "--limit" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
				limit = n
			}
			i++
		case strings.HasPrefix(args[i], "--limit="):
			if n, err := strconv.Atoi(strings.TrimPrefix(args[i], "--limit=")); err == nil && n > 0 {
				limit = n
			}
		case args[i] == "--full":
			full = true
		}
	}

	path := fmt.Sprintf("/api/v1/mysql/history/timeline?limit=%d", limit)
	if user != "" {
		path += "&user=" + url.QueryEscape(user)
	}
	if db != "" {
		path += "&db=" + url.QueryEscape(db)
	}
	if eventType != "" {
		path += "&type=" + url.QueryEscape(eventType)
	}

	var r struct {
		Rows []GovernorHistoryEvent `json:"rows"`
	}
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}

	for _, ev := range r.Rows {
		fmt.Printf("%d %s %s %s\n", ev.TsUnix, ev.EventType, ev.User, ev.Reason)
		if ev.Payload == nil {
			continue
		}

		if conn, ok := ev.Payload["conn"].(map[string]any); ok {
			fmt.Printf("  conn: total=%v max=%v pct=%v active=%v sleep=%v locked=%v\n",
				conn["total"], conn["max"], conn["pct"], conn["active"], conn["sleep"], conn["locked"])
		}
		if hosts, ok := ev.Payload["hosts"].([]any); ok && len(hosts) > 0 {
			fmt.Println("  hosts:")
			for i, h := range hosts {
				if i >= 5 {
					break
				}
				fmt.Printf("    %v\n", h)
			}
		}
		if cmds, ok := ev.Payload["commands"].([]any); ok && len(cmds) > 0 {
			fmt.Println("  commands:")
			for i, c := range cmds {
				if i >= 5 {
					break
				}
				fmt.Printf("    %v\n", c)
			}
		}
		if qps, ok := ev.Payload["query_patterns"].([]any); ok && len(qps) > 0 {
			fmt.Println("  query_patterns:")
			for i, q := range qps {
				if i >= 5 {
					break
				}
				fmt.Printf("    %v\n", q)
			}
		}
		if full {
			b, _ := json.MarshalIndent(ev.Payload, "  ", "  ")
			fmt.Println("  payload:")
			fmt.Println(string(b))
		}
	}
	return nil
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

// runMySQLUserSummary implements `cfm mysqltop user-summary --user=X [--db=Y]`.
//
// Calls GET /api/v1/mysql/user-summary and renders a human-readable table
// identical in style to the existing `cfm mysqltop text` output, but scoped
// to the requested users / databases.
func runMySQLUserSummary(baseURL string, args []string) error {
	users, dbs, window, _, err := parseUserDBFlags(args)
	if err != nil {
		return err
	}
	_ = window // not used by user-summary

	if len(users) == 0 && len(dbs) == 0 {
		return fmt.Errorf("user-summary: at least one --user= or --db= flag is required\n" +
			"  example: cfm mysqltop user-summary --user=chris*")
	}

	path := buildUserFilterPath("/api/v1/mysql/user-summary", users, dbs)

	type summaryResp struct {
		Ts      time.Time      `json:"ts"`
		Flavor  string         `json:"flavor"`
		Mode    string         `json:"mode"`
		Filter  map[string]any `json:"filter"`
		PerUser []UserStat     `json:"per_user"`
		Conn    struct {
			Total    int `json:"total"`
			Active   int `json:"active"`
			Sleeping int `json:"sleeping"`
			Locked   int `json:"locked"`
		} `json:"conn"`
		Running    []Process       `json:"running"`
		PerfDeltas []UserPerfDelta `json:"perf_deltas"`
	}

	var r summaryResp
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}

	fmt.Printf("[mysqltop user-summary] %s  flavor=%s  mode=%s\n",
		r.Ts.Format("15:04:05"), r.Flavor, r.Mode)
	fmt.Printf("filter: users=%v  dbs=%v\n", users, dbs)

	if len(r.PerUser) == 0 {
		fmt.Println("  (no matching connections)")
		return nil
	}

	fmt.Printf("\nCONNECTIONS (filtered): total=%d  active=%d  sleep=%d  locked=%d\n",
		r.Conn.Total, r.Conn.Active, r.Conn.Sleeping, r.Conn.Locked)

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tCONNS\tACTIVE\tSLEEP\tLOCKED\tMAX_IDLE\tRISK")
	for _, u := range r.PerUser {
		risk := "🟢 ok"
		if u.Locked > 0 {
			risk = "🔴 LOCKED"
		} else if u.MaxSleepSec > 300 {
			risk = "🟡 STALE"
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%s\t%s\n",
			u.User, u.Total, u.Active, u.Sleeping, u.Locked,
			formatAge(u.MaxSleepSec), risk)
	}
	w.Flush()

	if len(r.Running) > 0 {
		fmt.Printf("\nRUNNING QUERIES (%d)  [query text hidden — use admin endpoints]\n", len(r.Running))
		w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w2, "PID\tUSER\tDB\tCOMMAND\tTIME\tSTATE")
		for _, p := range r.Running {
			fmt.Fprintf(w2, "%d\t%s\t%s\t%s\t%ds\t%s\n",
				p.ID, p.User, p.DB, p.Command, p.TimeSec, p.State)
		}
		w2.Flush()
	}

	if len(r.PerfDeltas) > 0 {
		fmt.Println("\nCPU / QUERY DELTAS (last poll)")
		w3 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w3, "USER\tCPU_SEC\tQUERIES\tAVG_MS")
		for _, d := range r.PerfDeltas {
			fmt.Fprintf(w3, "%s\t%.4f\t%d\t%.2f\n",
				d.User, d.CPUSec, d.QueryCount, d.AvgQueryMsec)
		}
		w3.Flush()
	}

	return nil
}

// runMySQLUserKills implements `cfm mysqltop user-kills --user=X [--db=Y]`.
//
// Calls GET /api/v1/mysql/user-kills and renders the filtered kill ring.
func runMySQLUserKills(baseURL string, args []string) error {
	users, dbs, _, _, err := parseUserDBFlags(args)
	if err != nil {
		return err
	}

	if len(users) == 0 && len(dbs) == 0 {
		return fmt.Errorf("user-kills: at least one --user= or --db= flag is required\n" +
			"  example: cfm mysqltop user-kills --user=chris_wp")
	}

	path := buildUserFilterPath("/api/v1/mysql/user-kills", users, dbs)

	type killsResp struct {
		Ts     time.Time      `json:"ts"`
		Mode   string         `json:"mode"`
		Filter map[string]any `json:"filter"`
		Kills  []KillRecord   `json:"kills"`
	}

	var r killsResp
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}

	fmt.Printf("[mysqltop user-kills] %s  mode=%s\n", r.Ts.Format("15:04:05"), r.Mode)
	fmt.Printf("filter: users=%v  dbs=%v\n", users, dbs)

	if len(r.Kills) == 0 {
		fmt.Println("  (no kills matching filter)")
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

// runMySQLUserHistory implements `cfm mysqltop user-history --user=X [--window=6h] [--top=N]`.
//
// Calls GET /api/v1/mysql/user-history and renders filtered long-window stats.
func runMySQLUserHistory(baseURL string, args []string) error {
	users, dbs, window, topN, err := parseUserDBFlags(args)
	if err != nil {
		return err
	}

	if len(users) == 0 && len(dbs) == 0 {
		return fmt.Errorf("user-history: at least one --user= or --db= flag is required\n" +
			"  example: cfm mysqltop user-history --user=chris*")
	}

	path := buildUserFilterPath("/api/v1/mysql/user-history", users, dbs)
	path += fmt.Sprintf("&window=%s&top=%d", window, topN)

	type histResp struct {
		Ts          time.Time         `json:"ts"`
		Window      string            `json:"window"`
		SampleCount int               `json:"sample_count"`
		Filter      map[string]any    `json:"filter"`
		Users       []UserHistoryStat `json:"users"`
	}

	var r histResp
	if err := fetchGovernorJSON(baseURL, path, &r); err != nil {
		return err
	}

	fmt.Printf("[mysqltop user-history] %s  window=%s  samples=%d\n",
		r.Ts.Format("15:04:05"), r.Window, r.SampleCount)
	fmt.Printf("filter: users=%v  dbs=%v\n", users, dbs)

	if len(r.Users) == 0 {
		fmt.Println("  (no history matching filter)")
		return nil
	}

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

// ── shared flag / URL helpers ─────────────────────────────────────────────────

// parseUserDBFlags parses --user=, --db=, --window=, --top= from a CLI args slice.
//
// Supports both --flag=value and --flag value (space-separated) forms.
// --user and --db each accept comma-separated lists, e.g. --user=a,b,c.
// Unknown flags are ignored so future flags don't break existing scripts.
//
// Returns (users, dbs, window, topN, err).
// window defaults to "1h"; topN defaults to 0 (all).
func parseUserDBFlags(args []string) (users, dbs []string, window string, topN int, err error) {
	window = "1h"
	topN = 0

	splitCSV := func(s string) []string {
		var out []string
		for _, part := range strings.Split(s, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
		return out
	}

	for i := 0; i < len(args); i++ {
		a := args[i]

		// --flag=value form
		if strings.HasPrefix(a, "--") {
			a = a[2:] // strip leading --
			if idx := strings.IndexByte(a, '='); idx >= 0 {
				key, val := a[:idx], a[idx+1:]
				switch key {
				case "user":
					users = append(users, splitCSV(val)...)
				case "db":
					dbs = append(dbs, splitCSV(val)...)
				case "window":
					window = strings.TrimSpace(val)
				case "top":
					if n, e := strconv.Atoi(strings.TrimSpace(val)); e == nil && n >= 0 {
						topN = n
					}
				}
				continue
			}
			// --flag value form (next arg is the value)
			key := a
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				val := args[i+1]
				i++
				switch key {
				case "user":
					users = append(users, splitCSV(val)...)
				case "db":
					dbs = append(dbs, splitCSV(val)...)
				case "window":
					window = strings.TrimSpace(val)
				case "top":
					if n, e := strconv.Atoi(strings.TrimSpace(val)); e == nil && n >= 0 {
						topN = n
					}
				}
			}
		}
	}

	return users, dbs, window, topN, nil
}

// buildUserFilterPath constructs the API path with ?user= and ?db= query params.
// Uses repeated params (?user=a&user=b) rather than comma-separated so the
// server's parseMultiParam handles both forms identically.
func buildUserFilterPath(base string, users, dbs []string) string {
	var sb strings.Builder
	sb.WriteString(base)
	sep := "?"
	for _, u := range users {
		sb.WriteString(sep)
		sb.WriteString("user=")
		sb.WriteString(u)
		sep = "&"
	}
	for _, d := range dbs {
		sb.WriteString(sep)
		sb.WriteString("db=")
		sb.WriteString(d)
		sep = "&"
	}
	return sb.String()
}
