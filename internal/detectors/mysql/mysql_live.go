package mysql

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// --------------------------------------------------------------------------
// API response types
// --------------------------------------------------------------------------

type liveCPUResp struct {
	Ts            time.Time       `json:"ts"`
	PerfSchemaOK  bool            `json:"perf_schema_ok"`
	PerfHasCPU    bool            `json:"perf_has_cpu"`
	PerfCPUActive bool            `json:"perf_cpu_active"`
	UserstatOK    bool            `json:"userstat_ok"`
	UserstatOff   bool            `json:"userstat_off"`
	Users         []UserPerfDelta `json:"users"`
}

type liveHistoryResp struct {
	Ts          time.Time         `json:"ts"`
	Window      string            `json:"window"`
	SampleCount int               `json:"sample_count"`
	Users       []UserHistoryStat `json:"users"`
}

func fetchLiveJSON(url string, v any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// --------------------------------------------------------------------------
// UI-local ring buffer
// --------------------------------------------------------------------------

const trendLen = 150 // ~5 min at 2 s ticks

type uiRing struct {
	buf  [trendLen]float64
	head int
	size int
}

func (r *uiRing) push(v float64) {
	r.buf[r.head] = v
	r.head = (r.head + 1) % trendLen
	if r.size < trendLen {
		r.size++
	}
}

// slice returns the last n values in chronological order.
// Always returns >=2 elements so termui Plot never panics.
func (r *uiRing) slice(n int) []float64 {
	if n > r.size {
		n = r.size
	}
	if n < 2 {
		return []float64{0, 0}
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		idx := (r.head - n + i + trendLen) % trendLen
		out[i] = r.buf[idx]
	}
	return out
}

// --------------------------------------------------------------------------
// liveTreeLabel — plain string satisfying fmt.Stringer for TreeNode.Value
// --------------------------------------------------------------------------

type liveTreeLabel string

func (l liveTreeLabel) String() string { return string(l) }

// --------------------------------------------------------------------------
// Main live UI
// --------------------------------------------------------------------------

func mysqlLiveUI(baseURL string) error {
	if err := ui.Init(); err != nil {
		return err
	}
	defer ui.Close()

	// -----------------------------------------------------------------------
	// Widgets
	// -----------------------------------------------------------------------

	header := widgets.NewParagraph()
	header.Border = false
	header.PaddingTop = 0
	header.PaddingBottom = 0

	helpBar := widgets.NewParagraph()
	helpBar.Border = false
	helpBar.PaddingTop = 0
	helpBar.PaddingBottom = 0

	// ---- View A: classic tables ----

	connTable := widgets.NewTable()
	connTable.Title = " MySQL Connections "
	connTable.RowSeparator = false
	connTable.FillRow = true
	connTable.BorderStyle = ui.NewStyle(ui.ColorCyan)

	queryTable := widgets.NewTable()
	queryTable.Title = " Running Queries "
	queryTable.RowSeparator = false
	queryTable.FillRow = true
	queryTable.BorderStyle = ui.NewStyle(ui.ColorMagenta)

	cpuTable := widgets.NewTable()
	cpuTable.Title = " CPU / Queries "
	cpuTable.RowSeparator = false
	cpuTable.FillRow = true
	cpuTable.BorderStyle = ui.NewStyle(ui.ColorYellow)

	histTable := widgets.NewTable()
	histTable.Title = " History (1h) "
	histTable.RowSeparator = false
	histTable.FillRow = true
	histTable.BorderStyle = ui.NewStyle(ui.ColorGreen)

	// ---- View B: charts ----

	connGauge := widgets.NewGauge()
	connGauge.Title = " Connection Pressure "
	connGauge.BarColor = ui.ColorGreen
	connGauge.BorderStyle = ui.NewStyle(ui.ColorWhite)
	connGauge.LabelStyle = ui.NewStyle(ui.ColorWhite, ui.ColorClear, ui.ModifierBold)

	// Trend plot: total conns (cyan) + active conns (yellow)
	trendPlot := widgets.NewPlot()
	trendPlot.Title = " Conn Trend  [cyan=total  yellow=active] "
	trendPlot.Data = [][]float64{{0, 0}, {0, 0}}
	trendPlot.LineColors = []ui.Color{ui.ColorCyan, ui.ColorYellow}
	trendPlot.DrawDirection = widgets.DrawLeft
	trendPlot.AxesColor = ui.ColorWhite
	trendPlot.HorizontalScale = 1

	// QPS plot
	qpsPlot := widgets.NewPlot()
	qpsPlot.Title = " Queries / poll "
	qpsPlot.Data = [][]float64{{0, 0}}
	qpsPlot.LineColors = []ui.Color{ui.ColorCyan}
	qpsPlot.DrawDirection = widgets.DrawLeft
	qpsPlot.AxesColor = ui.ColorWhite
	qpsPlot.HorizontalScale = 1

	// Avg latency plot
	latPlot := widgets.NewPlot()
	latPlot.Title = " Avg Latency ms "
	latPlot.Data = [][]float64{{0, 0}}
	latPlot.LineColors = []ui.Color{ui.ColorYellow}
	latPlot.DrawDirection = widgets.DrawLeft
	latPlot.AxesColor = ui.ColorWhite
	latPlot.HorizontalScale = 1

	// Lock tree (replaces qps+lat when locks are active, in both views)
	lockTree := widgets.NewTree()
	lockTree.Title = " Lock Graph "
	lockTree.TextStyle = ui.NewStyle(ui.ColorWhite)
	lockTree.SelectedRowStyle = ui.NewStyle(ui.ColorBlack, ui.ColorRed)
	lockTree.WrapText = false

	// -----------------------------------------------------------------------
	// Layout
	// -----------------------------------------------------------------------

	var W, H int
	var plotPts int // data points that fit in a chart panel

	const headerH = 1
	const helpH   = 1
	const gaugeH  = 3
	const chrome  = headerH + helpH // rows consumed by header+help in both views

	chartView := false // false = View A (tables), true = View B (charts)

	doLayout := func() {
		W, H = ui.TerminalDimensions()

		usable := H - chrome // rows available below header+help

		// ---- View A layout ------------------------------------------------
		// gauge (full width, gaugeH rows)
		// Top half of remaining: connTable (left 38%) | queryTable (right 62%)
		// Bottom half:           cpuTable  (left 38%) | histTable  (right 62%)
		aTableY0 := chrome + gaugeH
		aUsable  := usable - gaugeH
		topH     := aUsable / 2
		if topH < 6 {
			topH = 6
		}
		aTopY1 := aTableY0 + topH

		aCol0W := W * 38 / 100
		if aCol0W < 28 {
			aCol0W = 28
		}

		connGauge.SetRect(0, chrome, W, chrome+gaugeH)
		connTable.SetRect(0, aTableY0, aCol0W, aTopY1)
		queryTable.SetRect(aCol0W, aTableY0, W, aTopY1)
		cpuTable.SetRect(0, aTopY1, aCol0W, H)
		histTable.SetRect(aCol0W, aTopY1, W, H)

		// ---- View B layout ------------------------------------------------
		// Row 0-chrome:  header + help (shared)
		// Row chrome:    gauge (gaugeH rows, full width) — same widget, same rect
		// Row chrome+gaugeH … H: trendPlot (left 50%) | right panel (50%)
		//    right panel = qpsPlot (top 55%) + latPlot (bottom 45%)
		//                  OR lockTree (full right) when locks active
		bChartY0 := chrome + gaugeH
		bChartH  := H - bChartY0
		if bChartH < 6 {
			bChartH = 6
		}
		bMidX := W / 2

		qpsH := bChartH * 55 / 100
		if qpsH < 4 {
			qpsH = 4
		}

		plotPts = bMidX - 4
		if plotPts < 10 {
			plotPts = 10
		}
		if plotPts > trendLen {
			plotPts = trendLen
		}

		trendPlot.SetRect(0, bChartY0, bMidX, H)
		qpsPlot.SetRect(bMidX, bChartY0, W, bChartY0+qpsH)
		latPlot.SetRect(bMidX, bChartY0+qpsH, W, H)
		lockTree.SetRect(bMidX, bChartY0, W, H)

		// header/help always full width
		header.SetRect(0, 0, W, headerH)
		helpBar.SetRect(0, headerH, W, chrome)
	}
	doLayout()

	// -----------------------------------------------------------------------
	// Ring buffers
	// -----------------------------------------------------------------------

	var rbTotal, rbActive, rbQPS, rbLat uiRing

	// -----------------------------------------------------------------------
	// Runtime state
	// -----------------------------------------------------------------------

	selected   := 0
	paused     := false
	lastErr    := ""
	lastUpdate := time.Time{}

	var state GovernorState
	var cpu   liveCPUResp
	var hist  liveHistoryResp

	// -----------------------------------------------------------------------
	// Column-width helper
	// -----------------------------------------------------------------------

	userColW := func() int {
		switch {
		case W >= 200:
			return 28
		case W >= 160:
			return 22
		case W >= 120:
			return 18
		default:
			return 14
		}
	}

	// -----------------------------------------------------------------------
	// Build functions — View A
	// -----------------------------------------------------------------------

	buildConnRows := func() {
		uw := userColW()
		rows := [][]string{{"USER", "TOT", "ACT", "SLP", "LCK", "MAX_IDLE", "RISK"}}
		styles := map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorCyan)}
		for i, u := range state.PerUser {
			name := truncStr(u.User, uw)
			risk, rowStyle := liveRiskRow(u)
			if i == selected {
				name = "▶ " + name
				rowStyle = ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold)
			}
			rows = append(rows, []string{
				name,
				fmt.Sprintf("%d", u.Total),
				fmt.Sprintf("%d", u.Active),
				fmt.Sprintf("%d", u.Sleeping),
				fmt.Sprintf("%d", u.Locked),
				formatAge(u.MaxSleepSec),
				risk,
			})
			styles[i+1] = rowStyle
		}
		connTable.Rows = rows
		connTable.RowStyles = styles
		connTable.ColumnWidths = []int{uw + 2, 5, 5, 5, 5, 9, 8}
	}

	buildQueryRows := func() {
		aCol0W := W * 38 / 100
		if aCol0W < 28 { aCol0W = 28 }
		panelW := W - aCol0W - 2
		const pidW, userW, dbW, timeW, stateW, sep = 8, 16, 14, 6, 18, 6
		queryW := panelW - pidW - userW - dbW - timeW - stateW - sep
		if queryW < 20 { queryW = 20 }

		rows := [][]string{{"PID", "USER", "DB", "TIME", "STATE", "QUERY"}}
		styles := map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorMagenta)}
		procs := state.Running
		if len(procs) > 12 { procs = procs[:12] }
		if len(procs) == 0 {
			rows = append(rows, []string{"(none)", "", "", "", "", ""})
		}
		for i, p := range procs {
			q := truncStr(strings.TrimSpace(p.Info), queryW)
			if q == "" { q = "-" }
			rows = append(rows, []string{
				fmt.Sprintf("%d", p.ID),
				truncStr(p.User, userW),
				truncStr(p.DB, dbW),
				formatAge(p.TimeSec),
				truncStr(p.State, stateW),
				q,
			})
			if isLockState(p.State) {
				styles[i+1] = ui.NewStyle(ui.ColorRed)
			} else if p.TimeSec >= 10 {
				styles[i+1] = ui.NewStyle(ui.ColorYellow)
			}
		}
		queryTable.Rows = rows
		queryTable.RowStyles = styles
		queryTable.ColumnWidths = []int{pidW, userW, dbW, timeW, stateW, queryW}
	}

	buildCPURows := func() {
		uw := userColW() - 2
		rows := [][]string{{"USER", "CPU_S", "WAIT%", "QRYS", "AVG_MS", "LOAD"}}
		styles := map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow)}
		switch {
		case !cpu.PerfSchemaOK:
			rows = append(rows, []string{"(perf_schema OFF)", "", "", "", "", ""})
		case len(cpu.Users) == 0:
			rows = append(rows, []string{"(no data yet)", "", "", "", "", ""})
		default:
			byUser := make(map[string]UserPerfDelta, len(cpu.Users))
			for _, u := range cpu.Users { byUser[u.User] = u }
			for i, user := range orderedUsersFromStateOrCPU(&state, cpu.Users) {
				u := byUser[user]
				name := truncStr(user, uw)
				if i == selected {
					name = "▶ " + name
					styles[i+1] = ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold)
				}
				rows = append(rows, []string{
					name,
					fmt.Sprintf("%.3f", u.CPUSec),
					waitPct(u.CPUSec, u.BusySec),
					fmt.Sprintf("%d", u.QueryCount),
					fmt.Sprintf("%.1f", u.AvgQueryMsec),
					cpuBar(u.CPUSec),
				})
			}
		}
		cpuTable.Rows = rows
		cpuTable.RowStyles = styles
		cpuTable.ColumnWidths = []int{uw + 2, 7, 7, 6, 7, 12}
	}

	buildHistRows := func() {
		uw := userColW() - 2
		rows := [][]string{{"USER", "PEAK", "AVG", "P_ACT", "A_ACT", "P_LCK", "SAT"}}
		styles := map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorGreen)}
		byUser := make(map[string]UserHistoryStat, len(hist.Users))
		for _, u := range hist.Users { byUser[u.User] = u }
		seen := map[string]bool{}
		var ordered []string
		for _, u := range state.PerUser {
			if _, ok := byUser[u.User]; ok {
				ordered = append(ordered, u.User)
				seen[u.User] = true
			}
		}
		for _, u := range hist.Users {
			if !seen[u.User] { ordered = append(ordered, u.User) }
		}
		for i, user := range ordered {
			u := byUser[user]
			name := truncStr(user, uw)
			if i == selected {
				name = "▶ " + name
				styles[i+1] = ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold)
			} else if u.PeakLocked > 0 {
				styles[i+1] = ui.NewStyle(ui.ColorRed)
			}
			rows = append(rows, []string{
				name,
				fmt.Sprintf("%d", u.PeakConns),
				fmt.Sprintf("%.1f", u.AvgConns),
				fmt.Sprintf("%d", u.PeakActive),
				fmt.Sprintf("%.1f", u.AvgActive),
				fmt.Sprintf("%d", u.PeakLocked),
				histBar(u.PeakConns, hist.Users),
			})
		}
		if len(rows) == 1 {
			rows = append(rows, []string{"(no data)", "", "", "", "", "", ""})
		}
		histTable.Rows = rows
		histTable.RowStyles = styles
		histTable.ColumnWidths = []int{uw + 2, 5, 5, 6, 6, 6, 12}
	}

	// -----------------------------------------------------------------------
	// Build functions — View B
	// -----------------------------------------------------------------------

	buildGauge := func() {
		pct := int(state.ConnPct)
		if pct < 0 { pct = 0 }
		if pct > 100 { pct = 100 }
		connGauge.Percent = pct
		connGauge.Label = fmt.Sprintf(
			"%d / %d  (%.0f%%)   active=%d   sleep=%d   locked=%d",
			state.TotalConn, state.MaxConn, state.ConnPct,
			state.ActiveConn, state.SleepConn, state.LockedConn,
		)
		switch {
		case state.ConnPct >= 85:
			connGauge.BarColor = ui.ColorRed
		case state.ConnPct >= 70:
			connGauge.BarColor = ui.ColorYellow
		default:
			connGauge.BarColor = ui.ColorGreen
		}
	}

	buildTrendPlot := func() {
		trendPlot.Data = [][]float64{
			rbTotal.slice(plotPts),
			rbActive.slice(plotPts),
		}
	}

	buildQPSPlots := func() {
		qpsPlot.Data = [][]float64{rbQPS.slice(plotPts)}
		latPlot.Data  = [][]float64{rbLat.slice(plotPts)}
	}

	buildLockTree := func() {
		if len(state.LockGraph) == 0 {
			lockTree.SetNodes([]*widgets.TreeNode{
				{Value: liveTreeLabel("  (no locks)")},
			})
			return
		}
		roots := make([]*widgets.TreeNode, 0, len(state.LockGraph))
		for _, g := range state.LockGraph {
			node := &widgets.TreeNode{
				Value: liveTreeLabel(fmt.Sprintf(
					"⚡ pid=%-7d  %-16s  db=%-12s  %s  %s",
					g.Blocker.ID, g.Blocker.User, g.Blocker.DB,
					formatAge(g.Blocker.TimeSec),
					truncStr(g.Blocker.Info, 55),
				)),
			}
			for _, w := range g.Waiters {
				node.Nodes = append(node.Nodes, &widgets.TreeNode{
					Value: liveTreeLabel(fmt.Sprintf(
						"  🔒 pid=%-7d  %-16s  %s  %s",
						w.ID, w.User,
						formatAge(w.TimeSec),
						truncStr(w.Info, 45),
					)),
				})
			}
			roots = append(roots, node)
		}
		lockTree.SetNodes(roots)
		lockTree.ExpandAll()
	}

	// -----------------------------------------------------------------------
	// Shared header + help bar
	// -----------------------------------------------------------------------

	buildHeader := func() {
		pausedTag := ""
		if paused { pausedTag = "  [PAUSED]" }
		errSuffix := ""
		if lastErr != "" { errSuffix = "  err=" + truncStr(lastErr, 55) }
		ts := ""
		if !lastUpdate.IsZero() { ts = "  updated=" + lastUpdate.Format("15:04:05") }

		viewTag := "tables"
		if chartView { viewTag = "charts" }

		header.Text = fmt.Sprintf(
			" LIVE mysql%s  flavor=%s  mode=%s  view=%s%s%s",
			pausedTag, state.Flavor, state.Mode, viewTag, ts, errSuffix,
		)
	}

	buildHelp := func() {
		pauseHint := ""
		if paused { pauseHint = "  [PAUSED — s/r to resume]" }
		if chartView {
			helpBar.Text = fmt.Sprintf(
				" q quit  x tables  s pause  r refresh%s"+
					"  │  left: conn trend  right: qps+lat  (lock tree when locks active)",
				pauseHint,
			)
		} else {
			helpBar.Text = fmt.Sprintf(
				" q quit  x charts  ↑↓/j/k nav  s pause  r refresh%s"+
					"  │  top: connections+queries  bottom: cpu+history",
				pauseHint,
			)
		}
	}

	// -----------------------------------------------------------------------
	// Ring-buffer sample push (every fetch)
	// -----------------------------------------------------------------------

	pushSamples := func() {
		rbTotal.push(float64(state.TotalConn))
		rbActive.push(float64(state.ActiveConn))
		var totalQ int64
		var totalW float64
		for _, u := range cpu.Users {
			totalQ += u.QueryCount
			totalW += float64(u.QueryCount) * u.AvgQueryMsec
		}
		rbQPS.push(float64(totalQ))
		if totalQ > 0 {
			rbLat.push(totalW / float64(totalQ))
		} else {
			rbLat.push(0)
		}
	}

	// -----------------------------------------------------------------------
	// Render — picks the right drawable set based on chartView
	// -----------------------------------------------------------------------

	render := func() {
		buildHeader()
		buildHelp()

		var drawable []ui.Drawable
		drawable = append(drawable, header, helpBar)

		if chartView {
			// View B — gauge + trend plot + qps/lat or lock tree
			buildGauge()
			buildTrendPlot()
			buildQPSPlots()
			buildLockTree()

			drawable = append(drawable, connGauge, trendPlot)
			if len(state.LockGraph) > 0 {
				lockTree.Title = fmt.Sprintf(" Lock Graph (%d blocker(s)) ", len(state.LockGraph))
				drawable = append(drawable, lockTree)
			} else {
				drawable = append(drawable, qpsPlot, latPlot)
			}
		} else {
			// View A — gauge + four tables
			buildGauge()
			buildConnRows()
			buildQueryRows()
			buildCPURows()
			buildHistRows()
			drawable = append(drawable, connGauge, connTable, queryTable, cpuTable, histTable)
		}

		ui.Clear()
		ui.Render(drawable...)
	}

	// -----------------------------------------------------------------------
	// Fetch
	// -----------------------------------------------------------------------

	refreshAll := func() {
		lastErr = ""
		if err := fetchLiveJSON(strings.TrimRight(baseURL, "/")+"/api/v1/mysql/state", &state); err != nil {
			lastErr = err.Error()
		} else {
			if err2 := fetchLiveJSON(strings.TrimRight(baseURL, "/")+"/api/v1/mysql/cpu", &cpu); err2 != nil {
				lastErr = "cpu:" + err2.Error()
			}
			if err3 := fetchLiveJSON(strings.TrimRight(baseURL, "/")+"/api/v1/mysql/history?window=1h&top=50", &hist); err3 != nil && lastErr == "" {
				lastErr = "hist:" + err3.Error()
			}
			if selected >= len(state.PerUser) && len(state.PerUser) > 0 {
				selected = len(state.PerUser) - 1
			}
		}
		pushSamples()
		lastUpdate = time.Now()
		render()
	}

	refreshAll()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	uiEvents := ui.PollEvents()

	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return nil

			case "x", "X":
				chartView = !chartView
				doLayout() // recalculate rects for the new view
				render()

			case "j", "<Down>":
				if !chartView && selected < len(state.PerUser)-1 {
					selected++
				}
				render()

			case "k", "<Up>":
				if !chartView && selected > 0 {
					selected--
				}
				render()

			case "r":
				paused = false
				refreshAll()

			case "s":
				paused = !paused
				render()

			case "<Resize>":
				doLayout()
				render()
			}

		case <-ticker.C:
			if !paused {
				refreshAll()
			}
		}
	}
}

// --------------------------------------------------------------------------
// Risk helpers
// --------------------------------------------------------------------------

func connRisk(pct float64) string {
	switch {
	case pct >= 85:
		return "🔴"
	case pct >= 70:
		return "🟡"
	default:
		return "🟢"
	}
}

func liveRiskRow(u UserStat) (label string, style ui.Style) {
	switch {
	case u.Locked > 0:
		return "LOCKED", ui.NewStyle(ui.ColorRed, ui.ColorClear, ui.ModifierBold)
	case u.MaxSleepSec > 300:
		return "STALE", ui.NewStyle(ui.ColorYellow)
	case u.Active >= 3:
		return "BUSY", ui.NewStyle(ui.ColorYellow)
	default:
		return "ok", ui.NewStyle(ui.ColorWhite)
	}
}

// --------------------------------------------------------------------------
// Display helpers
// --------------------------------------------------------------------------

func saturationText(state GovernorState, hist *liveHistoryResp) string {
	if state.MaxConn <= 0 {
		return "sat=-"
	}
	nowBar := percentBar(state.ConnPct)
	if hist == nil || len(hist.Users) == 0 {
		return "sat=" + nowBar
	}
	return fmt.Sprintf("sat=%s  hist_users=%d", nowBar, len(hist.Users))
}

func percentBar(pct float64) string {
	const maxBar = 10
	n := int((pct / 100.0) * maxBar)
	if n < 0 { n = 0 }
	if n > maxBar { n = maxBar }
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", maxBar-n) + "]"
}

func histBar(peak int, all []UserHistoryStat) string {
	const maxBar = 10
	if len(all) == 0 || all[0].PeakConns == 0 {
		return "[" + strings.Repeat("░", maxBar) + "]"
	}
	top := all[0].PeakConns
	n := int(float64(peak) / float64(top) * maxBar)
	if n < 0 { n = 0 }
	if n > maxBar { n = maxBar }
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", maxBar-n) + "]"
}

// --------------------------------------------------------------------------
// Table ordering
// --------------------------------------------------------------------------

func orderedUsersFromStateOrCPU(state *GovernorState, cpu []UserPerfDelta) []string {
	var out []string
	seen := map[string]bool{}
	if state != nil {
		for _, u := range state.PerUser {
			out = append(out, u.User)
			seen[u.User] = true
		}
	}
	for _, u := range cpu {
		if !seen[u.User] { out = append(out, u.User) }
	}
	return out
}

// --------------------------------------------------------------------------
// String utilities
// --------------------------------------------------------------------------

func truncStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n { return s }
	if n <= 2 { return string(r[:n]) }
	return string(r[:n-2]) + ".."
}

// intMax returns the larger of a and b.
// Named intMax to avoid conflicting with the Go 1.21+ builtin max.
func intMax(a, b int) int {
	if a > b { return a }
	return b
}
