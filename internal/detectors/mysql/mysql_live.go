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
// Main live UI
// --------------------------------------------------------------------------

func mysqlLiveUI(baseURL string) error {
	if err := ui.Init(); err != nil {
		return err
	}
	defer ui.Close()

	// ---- widgets ----
	header := widgets.NewParagraph()
	header.Border = false
	header.PaddingTop = 0
	header.PaddingBottom = 0

	helpBar := widgets.NewParagraph()
	helpBar.Border = false
	helpBar.PaddingTop = 0
	helpBar.PaddingBottom = 0

	connTable := widgets.NewTable()
	connTable.Title = " MySQL Connections "
	connTable.RowSeparator = false
	connTable.FillRow = true
	connTable.BorderStyle = ui.NewStyle(ui.ColorCyan)

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

	// ---- layout state ----
	var W, H int

	const headerH = 1 // rows for the header paragraph (single status line)
	const helpH = 1   // row for the help/keybind bar

	doLayout := func() {
		W, H = ui.TerminalDimensions()

		// connections table gets ~48% of the usable height
		connH := (H - headerH - helpH) * 48 / 100
		if connH < 8 {
			connH = 8
		}

		bottomY := headerH + helpH + connH
		bottomH := H - bottomY
		if bottomH < 5 {
			bottomH = 5
		}

		cpuW := W / 2

		header.SetRect(0, 0, W, headerH)
		helpBar.SetRect(0, headerH, W, headerH+helpH)
		connTable.SetRect(0, headerH+helpH, W, bottomY)
		cpuTable.SetRect(0, bottomY, cpuW, H)
		histTable.SetRect(cpuW, bottomY, W, H)
	}
	doLayout()

	// ---- runtime state ----
	selected := 0
	paused   := false
	lastErr := ""
	lastUpdate := time.Time{}

	var state GovernorState
	var cpu liveCPUResp
	var hist liveHistoryResp

	// ---- column-width helper (dynamic based on terminal width) ----
	userColW := func() int {
		switch {
		case W >= 200:
			return 32
		case W >= 160:
			return 26
		case W >= 120:
			return 22
		default:
			return 18
		}
	}

	// ---------- connection table fill ----------
	buildConnRows := func() {
		uw := userColW()
		header := []string{"USER", "TOT", "ACT", "SLP", "LCK", "MAX_IDLE", "RISK"}
		rows := [][]string{header}
		styles := map[int]ui.Style{
			0: ui.NewStyle(ui.ColorBlack, ui.ColorCyan),
		}

		for i, u := range state.PerUser {
			name := truncStr(u.User, uw)
			sel := i == selected

			risk, rowStyle := liveRiskRow(u, sel)
			if sel {
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
		connTable.ColumnWidths = []int{uw + 2, 5, 5, 5, 5, 9, 10}
	}

	// ---------- CPU table fill ----------
	buildCPURows := func() {
		uw := userColW() - 4 // CPU panel is half-width, shorten usernames
		header := []string{"USER", "CPU_S", "WAIT%", "QRYS", "AVG_MS", "LOAD"}
		rows := [][]string{header}
		styles := map[int]ui.Style{
			0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow),
		}

		if !cpu.PerfSchemaOK {
			rows = append(rows, []string{"(perf_schema OFF)", "", "", "", "", ""})
		} else if len(cpu.Users) == 0 {
			rows = append(rows, []string{"(no data)", "", "", "", "", ""})
		} else {
			byUser := make(map[string]UserPerfDelta, len(cpu.Users))
			for _, u := range cpu.Users {
				byUser[u.User] = u
			}
			ordered := orderedUsersFromStateOrCPU(&state, cpu.Users)
			for i, user := range ordered {
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

	// ---------- history table fill ----------
	buildHistRows := func() {
		uw := userColW() - 4
		header := []string{"USER", "PEAK", "AVG", "P_ACT", "A_ACT", "P_LCK", "SAT"}
		rows := [][]string{header}
		styles := map[int]ui.Style{
			0: ui.NewStyle(ui.ColorBlack, ui.ColorGreen),
		}

		byUser := make(map[string]UserHistoryStat, len(hist.Users))
		for _, u := range hist.Users {
			byUser[u.User] = u
		}

		// order by current connection list first, then any remaining history users
		seen := map[string]bool{}
		var ordered []string
		for _, u := range state.PerUser {
			if _, ok := byUser[u.User]; ok {
				ordered = append(ordered, u.User)
				seen[u.User] = true
			}
		}
		for _, u := range hist.Users {
			if !seen[u.User] {
				ordered = append(ordered, u.User)
			}
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

	// ---------- header text — plain text, no termui markup ----------
	// Termui markup inside Paragraph is fragile when substituted values
	// contain brackets or percent signs; plain text is always safe.
	buildHeader := func() {
		risk := connRisk(state.ConnPct)
		sat := saturationText(state, &hist)
		ts := ""
		if !lastUpdate.IsZero() {
			ts = "  updated=" + lastUpdate.Format("15:04:05")
		}
		errSuffix := ""
		if lastErr != "" {
			errSuffix = "  err=" + truncStr(lastErr, 50)
		}
		header.Text = fmt.Sprintf(
			" LIVE mysql%s  flavor=%s  mode=%s  conn=%d/%d (%.0f%% %s)  active=%d sleep=%d locked=%d  %s%s%s",
			func() string {
				if paused { return " [PAUSED]" }
				return ""
			}(),
			state.Flavor, state.Mode,
			state.TotalConn, state.MaxConn, state.ConnPct, risk,
			state.ActiveConn, state.SleepConn, state.LockedConn,
			sat, ts, errSuffix,
		)
	}

	// ---------- full render (no ui.Clear — avoid unnecessary full wipes) ----------
	render := func() {
		buildHeader()
		buildConnRows()
		buildCPURows()
		buildHistRows()
		helpBar.Text = " [q](fg:yellow) quit  [↑↓/j/k](fg:yellow) nav  [s](fg:yellow) pause/resume  [r](fg:yellow) refresh  " +
			"│ conn=[cyan](fg:cyan) ▲sel  risk: [dim](fg:white) ok  [yellow](fg:yellow) stale/busy  [red](fg:red) locked"
		ui.Clear()
		ui.Render(header, helpBar, connTable, cpuTable, histTable)
	}

	// ---------- data fetch ----------
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

			case "j", "<Down>":
				if selected < len(state.PerUser)-1 {
					selected++
				}
				render()

			case "k", "<Up>":
				if selected > 0 {
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

// connRisk returns a small text indicator for overall connection pressure.
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

// liveRiskRow returns a short risk label and a termui row style for the
// connections table. The sel flag is handled by the caller (selected row
// always gets the highlight style regardless).
func liveRiskRow(u UserStat, sel bool) (label string, style ui.Style) {
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
// Header display helpers
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
	if n < 0 {
		n = 0
	}
	if n > maxBar {
		n = maxBar
	}
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", maxBar-n) + "]"
}

func histBar(peak int, all []UserHistoryStat) string {
	const maxBar = 10
	if len(all) == 0 || all[0].PeakConns == 0 {
		return "[" + strings.Repeat("░", maxBar) + "]"
	}
	top := all[0].PeakConns
	n := int(float64(peak) / float64(top) * maxBar)
	if n < 0 {
		n = 0
	}
	if n > maxBar {
		n = maxBar
	}
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
		if !seen[u.User] {
			out = append(out, u.User)
		}
	}
	return out
}

// --------------------------------------------------------------------------
// String utilities
// --------------------------------------------------------------------------

// truncStr truncates s to at most n runes, appending ".." if it was cut.
func truncStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 2 {
		return string(r[:n])
	}
	return string(r[:n-2]) + ".."
}

// intMax returns the larger of a and b.
// Named intMax to avoid conflicting with the Go 1.21+ builtin max.
func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
