// internal/webdetector/live.go
package webdetector

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// ── ring buffer helpers ──────────────────────────────────────────────────────

const ringSize = 120 // 2 minutes of history at 1s poll

type ringBuf struct {
	data [ringSize]float64
	head int
	full bool
}

func (r *ringBuf) push(v float64) {
	r.data[r.head] = v
	r.head = (r.head + 1) % ringSize
	if r.head == 0 {
		r.full = true
	}
}

func (r *ringBuf) slice(n int) []float64 {
	if n > ringSize {
		n = ringSize
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		idx := (r.head - n + i + ringSize) % ringSize
		out[i] = r.data[idx]
	}
	return out
}

// ── snapshot types ───────────────────────────────────────────────────────────

type liveSnapshot struct {
	// from top-short row
	RPS  float64
	R2xx float64
	R3xx float64
	R4xx float64
	R5xx float64
	Err  float64 // 0-100 %
	Bot  float64 // 0-100 %

	// from drilldown
	RT        float64
	Score     float64
	UniqueIPs int
	BotPct    float64 // 0-100 (from HostDetail.BotPct)
	HumanPct  float64

	// enriched IPs
	EnrichedIPs []map[string]string

	// top paths
	TopPaths []TopKV

	// reasons
	Reasons []string

	// challenge state
	ChallengeActive bool
	ChallengeMode   string // "manual" | "auto" | ""
	ChallengeExpiry string // formatted expiry for manual
}

// ── fetchers ─────────────────────────────────────────────────────────────────

func fetchLiveSnapshot(baseURL, host string) (liveSnapshot, error) {
	var snap liveSnapshot

	// 1) top-short → find our row for RPS breakdown
	u1 := baseURL + "/api/v1/webdet/top-short"
	r1, err := http.Get(u1)
	if err != nil {
		return snap, err
	}
	defer r1.Body.Close()

	var topResp topShortCLIResponse
	if err := json.NewDecoder(r1.Body).Decode(&topResp); err != nil {
		return snap, err
	}
	for _, row := range topResp.Rows {
		if strings.EqualFold(row.Host, host) {
			snap.RPS      = row.RPS
			snap.R2xx     = row.R2xx
			snap.R3xx     = row.R3xx
			snap.R4xx     = row.R4xx
			snap.R5xx     = row.R5xx
			snap.Err      = row.ErrRatio * 100
			snap.Bot      = row.BotRatio * 100
			snap.Score    = row.Score
			snap.Reasons  = row.Reasons
			snap.UniqueIPs = row.UniqueIPs // ← real count from bucket maps, not capped
			break
		}
	}

	// 2) drilldown → enriched IPs, rt, paths  (?top=25 lifts the default cap of 10)
	u2 := baseURL + "/api/v1/webdet/drilldown?host=" + url.QueryEscape(host) + "&top=25"
	r2, err := http.Get(u2)
	if err != nil {
		return snap, nil // partial ok – use what we have
	}
	defer r2.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r2.Body).Decode(&raw); err != nil {
		return snap, nil
	}
	var detail HostDetail
	if b, ok := raw["short"]; ok {
		_ = json.Unmarshal(b, &detail)
	}
	snap.RT       = detail.ProcAvgSec
	// snap.UniqueIPs already set from top-short row above (accurate, uncapped)
	snap.BotPct   = detail.BotPct
	snap.HumanPct = math.Max(0, 100-detail.BotPct)
	snap.EnrichedIPs = detail.EnrichedTopIPs
	snap.TopPaths = detail.TopPaths
	if snap.Score == 0 {
		snap.Score = detail.ShortScore
	}
	if len(snap.Reasons) == 0 {
		snap.Reasons = detail.ShortReasons
	}

	// 3) challenge status
	snap.ChallengeActive, snap.ChallengeMode, snap.ChallengeExpiry = fetchChallengeStatus(baseURL, host)

	return snap, nil
}

// fetchChallengeStatus checks /challenge/vhost/status for the given host.
func fetchChallengeStatus(baseURL, host string) (active bool, mode, expiry string) {
	u := fmt.Sprintf("%s/api/v1/challenge/vhost/status?host=%s", baseURL, url.QueryEscape(host))
	r, err := http.Get(u)
	if err != nil {
		return
	}
	defer r.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		return
	}
	manualActive, _ := result["manual_active"].(bool)
	autoActive, _   := result["auto_active"].(bool)
	expiresAt, _    := result["expires_at"].(string)
	if manualActive {
		active = true
		mode   = "manual"
		// trim to HH:MM:SS if it's a full timestamp
		if len(expiresAt) > 19 {
			expiry = expiresAt[11:19]
		} else {
			expiry = expiresAt
		}
	} else if autoActive {
		active = true
		mode   = "auto"
	}
	return
}

// ── layout helpers ───────────────────────────────────────────────────────────

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func scoreColor(score float64) ui.Color {
	switch {
	case score >= 0.7:
		return ui.ColorRed
	case score >= 0.4:
		return ui.ColorYellow
	default:
		return ui.ColorGreen
	}
}

func errColor(pct float64) ui.Color {
	switch {
	case pct >= 30:
		return ui.ColorRed
	case pct >= 10:
		return ui.ColorYellow
	default:
		return ui.ColorGreen
	}
}

func botColor(pct float64) ui.Color {
	switch {
	case pct >= 60:
		return ui.ColorRed
	case pct >= 25:
		return ui.ColorYellow
	default:
		return ui.ColorCyan
	}
}

// fillIPTable updates an existing table widget in-place with enriched IPs.
func fillIPTable(t *widgets.Table, ips []map[string]string) {
	header := []string{"#", "IP", "Reqs", "PTR / ASN", "CC", "Score"}
	rows := [][]string{header}

	limit := len(ips)
	if limit > 14 {
		limit = 14
	}
	for i, row := range ips[:limit] {
		ip := row["ip"]
		count := row["count"]
		ptr := row["ptr"]
		asn := row["asn"]
		asnNm := row["asn_name"]
		cc := row["country"]
		score := row["score"] // may be empty

		// Build a combined PTR / ASN column
		ptrPart := ptr
		if len(ptrPart) > 22 {
			ptrPart = ptrPart[:20] + ".."
		}
		asPart := strings.TrimSpace(func() string {
			if asn == "" {
				return asnNm
			}
			if !strings.HasPrefix(asn, "AS") {
				asn = "AS" + asn
			}
			if asnNm != "" {
				return asn + " " + asnNm
			}
			return asn
		}())
		if len(asPart) > 22 {
			asPart = asPart[:20] + ".."
		}
		combined := ptrPart
		if combined == "" {
			combined = asPart
		} else if asPart != "" {
			combined = ptrPart + " / " + asPart
		}
		if len(combined) > 38 {
			combined = combined[:36] + ".."
		}

		scoreStr := score
		if scoreStr == "" {
			scoreStr = "-"
		}

		rows = append(rows, []string{
			fmt.Sprintf("%2d", i+1),
			ip,
			count,
			combined,
			cc,
			scoreStr,
		})
	}
	// Pad so the table height stays stable
	for len(rows) < 10 {
		rows = append(rows, []string{"", "", "", "", "", ""})
	}
	t.Rows = rows
}

// fillPathsTable updates a paths table widget in-place.
func fillPathsTable(t *widgets.Table, paths []TopKV) {
	header := []string{"#", "Path", "Hits"}
	rows := [][]string{header}

	limit := len(paths)
	if limit > 14 {
		limit = 14
	}
	for i, p := range paths[:limit] {
		path := p.Key
		if len(path) > 48 {
			path = path[:46] + ".."
		}
		rows = append(rows, []string{
			fmt.Sprintf("%2d", i+1),
			path,
			fmt.Sprintf("%d", p.Count),
		})
	}
	for len(rows) < 10 {
		rows = append(rows, []string{"", "", ""})
	}
	t.Rows = rows
}

// ── main entry point ─────────────────────────────────────────────────────────

// RunLiveDrilldown is `cfm webtop live <vhost>`.
func RunLiveDrilldown(baseURL, host string) error {
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	// ring buffers
	var (
		rbRPS  ringBuf
		rb2xx  ringBuf
		rb3xx  ringBuf
		rb4xx  ringBuf
		rb5xx  ringBuf
		rbErr  ringBuf
		rbBot  ringBuf
		rbHum  ringBuf
		rbRT   ringBuf
	)

	W, H := ui.TerminalDimensions()

	// ── widgets ──────────────────────────────────────────────────────────────

	// Title / header
	title := widgets.NewParagraph()
	title.Border = true
	title.BorderStyle = ui.NewStyle(ui.ColorCyan)

	// RPS line chart (2xx / 4xx / 5xx)
	rpsChart := widgets.NewPlot()
	rpsChart.Title = " ◈ Traffic RPS  [cyan=2xx  yellow=4xx  red=5xx] "
	rpsChart.Data = [][]float64{
		make([]float64, 60),
		make([]float64, 60),
		make([]float64, 60),
	}
	rpsChart.LineColors = []ui.Color{ui.ColorGreen, ui.ColorYellow, ui.ColorRed}
	rpsChart.DrawDirection = widgets.DrawLeft
	rpsChart.AxesColor = ui.ColorWhite

	// Bot vs Human line chart
	botChart := widgets.NewPlot()
	botChart.Title = " 🤖 Bot%  [red=bot  cyan=human] "
	botChart.Data = [][]float64{
		make([]float64, 60),
		make([]float64, 60),
	}
	botChart.LineColors = []ui.Color{ui.ColorRed, ui.ColorCyan}
	botChart.DrawDirection = widgets.DrawLeft
	botChart.AxesColor = ui.ColorWhite

	// Err% gauge
	errGauge := widgets.NewGauge()
	errGauge.Title = " ✖ Error Rate "
	errGauge.BarColor = ui.ColorRed
	errGauge.LabelStyle = ui.NewStyle(ui.ColorWhite)

	// RT sparkline
	rtSpark := widgets.NewSparkline()
	rtSpark.LineColor = ui.ColorMagenta
	rtSpark.Data = make([]float64, 60)
	rtGroup := widgets.NewSparklineGroup(rtSpark)
	rtGroup.Title = " ⏱ Response Time (ms) "

	// Score gauge
	scoreGauge := widgets.NewGauge()
	scoreGauge.Title = " ⚠ Threat Score "
	scoreGauge.BarColor = ui.ColorYellow

	// IP table (persistent – rect set once in doLayout, rows updated in-place)
	ipTable := widgets.NewTable()
	ipTable.Title = " ◉ Top IPs — enriched "
	ipTable.RowSeparator = false
	ipTable.FillRow = true
	ipTable.BorderStyle = ui.NewStyle(ui.ColorCyan)
	ipTable.RowStyles = map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorCyan)}
	ipTable.ColumnWidths = []int{3, 16, 5, 40, 4, 5}
	fillIPTable(ipTable, nil)

	// Paths table (persistent)
	pathsTable := widgets.NewTable()
	pathsTable.Title = " ◎ Top Paths "
	pathsTable.RowSeparator = false
	pathsTable.FillRow = true
	pathsTable.BorderStyle = ui.NewStyle(ui.ColorYellow)
	pathsTable.RowStyles = map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow)}
	pathsTable.ColumnWidths = []int{3, 50, 6}
	fillPathsTable(pathsTable, nil)

	// Status bar
	statusBar := widgets.NewParagraph()
	statusBar.Border = false
	statusBar.TextStyle = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)

	// ── layout ───────────────────────────────────────────────────────────────

	var doLayout func()

	doLayout = func() {
		W, H = ui.TerminalDimensions()

		titleH  := 3
		chartH  := H / 3
		gaugeH  := 3
		statusH := 3
		tableH  := H - titleH - chartH - gaugeH*2 - statusH
		if tableH < 8 {
			tableH = 8
		}

		half := W / 2

		y0 := 0
		title.SetRect(0, y0, W, y0+titleH)

		y1 := y0 + titleH
		rpsChart.SetRect(0, y1, half, y1+chartH)
		botChart.SetRect(half, y1, W, y1+chartH)

		y2 := y1 + chartH
		errGauge.SetRect(0, y2, half, y2+gaugeH)
		scoreGauge.SetRect(half, y2, W, y2+gaugeH)

		y3 := y2 + gaugeH
		rtGroup.SetRect(0, y3, W, y3+gaugeH)

		yTable := y3 + gaugeH
		// left 60% → IPs, right 40% → paths
		ipSplit := W * 6 / 10
		ipTable.SetRect(0, yTable, ipSplit, yTable+tableH)
		pathsTable.SetRect(ipSplit, yTable, W, yTable+tableH)

		ys := yTable + tableH
		statusBar.SetRect(0, ys, W, ys+statusH)
	}

	doLayout()

	renderAll := func(snap liveSnapshot, lastErr error, tick int) {
		// title
		scoreStr := fmt.Sprintf("%.2f", snap.Score)
		reasons := "-"
		if len(snap.Reasons) > 0 {
			reasons = strings.Join(snap.Reasons, ", ")
		}
		statusStr := "● LIVE"
		if lastErr != nil {
			statusStr = "✖ API ERROR"
		}

		// challenge badge
		chalBadge := ""
		if snap.ChallengeActive {
			switch snap.ChallengeMode {
			case "manual":
				chalBadge = fmt.Sprintf("  [🔒 CHALLENGE manual expires=%s](fg:red,mod:bold)", snap.ChallengeExpiry)
			case "auto":
				chalBadge = "  [🔒 CHALLENGE auto](fg:yellow,mod:bold)"
			default:
				chalBadge = "  [🔒 CHALLENGE](fg:yellow,mod:bold)"
			}
		}

		title.Text = fmt.Sprintf(
			" [%s](fg:green) [%s](fg:white,mod:bold)%s   "+
				"score:[%s](fg:yellow)  err:[%.1f%%](fg:red)  rt:[%.3fs](fg:cyan)  "+
				"uniqIP:[%d](fg:white)  bot:[%.0f%%](fg:magenta)  reasons:[%s](fg:yellow)",
			statusStr, host, chalBadge,
			scoreStr,
			snap.Err, snap.RT,
			snap.UniqueIPs, snap.Bot,
			reasons,
		)

		// RPS chart - use ring slices
		chartW := (W / 2) - 4
		if chartW < 10 {
			chartW = 10
		}
		rpsChart.Data[0] = rb2xx.slice(chartW)
		rpsChart.Data[1] = rb4xx.slice(chartW)
		rpsChart.Data[2] = rb5xx.slice(chartW)
		_ = rbRPS
		_ = rb3xx

		// Bot chart
		botChart.Data[0] = rbBot.slice(chartW)
		botChart.Data[1] = rbHum.slice(chartW)

		// Err gauge (0-100)
		ep := int(clamp(snap.Err, 0, 100))
		errGauge.Percent = ep
		errGauge.Label = fmt.Sprintf("%.1f%%", snap.Err)
		errGauge.BarColor = errColor(snap.Err)

		// Score gauge (0-100)
		sp := int(clamp(snap.Score*100, 0, 100))
		scoreGauge.Percent = sp
		scoreGauge.Label = fmt.Sprintf("%.2f", snap.Score)
		scoreGauge.BarColor = scoreColor(snap.Score)

		// RT sparkline (convert to ms)
		rtSpark.Data = make([]float64, len(rbRT.slice(W-4)))
		for i, v := range rbRT.slice(W - 4) {
			rtSpark.Data[i] = v * 1000
		}
		maxRT := 0.0
		for _, v := range rtSpark.Data {
			if v > maxRT {
				maxRT = v
			}
		}
		rtGroup.Title = fmt.Sprintf(" ⏱ Response Time  cur=[%.0fms](fg:magenta)  max=[%.0fms](fg:red) ",
			snap.RT*1000, maxRT)

		// IP table — update rows in-place, rect stays from doLayout
		fillIPTable(ipTable, snap.EnrichedIPs)

		// Paths table — update rows in-place
		fillPathsTable(pathsTable, snap.TopPaths)

		// status bar
		ts := time.Now().Format("15:04:05")
		chalHint := "[c] challenge"
		if snap.ChallengeActive && snap.ChallengeMode == "manual" {
			chalHint = "[c] remove challenge"
		}
		statusBar.Text = fmt.Sprintf(
			" [q] quit  [r] refresh  [%s]  │  %s  │  tick #%d  │  RPS: %.2f",
			chalHint, ts, tick, snap.RPS,
		)

		ui.Clear()
		ui.Render(title, rpsChart, botChart, errGauge, scoreGauge, rtGroup, ipTable, pathsTable, statusBar)
	}

	// chalToggle adds or removes a manual 30m challenge for this vhost.
	chalToggle := func(snap liveSnapshot) {
		var err error
		if snap.ChallengeActive && snap.ChallengeMode == "manual" {
			// remove it
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/remove?host=%s", baseURL, url.QueryEscape(host))
			_, err = http.Post(u, "application/json", nil)
		} else {
			// add 30m manual challenge
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/add?host=%s&ttl=30m&reason=live_manual", baseURL, url.QueryEscape(host))
			_, err = http.Post(u, "application/json", nil)
		}
		_ = err
	}

	// ── initial fetch ─────────────────────────────────────────────────────────

	snap, fetchErr := fetchLiveSnapshot(baseURL, host)
	rbRPS.push(snap.RPS)
	rb2xx.push(snap.R2xx)
	rb3xx.push(snap.R3xx)
	rb4xx.push(snap.R4xx)
	rb5xx.push(snap.R5xx)
	rbErr.push(snap.Err)
	rbBot.push(clamp(snap.Bot, 0, 100))
	rbHum.push(clamp(100-snap.Bot, 0, 100))
	rbRT.push(snap.RT)
	renderAll(snap, fetchErr, 0)

	// ── event loop ────────────────────────────────────────────────────────────

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	uiEvents := ui.PollEvents()
	tickN := 0

	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "Q", "<C-c>":
				return nil
			case "c", "C":
				chalToggle(snap)
				// re-fetch immediately so the badge updates
				snap, fetchErr = fetchLiveSnapshot(baseURL, host)
				renderAll(snap, fetchErr, tickN)
			case "r", "R":
				// force refresh
				snap, fetchErr = fetchLiveSnapshot(baseURL, host)
				rbRPS.push(snap.RPS)
				rb2xx.push(snap.R2xx)
				rb3xx.push(snap.R3xx)
				rb4xx.push(snap.R4xx)
				rb5xx.push(snap.R5xx)
				rbErr.push(snap.Err)
				rbBot.push(clamp(snap.Bot, 0, 100))
				rbHum.push(clamp(100-snap.Bot, 0, 100))
				rbRT.push(snap.RT)
				renderAll(snap, fetchErr, tickN)
			case "<Resize>":
				doLayout()
				ui.Clear()
				renderAll(snap, fetchErr, tickN)
			}

		case <-tick.C:
			tickN++
			snap, fetchErr = fetchLiveSnapshot(baseURL, host)
			rbRPS.push(snap.RPS)
			rb2xx.push(snap.R2xx)
			rb3xx.push(snap.R3xx)
			rb4xx.push(snap.R4xx)
			rb5xx.push(snap.R5xx)
			rbErr.push(snap.Err)
			rbBot.push(clamp(snap.Bot, 0, 100))
			rbHum.push(clamp(100-snap.Bot, 0, 100))
			rbRT.push(snap.RT)
			renderAll(snap, fetchErr, tickN)
		}
	}
}

// ── live top ─────────────────────────────────────────────────────────────────

// sortKeys is the ordered list of sort modes the user can cycle through.
var sortKeys = []string{"rps", "err", "bot", "score", "4xx", "5xx", "rt"}

// RunLiveTop is `cfm webtop live` – a scrollable live vhost picker.
// Press ↑/↓ to move, Enter to drill into a vhost, s to cycle sort, q to quit.
func RunLiveTop(baseURL string, limit int) error {
	if limit <= 0 {
		limit = 20
	}
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	W, H := ui.TerminalDimensions()

	// ── widgets ──────────────────────────────────────────────────────────────

	header := widgets.NewParagraph()
	header.Border = true
	header.BorderStyle = ui.NewStyle(ui.ColorCyan)

	table := widgets.NewTable()
	table.Title = " ◈ Live Top Vhosts — ↑↓ navigate  Enter=drill  s=sort  q=quit "
	table.RowSeparator = false
	table.FillRow = true
	table.BorderStyle = ui.NewStyle(ui.ColorWhite)

	statusBar := widgets.NewParagraph()
	statusBar.Border = false
	statusBar.TextStyle = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)

	// ── layout ───────────────────────────────────────────────────────────────

	var doLayout func()
	doLayout = func() {
		W, H = ui.TerminalDimensions()
		header.SetRect(0, 0, W, 3)
		table.SetRect(0, 3, W, H-3)
		statusBar.SetRect(0, H-3, W, H)
	}
	doLayout()

	// ── state ─────────────────────────────────────────────────────────────────

	var (
		rows      []ShortRow // latest fetched rows (already sorted)
		cursor    int        // selected row index (0-based into rows)
		sortIdx   int        // index into sortKeys
		lastErr   error
		tickN     int
	)

	// colour helpers for inline markup
	colorForErr := func(v float64) string {
		switch {
		case v >= 30:
			return "red"
		case v >= 10:
			return "yellow"
		default:
			return "green"
		}
	}
	colorForBot := func(v float64) string {
		switch {
		case v >= 60:
			return "red"
		case v >= 25:
			return "yellow"
		default:
			return "cyan"
		}
	}
	colorForScore := func(v float64) string {
		switch {
		case v >= 0.7:
			return "red"
		case v >= 0.4:
			return "yellow"
		default:
			return "green"
		}
	}

	// fetchAndSort fetches top-short and sorts by current sort key.
	fetchAndSort := func() {
		u := fmt.Sprintf("%s/api/v1/webdet/top-short", baseURL)
		r, err := http.Get(u)
		if err != nil {
			lastErr = err
			return
		}
		defer r.Body.Close()
		var resp topShortCLIResponse
		if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
			lastErr = err
			return
		}
		lastErr = nil
		sortShortRows(resp.Rows, sortKeys[sortIdx])
		if limit > 0 && len(resp.Rows) > limit {
			resp.Rows = resp.Rows[:limit]
		}
		rows = resp.Rows
		// keep cursor in bounds
		if cursor >= len(rows) {
			cursor = len(rows) - 1
		}
		if cursor < 0 {
			cursor = 0
		}
	}

	// buildTableRows renders the rows slice into table widget rows.
	buildTableRows := func() {
		colW := W - 2
		// dynamic host column width (rest goes to metrics)
		metricsW := 85 // fixed metrics portion width
		hostW := colW - metricsW
		if hostW < 15 {
			hostW = 15
		}

		// header row
		hdr := []string{
			padRight(" VHOST", hostW),
			"  RPS ", " 2xx  ", " 4xx  ", " 5xx  ",
			" err% ", " bot% ", "  rt  ", "score ", " uniq ",
		}
		tableRows := [][]string{hdr}

		for i, row := range rows {
			host := row.Host
			if len(host) > hostW-1 {
				host = host[:hostW-3] + ".."
			}
			host = padRight(" "+host, hostW)

			tableRows = append(tableRows, []string{
				host,
				fmt.Sprintf("%6.2f", row.RPS),
				fmt.Sprintf("%6.2f", row.R2xx),
				fmt.Sprintf("%6.2f", row.R4xx),
				fmt.Sprintf("%6.2f", row.R5xx),
				fmt.Sprintf("%5.1f%%", row.ErrRatio*100),
				fmt.Sprintf("%5.1f%%", row.BotRatio*100),
				fmt.Sprintf("%5.0fms", row.ProcAvgSec*1000),
				fmt.Sprintf("%5.2f ", row.Score),
				fmt.Sprintf("%5d ", row.UniqueIPs),
			})

			// colour the selected row differently
			style := ui.NewStyle(ui.ColorWhite)
			if i+1 == cursor+1 { // +1 for header offset
				style = ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold)
			} else {
				// dim rows with high err or bot red
				_ = colorForErr(row.ErrRatio * 100)
				_ = colorForBot(row.BotRatio * 100)
				_ = colorForScore(row.Score)
			}
			table.RowStyles[i+1] = style
		}
		table.RowStyles[0] = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)
		table.ColumnWidths = []int{hostW, 7, 7, 7, 7, 7, 7, 7, 7, 7}
		table.Rows = tableRows
	}

	// renderAll redraws everything.
	renderAll := func() {
		ts := time.Now().Format("15:04:05")
		sortKey := sortKeys[sortIdx]
		statusStr := "● LIVE"
		if lastErr != nil {
			statusStr = fmt.Sprintf("✖ %s", lastErr)
		}
		selectedHost := "-"
		if len(rows) > 0 && cursor < len(rows) {
			selectedHost = rows[cursor].Host
		}

		header.Text = fmt.Sprintf(
			" [%s](fg:green)  sort:[%s](fg:yellow,mod:bold)  selected:[%s](fg:cyan,mod:bold)  "+
				"tick:[%d](fg:white)  [%s](fg:white)",
			statusStr, sortKey, selectedHost, tickN, ts,
		)

		buildTableRows()

		statusBar.Text = fmt.Sprintf(
			" [↑↓] navigate  [Enter] drill  [c] toggle challenge (30m)  [s] sort (%s)  [q] quit  │  top %d by %s",
			sortKey, limit, sortKey,
		)

		ui.Clear()
		ui.Render(header, table, statusBar)
	}

	// chalToggleSelected adds/removes a 30m manual challenge on the selected vhost.
	chalToggleSelected := func() {
		if len(rows) == 0 || cursor >= len(rows) {
			return
		}
		h := rows[cursor].Host
		// Check current status first
		active, _, _ := fetchChallengeStatus(baseURL, h)
		if active {
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/remove?host=%s", baseURL, url.QueryEscape(h))
			_, _ = http.Post(u, "application/json", nil)
		} else {
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/add?host=%s&ttl=30m&reason=live_manual", baseURL, url.QueryEscape(h))
			_, _ = http.Post(u, "application/json", nil)
		}
	}

	// ── initial load ──────────────────────────────────────────────────────────

	fetchAndSort()
	renderAll()

	// ── event loop ────────────────────────────────────────────────────────────

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	uiEvents := ui.PollEvents()

	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "Q", "<C-c>":
				return nil

			case "c", "C":
				chalToggleSelected()
				fetchAndSort()
				renderAll()

			case "<Up>", "k":
				if cursor > 0 {
					cursor--
				}
				renderAll()

			case "<Down>", "j":
				if cursor < len(rows)-1 {
					cursor++
				}
				renderAll()

			case "<Home>":
				cursor = 0
				renderAll()

			case "<End>":
				if len(rows) > 0 {
					cursor = len(rows) - 1
				}
				renderAll()

			case "<Enter>":
				if len(rows) == 0 || cursor >= len(rows) {
					continue
				}
				selectedHost := rows[cursor].Host
				// Tear down the top view, launch drilldown, then come back.
				ui.Close()
				err := RunLiveDrilldown(baseURL, selectedHost)
				// Re-init for the top view after returning.
				if initErr := ui.Init(); initErr != nil {
					return initErr
				}
				W, H = ui.TerminalDimensions()
				doLayout()
				if err != nil {
					lastErr = err
				}
				fetchAndSort()
				renderAll()

			case "s", "S":
				sortIdx = (sortIdx + 1) % len(sortKeys)
				fetchAndSort()
				renderAll()

			case "<Resize>":
				doLayout()
				renderAll()
			}

		case <-tick.C:
			tickN++
			fetchAndSort()
			renderAll()
		}
	}
}

// padRight pads or truncates s to exactly n runes.
func padRight(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	for len(r) < n {
		r = append(r, ' ')
	}
	return string(r)
}
