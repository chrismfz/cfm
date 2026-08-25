package webdetector

import (
	"bufio"
	"cfm/internal/clihttp"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

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

type liveSnapshot struct {
	RPS  float64
	R2xx float64
	R3xx float64
	R4xx float64
	R5xx float64
	Err  float64 // 0-100 %
	Bot  float64 // 0-100 %

	RT        float64
	Score     float64
	UniqueIPs int
	BotPct    float64
	HumanPct  float64

	EnrichedIPs []map[string]string
	TopPaths    []TopKV
	Reasons     []string

	ChallengeActive bool
	ChallengeMode   string // "manual" | "auto" | ""
	ChallengeExpiry string
}

func fetchLiveSnapshot(baseURL, host string) (liveSnapshot, error) {
	var snap liveSnapshot

	u1 := baseURL + "/api/v1/webdet/top-short"
	r1, err := clihttp.Get(u1)
	if err != nil {
		return snap, err
	}
	defer r1.Body.Close()
	if r1.StatusCode < 200 || r1.StatusCode >= 300 {
		return snap, fmt.Errorf("http %s", r1.Status)
	}

	var topResp topShortCLIResponse
	if err := json.NewDecoder(r1.Body).Decode(&topResp); err != nil {
		return snap, err
	}
	for _, row := range topResp.Rows {
		if strings.EqualFold(row.Host, host) {
			snap.RPS = row.RPS
			snap.R2xx = row.R2xx
			snap.R3xx = row.R3xx
			snap.R4xx = row.R4xx
			snap.R5xx = row.R5xx
			snap.Err = row.ErrRatio * 100
			snap.Bot = row.BotRatio * 100
			snap.Score = row.Score
			snap.Reasons = row.Reasons
			snap.UniqueIPs = row.UniqueIPs
			break
		}
	}

	u2 := baseURL + "/api/v1/webdet/drilldown?host=" + url.QueryEscape(host) + "&top=25"
	r2, err := clihttp.Get(u2)
	if err != nil {
		return snap, err
	}
	defer r2.Body.Close()
	if r2.StatusCode < 200 || r2.StatusCode >= 300 {
		return snap, fmt.Errorf("http %s", r2.Status)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r2.Body).Decode(&raw); err != nil {
		return snap, err
	}
	var detail HostDetail
	if b, ok := raw["short"]; ok {
		_ = json.Unmarshal(b, &detail)
	}
	snap.RT = detail.ProcAvgSec
	snap.BotPct = detail.BotPct
	snap.HumanPct = math.Max(0, 100-detail.BotPct)
	snap.EnrichedIPs = detail.EnrichedTopIPs
	snap.TopPaths = detail.TopPaths
	if snap.Score == 0 {
		snap.Score = detail.ShortScore
	}
	if len(snap.Reasons) == 0 {
		snap.Reasons = detail.ShortReasons
	}

	snap.ChallengeActive, snap.ChallengeMode, snap.ChallengeExpiry, err = fetchChallengeStatus(baseURL, host)
	if err != nil {
		return snap, err
	}

	return snap, nil
}

func fetchChallengeStatus(baseURL, host string) (active bool, mode, expiry string, err error) {
	u := fmt.Sprintf("%s/api/v1/challenge/vhost/status?host=%s", baseURL, url.QueryEscape(host))
	r, err := clihttp.Get(u)
	if err != nil {
		return
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		err = fmt.Errorf("http %s", r.Status)
		return
	}

	var result map[string]interface{}
	if decodeErr := json.NewDecoder(r.Body).Decode(&result); decodeErr != nil {
		err = decodeErr
		return
	}
	manualActive, _ := result["manual_active"].(bool)
	autoActive, _ := result["auto_active"].(bool)
	expiresAt, _ := result["expires_at"].(string)

	if manualActive {
		active = true
		mode = "manual"
		// Show the remaining window, not a bare HH:MM:SS. Slicing [11:19] off
		// the RFC3339 string dropped the date, so a >24h manual TTL (e.g. 34h)
		// read as "expires in a few hours" when it was actually tomorrow.
		if t, perr := time.Parse(time.RFC3339, expiresAt); perr == nil {
			expiry = leftDuration(t)
		} else {
			// Unparseable expiry: show "?" rather than an absolute timestamp,
			// which the badge would mislabel as a remaining duration (left=).
			expiry = "?"
		}
	} else if autoActive {
		active = true
		mode = "auto"
	}
	return
}

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

func fillIPTable(t *widgets.Table, ips []map[string]string, tableW int, ipCursor int) {
	// Better width budget:
	// # | IP | Reqs | PTR | ASN | CC | Score
	const (
		numW   = 3
		ipW    = 16
		reqW   = 6
		ccW    = 6
		scoreW = 5
	)
	const overhead = 10

	fixed := numW + ipW + reqW + ccW + scoreW + overhead
	flex := tableW - fixed
	if flex < 28 {
		flex = 28
	}

	ptrW := flex * 42 / 100
	asnW := flex - ptrW
	if ptrW < 12 {
		ptrW = 12
	}
	if asnW < 16 {
		asnW = 16
	}

	header := []string{"#", "IP", "Reqs", "PTR", "ASN", "CC", "Score"}
	rows := [][]string{header}

	for i, row := range ips {
		ip := row["ip"]
		count := row["count"]
		ptr := row["ptr"]
		asn := row["asn"]
		asnNm := row["asn_name"]
		cc := row["country"]
		score := row["score"]

		if len(ptr) > ptrW {
			ptr = ptr[:ptrW-2] + ".."
		}

		asFull := strings.TrimSpace(func() string {
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
		if len(asFull) > asnW {
			asFull = asFull[:asnW-2] + ".."
		}

		if len(cc) > ccW {
			cc = cc[:ccW-2] + ".."
		}

		scoreStr := score
		if scoreStr == "" {
			scoreStr = "-"
		}
		if len(scoreStr) > scoreW {
			scoreStr = scoreStr[:scoreW]
		}

		rows = append(rows, []string{
			fmt.Sprintf("%2d", i+1),
			ip,
			count,
			ptr,
			asFull,
			cc,
			scoreStr,
		})
	}

	for len(rows) < 6 {
		rows = append(rows, []string{"", "", "", "", "", "", ""})
	}

	t.Rows = rows
	t.ColumnWidths = []int{numW, ipW, reqW, ptrW, asnW, ccW, scoreW}
	t.RowStyles = map[int]ui.Style{
		0: ui.NewStyle(ui.ColorBlack, ui.ColorCyan),
	}
	if ipCursor >= 0 && ipCursor+1 < len(rows) {
		t.RowStyles[ipCursor+1] = ui.NewStyle(ui.ColorBlack, ui.ColorWhite, ui.ModifierBold)
	}
}

func fillPathsTable(t *widgets.Table, paths []TopKV, tableW int) {
	pathW := tableW - 3 - 6 - 8
	if pathW < 20 {
		pathW = 20
	}

	header := []string{"#", "Path", "Hits"}
	rows := [][]string{header}

	for i, p := range paths {
		path := p.Key
		if len(path) > pathW {
			path = path[:pathW-2] + ".."
		}
		rows = append(rows, []string{
			fmt.Sprintf("%2d", i+1),
			path,
			fmt.Sprintf("%d", p.Count),
		})
	}
	for len(rows) < 6 {
		rows = append(rows, []string{"", "", ""})
	}
	t.Rows = rows
	t.ColumnWidths = []int{3, pathW, 6}
}

func blockIPLive(ip string) string {
	if ip == "" {
		return "no IP selected"
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "cfm"
	}
	cmd := exec.Command(exe, "block", ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("block %s FAILED: %v", ip, err)
	}
	msg := strings.TrimSpace(string(out))
	if len(msg) > 60 {
		msg = msg[:58] + ".."
	}
	return "✔ blocked " + ip + "  " + msg
}

func RunLiveDrilldown(baseURL, host string) error {
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	var (
		rbRPS ringBuf
		rb2xx ringBuf
		rb3xx ringBuf
		rb4xx ringBuf
		rb5xx ringBuf
		rbErr ringBuf
		rbBot ringBuf
		rbHum ringBuf
		rbRT  ringBuf
	)

	W, H := ui.TerminalDimensions()

	title := widgets.NewParagraph()
	title.Border = true
	title.BorderStyle = ui.NewStyle(ui.ColorCyan)

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

	botChart := widgets.NewPlot()
	botChart.Title = " 🤖 Bot%  [red=bot  cyan=human] "
	botChart.Data = [][]float64{
		make([]float64, 60),
		make([]float64, 60),
	}
	botChart.LineColors = []ui.Color{ui.ColorRed, ui.ColorCyan}
	botChart.DrawDirection = widgets.DrawLeft
	botChart.AxesColor = ui.ColorWhite

	errGauge := widgets.NewGauge()
	errGauge.Title = " ✖ Error Rate "
	errGauge.BarColor = ui.ColorRed
	errGauge.LabelStyle = ui.NewStyle(ui.ColorWhite)

	rtSpark := widgets.NewSparkline()
	rtSpark.LineColor = ui.ColorMagenta
	rtSpark.Data = make([]float64, 60)
	rtGroup := widgets.NewSparklineGroup(rtSpark)
	rtGroup.Title = " ⏱ Response Time (ms) "

	scoreGauge := widgets.NewGauge()
	scoreGauge.Title = " ⚠ Threat Score "
	scoreGauge.BarColor = ui.ColorYellow

	ipTable := widgets.NewTable()
	ipTable.Title = " ◉ Top IPs — ↑↓ navigate  b=block "
	ipTable.RowSeparator = false
	ipTable.FillRow = true
	ipTable.BorderStyle = ui.NewStyle(ui.ColorCyan)
	fillIPTable(ipTable, nil, 60, -1)

	pathsTable := widgets.NewTable()
	pathsTable.Title = " ◎ Top Paths "
	pathsTable.RowSeparator = false
	pathsTable.FillRow = true
	pathsTable.BorderStyle = ui.NewStyle(ui.ColorYellow)
	pathsTable.RowStyles = map[int]ui.Style{0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow)}
	fillPathsTable(pathsTable, nil, 40)

	statusBar := widgets.NewParagraph()
	statusBar.Border = false
	statusBar.TextStyle = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)

	ipCursor := -1
	lastBlockMsg := ""

	var (
		ipTableW int
		ipLimit  int
	)
	var doLayout func()

	doLayout = func() {
		W, H = ui.TerminalDimensions()

		titleH := 3
		chartH := H / 3
		gaugeH := 3
		statusH := 3
		tableH := H - titleH - chartH - gaugeH*2 - statusH
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
		ipSplit := W * 6 / 10
		ipTable.SetRect(0, yTable, ipSplit, yTable+tableH)
		pathsTable.SetRect(ipSplit, yTable, W, yTable+tableH)

		ys := yTable + tableH
		statusBar.SetRect(0, ys, W, ys+statusH)

		ipTableW = ipSplit - 2

		ipLimit = tableH - 2
		if ipLimit < 5 {
			ipLimit = 5
		}
		if ipLimit > 40 {
			ipLimit = 40
		}

		if ipCursor >= ipLimit {
			ipCursor = ipLimit - 1
		}
	}

	doLayout()

	renderAll := func(snap liveSnapshot, lastErr error, tick int) {
		scoreStr := fmt.Sprintf("%.2f", snap.Score)
		reasons := "-"
		if len(snap.Reasons) > 0 {
			reasons = strings.Join(snap.Reasons, ", ")
		}
		statusStr := "● LIVE"
		if lastErr != nil {
			statusStr = fmt.Sprintf("✖ %s", lastErr)
		}

		chalBadge := ""
		if snap.ChallengeActive {
			switch snap.ChallengeMode {
			case "manual":
				chalBadge = fmt.Sprintf("  [🔒 CHALLENGE manual left=%s](fg:red,mod:bold)", snap.ChallengeExpiry)
			case "auto":
				chalBadge = "  [🔒 CHALLENGE auto](fg:yellow,mod:bold)"
			default:
				chalBadge = "  [🔒 CHALLENGE](fg:yellow,mod:bold)"
			}
		}

		title.Text = fmt.Sprintf(
			" [%s](fg:green) [%s](fg:white,mod:bold)%s   score:[%s](fg:yellow)  err:[%.1f%%](fg:red)  rt:[%.3fs](fg:cyan)  uniqIP:[%d](fg:white)  bot:[%.0f%%](fg:magenta)  reasons:[%s](fg:yellow)",
			statusStr, host, chalBadge, scoreStr, snap.Err, snap.RT, snap.UniqueIPs, snap.Bot, reasons,
		)

		chartW := (W / 2) - 4
		if chartW < 10 {
			chartW = 10
		}
		rpsChart.Data[0] = rb2xx.slice(chartW)
		rpsChart.Data[1] = rb4xx.slice(chartW)
		rpsChart.Data[2] = rb5xx.slice(chartW)
		_ = rbRPS
		_ = rb3xx

		botChart.Data[0] = rbBot.slice(chartW)
		botChart.Data[1] = rbHum.slice(chartW)

		ep := int(clamp(snap.Err, 0, 100))
		errGauge.Percent = ep
		errGauge.Label = fmt.Sprintf("%.1f%%", snap.Err)
		errGauge.BarColor = errColor(snap.Err)

		sp := int(clamp(snap.Score*100, 0, 100))
		scoreGauge.Percent = sp
		scoreGauge.Label = fmt.Sprintf("%.2f", snap.Score)
		scoreGauge.BarColor = scoreColor(snap.Score)

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
		rtGroup.Title = fmt.Sprintf(" ⏱ Response Time  cur=[%.0fms](fg:magenta)  max=[%.0fms](fg:red) ", snap.RT*1000, maxRT)

		ipSlice := snap.EnrichedIPs
		if len(ipSlice) > ipLimit {
			ipSlice = ipSlice[:ipLimit]
		}
		fillIPTable(ipTable, ipSlice, ipTableW, ipCursor)

		pathTableW := W - (W * 6 / 10) - 2
		fillPathsTable(pathsTable, snap.TopPaths, pathTableW)

		ts := time.Now().Format("15:04:05")
		chalHint := "[c] challenge"
		if snap.ChallengeActive && snap.ChallengeMode == "manual" {
			chalHint = "[c] remove challenge"
		}
		ipHint := "[↑↓] navigate IPs  [b] block"
		if ipCursor >= 0 && ipCursor < len(snap.EnrichedIPs) {
			ipHint = fmt.Sprintf("[↑↓] IP#%d: %s  [b] block", ipCursor+1, snap.EnrichedIPs[ipCursor]["ip"])
		}
		blockLine := ""
		if lastBlockMsg != "" {
			blockLine = "  │  " + lastBlockMsg
		}
		statusBar.Text = fmt.Sprintf(
			" [q] quit  [r] refresh  [%s]  │  %s  │  %s%s  │  tick #%d",
			chalHint, ipHint, ts, blockLine, tick,
		)

		ui.Clear()
		ui.Render(title, rpsChart, botChart, errGauge, scoreGauge, rtGroup, ipTable, pathsTable, statusBar)
	}

	chalToggle := func(snap liveSnapshot) {
		if snap.ChallengeActive && snap.ChallengeMode == "manual" {
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/remove?host=%s", baseURL, url.QueryEscape(host))
			_, _ = clihttp.Post(u, "application/json", nil)
		} else {
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/add?host=%s&ttl=30m&reason=live_manual", baseURL, url.QueryEscape(host))
			_, _ = clihttp.Post(u, "application/json", nil)
		}
	}

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
				snap, fetchErr = fetchLiveSnapshot(baseURL, host)
				renderAll(snap, fetchErr, tickN)
			case "<Up>", "k":
				if ipCursor < 0 {
					ipCursor = 0
				} else if ipCursor > 0 {
					ipCursor--
				}
				renderAll(snap, fetchErr, tickN)
			case "<Down>", "j":
				maxIdx := len(snap.EnrichedIPs) - 1
				if maxIdx > ipLimit-1 {
					maxIdx = ipLimit - 1
				}
				if ipCursor < maxIdx {
					ipCursor++
				} else if ipCursor < 0 {
					ipCursor = 0
				}
				renderAll(snap, fetchErr, tickN)
			case "b", "B":
				if ipCursor >= 0 && ipCursor < len(snap.EnrichedIPs) {
					ip := snap.EnrichedIPs[ipCursor]["ip"]
					lastBlockMsg = blockIPLive(ip)
				} else {
					lastBlockMsg = "select an IP first (↑↓)"
				}
				renderAll(snap, fetchErr, tickN)
			case "r", "R":
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

var sortKeys = []string{"rps", "uniq", "err", "bot", "score", "4xx", "5xx", "rt"}

// challLite is the subset of a /challenge/vhosts row the live TUI needs: the CH
// indicator up top, and — merged with the suspicious list — a challenged vhost's
// row (auto or manual) in the bottom attention panel, carrying its shadow signals.
type challLite struct {
	host    string // original-case host (the map key is lowercased)
	mode    string // auto|manual
	score   float64
	rps     float64
	uniq    int
	reasons []string
	facet   int // query_cardinality
	cost    int // cost_pressure (5xx %)
	dc      int // dc_fraction (%)
	shadow  int // shadow_outliers
	farm    bool
}

// sigLetters renders a compact fixed-slot facet/cost/dc/shadow presence cell for
// the top panel's SIG column: each slot is the signal's letter when active, else
// '·', so the column scans vertically (a signal is always in the same position).
func sigLetters(facet, cost, dc, shadow int) string {
	// []rune, not []byte: '·' (U+00B7) is 2 bytes in UTF-8, so byte-indexing would
	// corrupt the cell — write runes by position instead.
	r := []rune("····")
	if facet > 0 {
		r[0] = 'f'
	}
	if cost > 0 {
		r[1] = 'c'
	}
	if dc > 0 {
		r[2] = 'd'
	}
	if shadow > 0 {
		r[3] = 's'
	}
	return string(r)
}

// sigTokens returns the shadow-signal reason tokens for the bottom attention
// panel's REASONS column (farm + the three new signals + the rate-outlier count),
// appended after the score reasons. Empty slice when nothing is active.
func sigTokens(facet, cost, dc, shadow int, farm bool) []string {
	var t []string
	if farm {
		t = append(t, "farm")
	}
	if facet > 0 {
		t = append(t, fmt.Sprintf("facet=%d", facet))
	}
	if cost > 0 {
		t = append(t, fmt.Sprintf("cost=%d%%", cost))
	}
	if dc > 0 {
		t = append(t, fmt.Sprintf("dc=%d%%", dc))
	}
	if shadow > 0 {
		t = append(t, fmt.Sprintf("shadow=%d", shadow))
	}
	return t
}

func RunLiveTop(baseURL string, limit int) error {
	if limit <= 0 {
		limit = 25
	}
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	W, H := ui.TerminalDimensions()

	header := widgets.NewParagraph()
	header.Border = true
	header.BorderStyle = ui.NewStyle(ui.ColorCyan)

	table := widgets.NewTable()
	table.Title = " ◈ Live Top Vhosts — ↑↓ navigate  Enter=vhost  s=sort  x=bottom  q=quit "
	table.RowSeparator = false
	table.FillRow = true
	table.BorderStyle = ui.NewStyle(ui.ColorWhite)

	bottomPanel := widgets.NewTable()
	bottomPanel.Title = " ◉ Global Top IPs — j/k navigate  l=drill  b=block  x=toggle "
	bottomPanel.RowSeparator = false
	bottomPanel.FillRow = true
	bottomPanel.BorderStyle = ui.NewStyle(ui.ColorCyan)
	fillIPTable(bottomPanel, nil, 60, -1)

	statusBar := widgets.NewParagraph()
	statusBar.Border = false
	statusBar.TextStyle = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)

	var (
		bottomPanelW   int
		bottomPanelLim int
	)

	var doLayout func()
	doLayout = func() {
		W, H = ui.TerminalDimensions()

		splitY := H * 60 / 100
		if splitY < 8 {
			splitY = 8
		}
		if H-splitY < 8 {
			splitY = H - 8
		}

		header.SetRect(0, 0, W, 3)
		table.SetRect(0, 3, W, splitY)
		bottomPanel.SetRect(0, splitY, W, H-4)
		statusBar.SetRect(0, H-4, W, H)

		bottomPanelW = W - 2
		bottomPanelLim = (H - 4 - splitY) - 2
		if bottomPanelLim < 5 {
			bottomPanelLim = 5
		}
		if bottomPanelLim > 20 {
			bottomPanelLim = 20
		}
	}
	doLayout()

	var (
		rows         []ShortRow
		challenged   map[string]challLite
		globalIPs    []map[string]string
		suspicious   []SuspiciousRow
		suspMap      map[string]SuspiciousRow
		bottomMode   string
		ipCursor     int
		lastBlockMsg string
		cursor       int
		sortIdx      int
		lastErr      error
		tickN        int
	)
	ipCursor = -1
	bottomMode = "ips"

	fetchChallenged := func() (map[string]challLite, error) {
		u := fmt.Sprintf("%s/api/v1/challenge/vhosts?status=active&limit=500", baseURL)
		r, err := clihttp.Get(u)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		if r.StatusCode < 200 || r.StatusCode >= 300 {
			return nil, fmt.Errorf("http %s", r.Status)
		}

		var vhs []struct {
			Host             string   `json:"host"`
			Mode             string   `json:"mode"`
			Score            float64  `json:"score"`
			RPS              float64  `json:"rps"`
			UniqIP           int      `json:"uniq_ip"`
			Reasons          []string `json:"reasons"`
			QueryCardinality int      `json:"query_cardinality"`
			CostPressure     int      `json:"cost_pressure"`
			DCFraction       int      `json:"dc_fraction"`
			ShadowOutliers   int      `json:"shadow_outliers"`
			SolverFarm       bool     `json:"solver_farm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&vhs); err != nil {
			return nil, err
		}
		// Keyed lowercase to join cleanly with suspMap (also lowercased) — a
		// case-inconsistent join here would double-list a challenged vhost in the
		// bottom panel (CLAUDE.md §6). The original-case host rides along for display.
		m := make(map[string]challLite, len(vhs))
		for _, v := range vhs {
			m[strings.ToLower(v.Host)] = challLite{
				host: v.Host, mode: v.Mode, score: v.Score, rps: v.RPS, uniq: v.UniqIP,
				reasons: v.Reasons, facet: v.QueryCardinality, cost: v.CostPressure,
				dc: v.DCFraction, shadow: v.ShadowOutliers, farm: v.SolverFarm,
			}
		}
		return m, nil
	}

	fetchGlobalIPs := func() ([]map[string]string, error) {
		u := fmt.Sprintf("%s/api/v1/webdet/hot-ips?limit=50", baseURL)
		r, err := clihttp.Get(u)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		if r.StatusCode < 200 || r.StatusCode >= 300 {
			return nil, fmt.Errorf("http %s", r.Status)
		}

		var rows []struct {
			IP      string `json:"ip"`
			Req     int    `json:"req"`
			Vhosts  int    `json:"vhosts"`
			PTR     string `json:"ptr"`
			ASN     string `json:"asn"`
			ASNName string `json:"asn_name"`
			Country string `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
			return nil, err
		}

		out := make([]map[string]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, map[string]string{
				"ip":       r.IP,
				"count":    fmt.Sprintf("%d", r.Req),
				"ptr":      r.PTR,
				"asn":      r.ASN,
				"asn_name": r.ASNName,
				"country":  r.Country,
			})
		}
		return out, nil
	}

	fetchSuspicious := func() ([]SuspiciousRow, map[string]SuspiciousRow, error) {
		u := fmt.Sprintf("%s/api/v1/webdet/suspicious", baseURL)
		r, err := clihttp.Get(u)
		if err != nil {
			return nil, nil, err
		}
		defer r.Body.Close()
		if r.StatusCode < 200 || r.StatusCode >= 300 {
			return nil, nil, fmt.Errorf("http %s", r.Status)
		}

		var rows []SuspiciousRow
		if err := json.NewDecoder(r.Body).Decode(&rows); err != nil {
			return nil, nil, err
		}

		m := make(map[string]SuspiciousRow, len(rows))
		for _, s := range rows {
			m[strings.ToLower(s.Host)] = s
		}
		return rows, m, nil
	}

	fetchAndSort := func() {
		u := fmt.Sprintf("%s/api/v1/webdet/top-short", baseURL)
		r, err := clihttp.Get(u)
		if err != nil {
			lastErr = err
			return
		}
		defer r.Body.Close()
		if r.StatusCode < 200 || r.StatusCode >= 300 {
			lastErr = fmt.Errorf("http %s", r.Status)
			return
		}

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

		if cursor >= len(rows) {
			cursor = len(rows) - 1
		}
		if cursor < 0 {
			cursor = 0
		}

		challenged, err = fetchChallenged()
		if err != nil {
			lastErr = fmt.Errorf("challenge vhosts: %w", err)
		}
		globalIPs, err = fetchGlobalIPs()
		if err != nil {
			lastErr = fmt.Errorf("hot ips: %w", err)
		}
		suspicious, suspMap, err = fetchSuspicious()
		if err != nil {
			lastErr = fmt.Errorf("suspicious: %w", err)
		}

		if ipCursor >= len(globalIPs) {
			ipCursor = len(globalIPs) - 1
		}
	}

	buildTableRows := func() {
		colW := W - 2
		metricsW := 98 // +6 for the SIG column
		hostW := colW - metricsW
		if hostW < 15 {
			hostW = 15
		}

		hdr := []string{
			padRight(" VHOST", hostW),
			" CH ",
			"SUP ",
			" SIG  ",
			"  RPS ",
			" 2xx  ",
			" 4xx  ",
			" 5xx  ",
			" err% ",
			" bot% ",
			"  rt  ",
			"score ",
			" uniq ",
		}
		tableRows := [][]string{hdr}
		table.RowStyles = map[int]ui.Style{}

		for i, row := range rows {
			chalMode := challenged[strings.ToLower(row.Host)].mode

			host := row.Host
			maxHost := hostW - 1
			if len(host) > maxHost {
				host = host[:maxHost-2] + ".."
			}
			host = padRight(" "+host, hostW)

			chalCell := "    "
			if chalMode == "manual" {
				chalCell = " 🔒M"
			} else if chalMode == "auto" {
				chalCell = " 🔒A"
			}

			suspCell := "   "
			if s, ok := suspMap[strings.ToLower(row.Host)]; ok {
				switch {
				case s.Score >= 0.70:
					suspCell = " !!"
				case s.Score >= 0.40:
					suspCell = "  !"
				default:
					suspCell = "  ?"
				}
			}
			// challenge_solver_farm currently sees a distributed solver farm on
			// this vhost. It goes in the leading slot of the already-reserved SUP
			// cell rather than a new column, so the layout is unchanged — and it
			// is orthogonal to the score beside it: a farm solves the challenge
			// correctly, so it need not score suspicious at all.
			if row.SolverFarm {
				suspCell = "F" + suspCell[1:]
			}
			// SIG: a compact fixed-slot presence cell for the shadow signals —
			// f=facet(query_cardinality) c=cost(5xx) d=dc(datacenter frac)
			// s=shadow(rate-outlier). The exact numbers are in the bottom
			// Suspicious+Challenged panel, `cfm webtop challenge`, and cfm-admin.
			sigCell := " " + sigLetters(row.QueryCardinality, row.CostPressure, row.DCFraction, row.ShadowOutliers) + " "

			tableRows = append(tableRows, []string{
				host,
				chalCell,
				suspCell,
				sigCell,
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

			var style ui.Style
			if i+1 == cursor+1 {
				style = ui.NewStyle(ui.ColorBlack, ui.ColorCyan, ui.ModifierBold)
			} else if chalMode != "" {
				style = ui.NewStyle(ui.ColorYellow)
			} else if row.ErrRatio >= 0.3 || row.Score >= 0.7 {
				style = ui.NewStyle(ui.ColorRed)
			} else if row.ErrRatio >= 0.1 || row.Score >= 0.4 {
				style = ui.NewStyle(ui.ColorYellow)
			} else {
				style = ui.NewStyle(ui.ColorWhite)
			}
			table.RowStyles[i+1] = style
		}

		table.RowStyles[0] = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)
		table.ColumnWidths = []int{hostW, 5, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7}
		table.Rows = tableRows
	}

	buildSuspiciousPanel := func() {
		panelW := W - 2
		hostW := 28
		chW := 3
		scoreW := 6
		errW := 6
		botW := 6
		uniqW := 6
		reasonW := panelW - hostW - chW - scoreW - errW - botW - uniqW - 14
		if reasonW < 18 {
			reasonW = 18
		}

		// Unified attention list: suspicious ∪ challenged (auto/manual), deduped by
		// lowercased host — the same merge cfm-admin's "Suspicious + challenged" card
		// does. A challenged-only vhost (not scored suspicious) still appears, with
		// its shadow signals; it has no err/bot sample of its own, shown as "-".
		type attn struct {
			host                    string
			chal                    string // "", auto, manual
			score, errPct, botPct   float64
			hasEB                   bool // err/bot known (suspicious rows only)
			uniq                    int
			reasons                 []string
			facet, cost, dc, shadow int
			farm                    bool
		}
		seen := make(map[string]bool, len(suspicious))
		list := make([]attn, 0, len(suspicious)+len(challenged))
		for _, s := range suspicious {
			lc := strings.ToLower(s.Host)
			seen[lc] = true
			list = append(list, attn{
				host: s.Host, chal: challenged[lc].mode, score: s.Score,
				errPct: s.ErrRatio * 100, botPct: s.BotRatio * 100, hasEB: true,
				uniq: s.UniqueIPs, reasons: s.Reasons, facet: s.QueryCardinality,
				cost: s.CostPressure, dc: s.DCFraction, shadow: s.ShadowOutliers, farm: s.SolverFarm,
			})
		}
		for lc, c := range challenged {
			if seen[lc] {
				continue
			}
			list = append(list, attn{
				host: c.host, chal: c.mode, score: c.score, hasEB: false,
				uniq: c.uniq, reasons: c.reasons, facet: c.facet, cost: c.cost,
				dc: c.dc, shadow: c.shadow, farm: c.farm,
			})
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].score > list[j].score })

		rows2 := [][]string{
			{"HOST", "CH", "SCORE", "ERR%", "BOT%", "UNIQ", "REASONS"},
		}
		maxRows := bottomPanelLim
		for i, a := range list {
			if i >= maxRows {
				break
			}
			host := a.host
			if len(host) > hostW {
				host = host[:hostW-2] + ".."
			}
			ch := ""
			switch a.chal {
			case "manual":
				ch = "M"
			case "auto":
				ch = "A"
			}
			errStr, botStr := "-", "-"
			if a.hasEB {
				errStr = fmt.Sprintf("%.1f", a.errPct)
				botStr = fmt.Sprintf("%.1f", a.botPct)
			}
			// score reasons first, then the shadow-signal tokens (farm/facet/cost/dc/shadow).
			merged := append(append([]string{}, a.reasons...), sigTokens(a.facet, a.cost, a.dc, a.shadow, a.farm)...)
			rs := joinReasons(merged)
			if len(rs) > reasonW {
				rs = rs[:reasonW-2] + ".."
			}
			rows2 = append(rows2, []string{
				host, ch, fmt.Sprintf("%.2f", a.score), errStr, botStr,
				fmt.Sprintf("%d", a.uniq), rs,
			})
		}
		for len(rows2) < maxRows+1 {
			rows2 = append(rows2, []string{"", "", "", "", "", "", ""})
		}

		bottomPanel.Title = " ⚠ Suspicious + Challenged — x=toggle "
		bottomPanel.Rows = rows2
		bottomPanel.ColumnWidths = []int{hostW, chW, scoreW, errW, botW, uniqW, reasonW}
		bottomPanel.RowStyles = map[int]ui.Style{
			0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow),
		}
		for i, a := range list {
			if i >= maxRows {
				break
			}
			switch {
			case a.score >= 0.70 || (a.hasEB && a.errPct >= 50):
				bottomPanel.RowStyles[i+1] = ui.NewStyle(ui.ColorRed)
			case a.score >= 0.40 || (a.hasEB && a.errPct >= 20):
				bottomPanel.RowStyles[i+1] = ui.NewStyle(ui.ColorYellow)
			default:
				bottomPanel.RowStyles[i+1] = ui.NewStyle(ui.ColorWhite)
			}
		}
	}

	renderAll := func() {
		ts := time.Now().Format("15:04:05")
		sortKey := sortKeys[sortIdx]
		statusStr := "● LIVE"
		if lastErr != nil {
			statusStr = fmt.Sprintf("✖ %s", lastErr)
		}

		selectedHost := "-"
		selectedChal := ""
		if len(rows) > 0 && cursor < len(rows) {
			selectedHost = rows[cursor].Host
			selectedChal = challenged[strings.ToLower(selectedHost)].mode
		}

		chalBadge := ""
		switch selectedChal {
		case "manual":
			chalBadge = "  [🔒 CHALLENGED manual](fg:red,mod:bold)"
		case "auto":
			chalBadge = "  [🔒 CHALLENGED auto](fg:yellow,mod:bold)"
		}

		header.Text = fmt.Sprintf(
			" [%s](fg:green)  sort:[%s](fg:yellow,mod:bold)  bottom:[%s](fg:cyan)  vhost:[%s](fg:cyan,mod:bold)%s  tick:[%d](fg:white)  [%s](fg:white)",
			statusStr, sortKey, bottomMode, selectedHost, chalBadge, tickN, ts,
		)

		buildTableRows()

		if bottomMode == "susp" {
			buildSuspiciousPanel()
		} else {
			bottomPanel.Title = " ◉ Global Top IPs — j/k navigate  l=drill  b=block  x=toggle "
			ipSlice := globalIPs
			if len(ipSlice) > bottomPanelLim {
				ipSlice = ipSlice[:bottomPanelLim]
			}
			fillIPTable(bottomPanel, ipSlice, bottomPanelW, ipCursor)
		}

		chalHint := "[c] challenge"
		if selectedChal == "manual" {
			chalHint = "[c] remove challenge"
		} else if selectedChal == "auto" {
			chalHint = "[c] add manual"
		}

		ipHint := "[j/k] navigate IPs  [l] drill  [b] block"
		if bottomMode == "ips" && ipCursor >= 0 && ipCursor < len(globalIPs) {
			ipHint = fmt.Sprintf("[j/k] IP#%d: %s  [l] drill  [b] block", ipCursor+1, globalIPs[ipCursor]["ip"])
		}
		if bottomMode == "susp" {
			ipHint = "[x] switch to IPs"
		}

		blockLine := ""
		if lastBlockMsg != "" {
			blockLine = "  │  " + lastBlockMsg
		}

		legend := "[cyan]=selected  [yellow]=warn/challenged  [red]=high-risk  SUP: !=suspect !!=strong F=farm  SIG: f=facet c=cost d=dc s=shadow"
		statusBar.Text = fmt.Sprintf(
			" [↑↓] vhosts  [Enter] drill  [%s]  [s] sort(%s)  [x] bottom(%s)  │  %s%s  [q] quit\n %s",
			chalHint, sortKey, bottomMode, ipHint, blockLine, legend,
		)

		ui.Clear()
		ui.Render(header, table, bottomPanel, statusBar)
	}

	chalToggleSelected := func() {
		if len(rows) == 0 || cursor >= len(rows) {
			return
		}
		h := rows[cursor].Host
		mode := challenged[strings.ToLower(h)].mode
		if mode == "manual" {
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/remove?host=%s", baseURL, url.QueryEscape(h))
			_, _ = clihttp.Post(u, "application/json", nil)
		} else {
			u := fmt.Sprintf("%s/api/v1/challenge/vhost/add?host=%s&ttl=30m&reason=live_manual", baseURL, url.QueryEscape(h))
			_, _ = clihttp.Post(u, "application/json", nil)
		}
	}

	fetchAndSort()
	renderAll()

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

			case "<Up>":
				if cursor > 0 {
					cursor--
				}
				renderAll()

			case "<Down>":
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

			case "k":
				if bottomMode != "ips" {
					continue
				}
				if ipCursor <= 0 {
					ipCursor = 0
				} else {
					ipCursor--
				}
				renderAll()

			case "j":
				if bottomMode != "ips" {
					continue
				}
				maxIP := len(globalIPs) - 1
				if maxIP > bottomPanelLim-1 {
					maxIP = bottomPanelLim - 1
				}
				if ipCursor < maxIP {
					ipCursor++
				} else if ipCursor < 0 {
					ipCursor = 0
				}
				renderAll()

			case "b", "B":
				if bottomMode != "ips" {
					lastBlockMsg = "switch bottom panel to IPs first (x)"
					renderAll()
					continue
				}
				if ipCursor >= 0 && ipCursor < len(globalIPs) {
					ip := globalIPs[ipCursor]["ip"]
					lastBlockMsg = blockIPLive(ip)
				} else {
					lastBlockMsg = "select an IP first (j/k to navigate IP panel)"
				}
				renderAll()

			case "l", "L":
				if bottomMode != "ips" {
					lastBlockMsg = "switch bottom panel to IPs first (x)"
					renderAll()
					continue
				}
				if ipCursor < 0 || ipCursor >= len(globalIPs) {
					lastBlockMsg = "select an IP first (j/k to navigate IP panel)"
					renderAll()
					continue
				}

				ip := globalIPs[ipCursor]["ip"]

				ui.Close()
				err := runIPDrilldown(baseURL, ip)

				fmt.Println()
				fmt.Print("Press Enter to return to webtop...")
				_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

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

			case "<Enter>":
				if len(rows) == 0 || cursor >= len(rows) {
					continue
				}
				selectedHost := rows[cursor].Host

				ui.Close()
				err := RunLiveDrilldown(baseURL, selectedHost)

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

			case "x", "X":
				if bottomMode == "ips" {
					bottomMode = "susp"
				} else {
					bottomMode = "ips"
				}
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
