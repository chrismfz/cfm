// internal/webdetector/cli_bots_live.go
//
// Live two-pane TUI for `cfm bots`. Top pane shows the bot-top live rows;
// bottom pane shows the active emergency rules so the operator can see
// exactly what they have in flight and undo it with a single key.
//
// Key bindings:
//
//   ↑/↓        navigate top pane (UA rows)
//   j/k        navigate bottom pane (active rules)
//   t/b        throttle / block the selected UA in the top pane
//   T          (shift-T) force-confirm a Google verified crawler
//   u          undo the rule selected in the bottom pane
//   d          drill into the selected UA (drops out, runs cfm bots drill)
//   1/2/3/4    cycle TTL preset (5m / 15m / 30m / 60m). Default 30m.
//   r          refresh now (otherwise auto-tick 2s)
//   q          quit
//
// "allow" is intentionally not exposed: UA-keyed bypass would be a
// trivially spoofable WAF gap. Use per-vhost rules with IP/ASN
// verification for verified-crawler exemptions.
package webdetector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	clihttp "cfm/internal/clihttp"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// runBotsLive drives the live TUI loop.
func runBotsLive(baseURL string) error {
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	W, H := ui.TerminalDimensions()

	header := widgets.NewParagraph()
	header.Border = true
	header.BorderStyle = ui.NewStyle(ui.ColorCyan)

	topTable := widgets.NewTable()
	topTable.Title = " ◈ Live UA Top — ↑↓ navigate  t=throttle  b=block  d=drill  q=quit "
	topTable.RowSeparator = false
	topTable.FillRow = true
	topTable.BorderStyle = ui.NewStyle(ui.ColorWhite)

	bottomTable := widgets.NewTable()
	bottomTable.Title = " ⚠ Active Emergency Rules — j/k navigate  u=undo "
	bottomTable.RowSeparator = false
	bottomTable.FillRow = true
	bottomTable.BorderStyle = ui.NewStyle(ui.ColorYellow)

	statusBar := widgets.NewParagraph()
	statusBar.Border = false
	statusBar.TextStyle = ui.NewStyle(ui.ColorBlack, ui.ColorWhite)

	doLayout := func() {
		W, H = ui.TerminalDimensions()
		splitY := H * 60 / 100
		if splitY < 8 {
			splitY = 8
		}
		if H-splitY < 6 {
			splitY = H - 6
		}
		header.SetRect(0, 0, W, 3)
		topTable.SetRect(0, 3, W, splitY)
		bottomTable.SetRect(0, splitY, W, H-3)
		statusBar.SetRect(0, H-3, W, H)
	}
	doLayout()

	var (
		topRows   []UATopRow
		rules     []UAEmergencyRule
		ruleByUA  map[string]UAEmergencyRule
		topCursor int
		botCursor int
		lastMsg   string
		lastErr   error
		ttlIdx    = 2 // index into ttlPresets, 30m default
		tickN     int
	)

	ttlPresets := []time.Duration{
		5 * time.Minute,
		15 * time.Minute,
		30 * time.Minute,
		60 * time.Minute,
	}

	refresh := func() {
		topRows, lastErr = fetchUATop(baseURL, 50)
		if lastErr == nil {
			rules, _ = fetchUAEmergencyList(baseURL)
			ruleByUA = indexRulesByUA(rules)
		}
		if topCursor >= len(topRows) {
			topCursor = max0(len(topRows) - 1)
		}
		if botCursor >= len(rules) {
			botCursor = max0(len(rules) - 1)
		}
	}

	renderAll := func() {
		ts := time.Now().Format("15:04:05")
		status := "● LIVE"
		if lastErr != nil {
			status = fmt.Sprintf("✖ %s", lastErr)
		}
		header.Text = fmt.Sprintf(
			" [%s](fg:green)  ttl:[%s](fg:yellow,mod:bold)  tick:[%d](fg:white)  [%s](fg:white)  %s",
			status, ttlPresets[ttlIdx], tickN, ts, escapeMsg(lastMsg),
		)

		// Top pane.
		topTable.Rows = [][]string{{"#", "UA", "RPS", "REQS", "IPS", "VHOSTS", "ACTIVE"}}
		for i, r := range topRows {
			active := "-"
			if ar, ok := ruleByUA[r.UA]; ok {
				active = fmt.Sprintf("%s %s", ar.Action, leftDuration(ar.ExpiresAt))
			}
			topTable.Rows = append(topTable.Rows, []string{
				fmt.Sprintf("%d", i+1),
				truncateBots(r.UA, 32),
				fmt.Sprintf("%.2f", r.RPS),
				fmt.Sprintf("%d", r.Reqs),
				fmt.Sprintf("%d", r.UniqueIPs),
				fmt.Sprintf("%d", r.Vhosts),
				active,
			})
		}
		topTable.ColumnWidths = []int{4, 34, 8, 8, 8, 8, 0}
		topTable.RowStyles = map[int]ui.Style{
			0: ui.NewStyle(ui.ColorBlack, ui.ColorCyan),
		}
		if topCursor >= 0 && topCursor+1 < len(topTable.Rows) {
			topTable.RowStyles[topCursor+1] = ui.NewStyle(ui.ColorBlack, ui.ColorYellow)
		}

		// Bottom pane.
		bottomTable.Rows = [][]string{{"UA", "ACTION", "EXPIRES_IN", "HITS", "BY", "REASON"}}
		for _, r := range rules {
			bottomTable.Rows = append(bottomTable.Rows, []string{
				truncateBots(r.UA, 32),
				r.Action,
				leftDuration(r.ExpiresAt),
				fmt.Sprintf("%d", r.Hits),
				truncateBots(r.CreatedBy, 16),
				truncateBots(r.Reason, 24),
			})
		}
		bottomTable.ColumnWidths = []int{34, 10, 14, 8, 18, 0}
		bottomTable.RowStyles = map[int]ui.Style{
			0: ui.NewStyle(ui.ColorBlack, ui.ColorYellow),
		}
		if botCursor >= 0 && botCursor+1 < len(bottomTable.Rows) {
			bottomTable.RowStyles[botCursor+1] = ui.NewStyle(ui.ColorBlack, ui.ColorYellow)
		}

		statusBar.Text = fmt.Sprintf(
			" [t]throttle  [b]block  [T]google-confirm  [d]drill  [u]undo  [1-4]ttl  [r]refresh  [q]quit",
		)

		ui.Clear()
		ui.Render(header, topTable, bottomTable, statusBar)
	}

	selectedUA := func() string {
		if topCursor < 0 || topCursor >= len(topRows) {
			return ""
		}
		return topRows[topCursor].UA
	}

	apply := func(action string, confirm bool) {
		ua := selectedUA()
		if ua == "" {
			lastMsg = "select a UA row first"
			return
		}
		body, _ := json.Marshal(uaEmergencyPostBody{
			UA:         ua,
			Action:     action,
			TTLSeconds: int(ttlPresets[ttlIdx].Seconds()),
			Reason:     "live_ui",
			Confirm:    confirm,
		})
		resp, err := clihttp.Post(baseURL+"/api/v1/webdet/ua-emergency", "application/json", bytes.NewReader(body))
		if err != nil {
			lastMsg = "✖ " + err.Error()
			return
		}
		defer drainClose(resp.Body)
		if resp.StatusCode == http.StatusConflict {
			var errBody map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&errBody)
			if errBody["error"] == "google_verified_bot_requires_confirm" {
				lastMsg = fmt.Sprintf("⚠ %q is a verified Google crawler — press [T] to confirm", ua)
				return
			}
			lastMsg = "✖ conflict"
			return
		}
		if resp.StatusCode/100 != 2 {
			lastMsg = fmt.Sprintf("✖ http %s", resp.Status)
			return
		}
		lastMsg = fmt.Sprintf("✓ %s ua=%s ttl=%s", action, ua, ttlPresets[ttlIdx])
		refresh()
	}

	undo := func() {
		if botCursor < 0 || botCursor >= len(rules) {
			lastMsg = "select an active rule first"
			return
		}
		ua := rules[botCursor].UA
		u := fmt.Sprintf("%s/api/v1/webdet/ua-emergency?ua=%s", baseURL, url.QueryEscape(ua))
		req, _ := http.NewRequest(http.MethodDelete, u, nil)
		resp, err := clihttp.Do(req)
		if err != nil {
			lastMsg = "✖ " + err.Error()
			return
		}
		drainClose(resp.Body)
		if resp.StatusCode/100 != 2 {
			lastMsg = fmt.Sprintf("✖ http %s", resp.Status)
			return
		}
		lastMsg = "✓ undone " + ua
		refresh()
	}

	// drill returns true on success (UI re-initialized cleanly), or false
	// if ui.Init failed after the runBotsDrill detour. The main loop must
	// exit on false — without doing so the next renderAll would call
	// ui.Render against a torn-down termui (panic or garbled terminal).
	drill := func() bool {
		ua := selectedUA()
		if ua == "" {
			lastMsg = "select a UA row first"
			renderAll()
			return true
		}
		ui.Close()
		_ = runBotsDrill(baseURL, ua)
		fmt.Println()
		fmt.Print("Press Enter to return to cfm bots...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		if initErr := ui.Init(); initErr != nil {
			lastErr = initErr
			return false
		}
		doLayout()
		return true
	}

	refresh()
	renderAll()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	events := ui.PollEvents()

	for {
		select {
		case e := <-events:
			switch e.ID {
			case "q", "Q", "<C-c>":
				return nil
			case "<Up>":
				if topCursor > 0 {
					topCursor--
				}
				renderAll()
			case "<Down>":
				if topCursor < len(topRows)-1 {
					topCursor++
				}
				renderAll()
			case "k":
				if botCursor > 0 {
					botCursor--
				}
				renderAll()
			case "j":
				if botCursor < len(rules)-1 {
					botCursor++
				}
				renderAll()
			case "t":
				apply("throttle", false)
				renderAll()
			case "b":
				apply("block", false)
				renderAll()
			case "T":
				// Shift-T: confirm Google verified — applies the last attempted
				// action again with confirm=true. For simplicity we re-issue a
				// block with confirm; operators wanting throttle/allow on
				// Google bots can use the CLI subcommand with --confirm.
				apply("block", true)
				renderAll()
			case "u":
				undo()
				renderAll()
			case "d":
				if !drill() {
					// ui.Init failed after the drill detour; the UI is
					// torn down and we can't render anything safely. Bail.
					return lastErr
				}
				refresh()
				renderAll()
			case "1":
				ttlIdx = 0
				renderAll()
			case "2":
				ttlIdx = 1
				renderAll()
			case "3":
				ttlIdx = 2
				renderAll()
			case "4":
				ttlIdx = 3
				renderAll()
			case "r", "R":
				refresh()
				renderAll()
			case "<Resize>":
				doLayout()
				renderAll()
			}
		case <-tick.C:
			tickN++
			refresh()
			renderAll()
		}
	}
}

// ── small helpers ───────────────────────────────────────────────────────────

// truncateBots is the bot-top variant of truncate (the cli_history version
// uses an ellipsis glyph that doesn't fit in the column widths chosen here).
func truncateBots(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 2 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

func escapeMsg(s string) string {
	// termui uses [text](style); escape stray brackets so they don't get
	// interpreted as style markup.
	r := strings.NewReplacer("[", "(", "]", ")")
	return r.Replace(s)
}

func max0(x int) int {
	if x < 0 {
		return 0
	}
	return x
}
