package kernsec

import (
	"fmt"
	"os"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"golang.org/x/term"
)

// IsTTY reports whether stdout is attached to a terminal. Used by the
// CLI dispatcher to auto-fall back from the default TUI to text output
// when the command is piped or run in a non-interactive context.
func IsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// RunTUI launches the interactive kernsec audit. switchToText is set
// when the user pressed 't' to drop to plain-text mode; the caller
// should run RunStatus afterwards.
func RunTUI() (switchToText bool, err error) {
	if initErr := ui.Init(); initErr != nil {
		return false, fmt.Errorf("termui init: %w", initErr)
	}
	defer ui.Close()

	bootMode := DetectBackend(RealFS{}).Label()

	header := widgets.NewParagraph()
	header.Border = false
	header.PaddingLeft = 1

	table := widgets.NewTable()
	table.Title = " Rules "
	table.RowSeparator = false
	table.FillRow = false
	// STATE | TIER | KIND | GROUP | RULE
	table.ColumnWidths = []int{9, 5, 7, 22, 0}
	table.TextAlignment = ui.AlignLeft

	detail := widgets.NewParagraph()
	detail.Title = " Detail "
	detail.WrapText = true
	detail.PaddingLeft = 1
	detail.PaddingRight = 1

	footer := widgets.NewParagraph()
	footer.Border = false
	footer.PaddingLeft = 1

	grid := ui.NewGrid()
	layout := func() {
		w, h := ui.TerminalDimensions()
		grid.SetRect(0, 0, w, h)
		grid.Set(
			ui.NewRow(0.08, ui.NewCol(1.0, header)),
			ui.NewRow(0.84,
				ui.NewCol(0.62, table),
				ui.NewCol(0.38, detail),
			),
			ui.NewRow(0.08, ui.NewCol(1.0, footer)),
		)
	}
	layout()

	allRows := BuildAuditRows()
	rows := allRows
	cursor := 0
	statusMsg := ""
	statusUntil := time.Time{}
	showHelp := false

	// Filter mode state. When filterEditing == true the user is typing
	// a filter substring into the footer; render() shows "filter: <buf>_".
	filterEditing := false
	filterBuf := ""
	activeFilter := ""

	applyFilter := func() {
		if activeFilter == "" {
			rows = allRows
		} else {
			needle := strings.ToLower(activeFilter)
			rows = rows[:0]
			for _, r := range allRows {
				if strings.Contains(strings.ToLower(r.Display), needle) ||
					strings.Contains(strings.ToLower(r.Group), needle) ||
					strings.Contains(strings.ToLower(r.ID), needle) {
					rows = append(rows, r)
				}
			}
		}
		if cursor >= len(rows) {
			cursor = len(rows) - 1
		}
		if cursor < 0 {
			cursor = 0
		}
	}

	rebuildTable := func() {
		rs := make([][]string, 0, len(rows)+1)
		rs = append(rs, []string{"STATE", "TIER", "KIND", "GROUP", "RULE"})
		for _, r := range rows {
			rs = append(rs, []string{
				string(r.State),
				"T" + r.Tier.label(),
				string(r.Kind),
				r.Group,
				r.Display,
			})
		}
		table.Rows = rs
		table.RowStyles = make(map[int]ui.Style, len(rows)+1)
		table.RowStyles[0] = ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)
		for i, r := range rows {
			table.RowStyles[i+1] = ui.NewStyle(StateColor(r.State))
		}
		if cursor >= 0 && cursor < len(rows) {
			sel := cursor + 1
			table.RowStyles[sel] = ui.NewStyle(ui.ColorBlack, StateColor(rows[cursor].State))
		}
	}

	renderHeader := func() {
		warns := 0
		for _, r := range rows {
			if r.State != StateOK && r.State != StateSKIP {
				warns++
			}
		}
		header.Text = fmt.Sprintf(
			"[cfm kernsec](fg:cyan,mod:bold)  •  boot mode: [%s](fg:white,mod:bold)  •  rules: %d  •  warnings: [%d](fg:%s)  •  updated: %s",
			bootMode, len(rows), warns, warnsColorName(warns), time.Now().Format("15:04:05"),
		)
	}

	renderDetail := func() {
		if cursor < 0 || cursor >= len(rows) {
			detail.Text = ""
			return
		}
		r := rows[cursor]
		var b strings.Builder
		fmt.Fprintf(&b, "[Selected:](fg:cyan,mod:bold) %s\n\n", r.Display)
		fmt.Fprintf(&b, "[State:](fg:cyan)  [%s](fg:%s,mod:bold)\n\n", r.State, StateColorName(r.State))
		fmt.Fprintf(&b, "[Description:](fg:cyan)\n  %s\n\n", r.Description)
		fmt.Fprintf(&b, "[Affects:](fg:cyan)\n  %s\n\n", r.Affects)
		fmt.Fprintf(&b, "[Live state:](fg:cyan)\n")
		switch r.Kind {
		case KindSysctl:
			switch r.State {
			case StateSKIP:
				fmt.Fprintln(&b, "  /proc/sys: missing on this kernel")
			case StateOK:
				fmt.Fprintf(&b, "  /proc/sys: %s\n", r.LiveValue)
			default:
				fmt.Fprintf(&b, "  /proc/sys: %s  (expected %s)\n", r.LiveValue, r.ExpectedValue)
			}
		case KindBoot:
			fmt.Fprintf(&b, "  /proc/cmdline:    %s\n", presence(r.InCurrent))
			if r.NextBootKnown {
				fmt.Fprintf(&b, "  next-boot config: %s\n", presence(r.InNextBoot))
			} else {
				fmt.Fprintln(&b, "  next-boot config: unknown (could not read bootloader)")
			}
		case KindModule:
			fmt.Fprintf(&b, "  blacklisted in modprobe.d: %s\n", presence(r.BlacklistedInFile))
			fmt.Fprintf(&b, "  currently loaded:          %s\n", presence(r.Loaded))
			fmt.Fprintf(&b, "  built into this kernel:    %s\n", presence(r.PresentOnKernel))
			if r.State == StateLOADED {
				fmt.Fprintln(&b, "")
				fmt.Fprintln(&b, "  [Note:](fg:yellow,mod:bold) blacklist active but module still loaded.")
				fmt.Fprintln(&b, "  Reboot or `rmmod` for the blacklist to take effect.")
			}
		}
		detail.Text = b.String()
	}

	renderFooter := func() {
		if filterEditing {
			footer.Text = fmt.Sprintf("[filter:](fg:cyan,mod:bold) %s_   [Enter](fg:cyan) apply  [Esc](fg:cyan) cancel  [Backspace](fg:cyan) erase", filterBuf)
			return
		}
		if showHelp {
			footer.Text = "[help](fg:cyan,mod:bold)  Phase 1 audit-only.  e/d are stubs until Phase 3.  Press [?](fg:cyan) to dismiss."
			return
		}
		if statusMsg != "" && time.Now().Before(statusUntil) {
			footer.Text = fmt.Sprintf("[%s](fg:yellow)", statusMsg)
			return
		}
		base := "[q](fg:cyan)uit  [↑/↓](fg:cyan) nav  [r](fg:cyan)efresh  [t](fg:cyan)ext  [e](fg:cyan)nable  [d](fg:cyan)isable  [/](fg:cyan) filter  [?](fg:cyan) help"
		if activeFilter != "" {
			base += fmt.Sprintf("  •  [filter:](fg:cyan) %s  [c](fg:cyan)lear", activeFilter)
		}
		footer.Text = base
	}

	flash := func(msg string) {
		statusMsg = msg
		statusUntil = time.Now().Add(3 * time.Second)
	}

	render := func() {
		renderHeader()
		rebuildTable()
		renderDetail()
		renderFooter()
		ui.Render(grid)
	}

	refresh := func() {
		allRows = BuildAuditRows()
		applyFilter()
	}

	render()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	events := ui.PollEvents()
	for {
		select {
		case e := <-events:
			if filterEditing {
				switch e.ID {
				case "<Enter>":
					activeFilter = filterBuf
					filterEditing = false
					applyFilter()
				case "<Escape>":
					filterEditing = false
					filterBuf = ""
				case "<Backspace>", "<C-8>":
					if len(filterBuf) > 0 {
						filterBuf = filterBuf[:len(filterBuf)-1]
					}
				case "<Space>":
					filterBuf += " "
				default:
					if len(e.ID) == 1 {
						r := e.ID[0]
						if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') ||
							(r >= 'A' && r <= 'Z') || r == '.' || r == '_' || r == '-' {
							filterBuf += e.ID
						}
					}
				}
				render()
				continue
			}
			switch e.ID {
			case "q", "<C-c>":
				return false, nil
			case "<Up>", "k":
				if cursor > 0 {
					cursor--
				}
				render()
			case "<Down>", "j":
				if cursor < len(rows)-1 {
					cursor++
				}
				render()
			case "<Home>", "g":
				cursor = 0
				render()
			case "<End>", "G":
				cursor = len(rows) - 1
				render()
			case "<PageUp>":
				cursor -= 8
				if cursor < 0 {
					cursor = 0
				}
				render()
			case "<PageDown>":
				cursor += 8
				if cursor >= len(rows) {
					cursor = len(rows) - 1
				}
				render()
			case "r":
				refresh()
				flash("refreshed")
				render()
			case "t":
				return true, nil
			case "e":
				flash("enable lands in Phase 3 — see docs/kernsec.md")
				render()
			case "d":
				flash("disable lands in Phase 3 — see docs/kernsec.md")
				render()
			case "/":
				filterEditing = true
				filterBuf = activeFilter
				render()
			case "c":
				if activeFilter != "" {
					activeFilter = ""
					filterBuf = ""
					applyFilter()
					render()
				}
			case "?":
				showHelp = !showHelp
				render()
			case "<Resize>":
				layout()
				render()
			}
		case <-tick.C:
			refresh()
			render()
		}
	}
}

// StateColor maps a RuleState to a termui color for table row styling.
func StateColor(s RuleState) ui.Color {
	switch s {
	case StateOK:
		return ui.ColorGreen
	case StateSKIP:
		return ui.ColorWhite
	case StateDIFF, StateWARN, StateMISSING:
		return ui.ColorYellow
	case StateDRIFT:
		return ui.ColorRed
	}
	return ui.ColorWhite
}

// StateColorName is the same mapping but as the lowercase color name termui
// markup expects in `[text](fg:NAME)` annotations.
func StateColorName(s RuleState) string {
	switch s {
	case StateOK:
		return "green"
	case StateSKIP:
		return "white"
	case StateDIFF, StateWARN, StateMISSING:
		return "yellow"
	case StateDRIFT:
		return "red"
	}
	return "white"
}

func warnsColorName(n int) string {
	if n == 0 {
		return "green"
	}
	return "yellow"
}

func presence(b bool) string {
	if b {
		return "present"
	}
	return "missing"
}
