package kernsec

import (
	"bytes"
	"fmt"
	"os"
	"sort"
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

	allRows := buildAuditRowsForTUI()
	sort.SliceStable(allRows, func(i, j int) bool {
		return allRows[i].Tier < allRows[j].Tier
	})
	rows := allRows
	cursor := 0
	offset := 0
	// pending maps rule ID -> queued RuleOverride. The user stages
	// enable/disable with e/d/u and commits the batch with `a`. Held
	// only in TUI memory until apply; `x` discards.
	pending := map[string]RuleOverride{}
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
		offset = 0
	}

	// pageSize is how many data rows fit in the table's inner viewport
	// (minus 1 for the sticky header). termui's Table doesn't scroll on
	// its own — we feed it just the visible slice and track `offset`.
	pageSize := func() int {
		n := table.Inner.Dy() - 1
		if n < 1 {
			n = 1
		}
		return n
	}

	clampOffset := func() {
		ps := pageSize()
		if cursor < offset {
			offset = cursor
		}
		if cursor >= offset+ps {
			offset = cursor - ps + 1
		}
		max := len(rows) - ps
		if max < 0 {
			max = 0
		}
		if offset > max {
			offset = max
		}
		if offset < 0 {
			offset = 0
		}
	}

	rebuildTable := func() {
		clampOffset()
		ps := pageSize()
		end := offset + ps
		if end > len(rows) {
			end = len(rows)
		}
		visible := rows[offset:end]

		rs := make([][]string, 0, len(visible)+1)
		rs = append(rs, []string{"STATE", "TIER", "KIND", "GROUP", "RULE"})
		for _, r := range visible {
			rs = append(rs, []string{
				stateCell(r, pending),
				"T" + r.Tier.label(),
				string(r.Kind),
				r.Group,
				r.Display,
			})
		}
		table.Rows = rs
		table.RowStyles = make(map[int]ui.Style, len(visible)+1)
		table.RowStyles[0] = ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)
		for i, r := range visible {
			table.RowStyles[i+1] = ui.NewStyle(rowColor(r, pending))
		}
		if cursor >= offset && cursor < end {
			sel := cursor - offset + 1
			table.RowStyles[sel] = ui.NewStyle(ui.ColorBlack, rowColor(rows[cursor], pending))
		}
	}

	renderHeader := func() {
		warns := 0
		for _, r := range rows {
			if r.State != StateOK && r.State != StateSKIP && r.State != StateOFF && r.State != StateEXT {
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
		fmt.Fprintf(&b, "[State:](fg:cyan)  [%s](fg:%s,mod:bold)\n", r.State, StateColorName(r.State))
		if r.Reason != "" {
			fmt.Fprintf(&b, "[Reason:](fg:cyan) %s\n", r.Reason)
		}
		fmt.Fprintf(&b, "\n[Description:](fg:cyan)\n  %s\n\n", r.Description)
		fmt.Fprintf(&b, "[Affects:](fg:cyan)\n  %s\n\n", r.Affects)
		fmt.Fprintf(&b, "[Live state:](fg:cyan)\n")
		switch r.Kind {
		case KindSysctl:
			switch r.State {
			case StateSKIP:
				fmt.Fprintln(&b, "  /proc/sys: missing on this kernel")
			case StateOK:
				fmt.Fprintf(&b, "  /proc/sys: %s\n", r.LiveValue)
			case StateEXT:
				// Externally managed: kernsec does NOT enforce a value
				// here, so "expected X" wording would mislead the
				// operator. Show the live value with the owner attribution.
				owner := "another cfm component"
				if r.Reason != "" {
					owner = r.Reason
				}
				if r.LiveValue == "" {
					fmt.Fprintf(&b, "  /proc/sys: not exposed by this kernel  (%s)\n", owner)
				} else {
					fmt.Fprintf(&b, "  /proc/sys: %s  (%s; kernsec audits but does not enforce)\n",
						r.LiveValue, owner)
				}
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
		case KindMount:
			fmt.Fprintf(&b, "  mount point:        %s\n", r.MountPoint)
			fmt.Fprintf(&b, "  recommended:        %s\n", r.RecommendedOptions)
			if r.CurrentOptions == "" {
				fmt.Fprintln(&b, "  current /proc/mounts: not separately mounted")
			} else {
				fmt.Fprintf(&b, "  current /proc/mounts: %s\n", r.CurrentOptions)
			}
			fmt.Fprintln(&b, "")
			fmt.Fprintln(&b, "  [Note:](fg:cyan,mod:bold) audit-only — kernsec never edits /etc/fstab.")
		}
		detail.Text = b.String()
	}

	renderFooter := func() {
		if filterEditing {
			footer.Text = fmt.Sprintf("[filter:](fg:cyan,mod:bold) %s_   [Enter](fg:cyan) apply  [Esc](fg:cyan) cancel  [Backspace](fg:cyan) erase", filterBuf)
			return
		}
		if showHelp {
			footer.Text = "[help](fg:cyan,mod:bold)  Audit-only TUI. Run [cfm kernsec apply](fg:cyan)/[disable](fg:cyan) from the shell to mutate state. Press [?](fg:cyan) to dismiss."
			return
		}
		if statusMsg != "" && time.Now().Before(statusUntil) {
			footer.Text = fmt.Sprintf("[%s](fg:yellow)", statusMsg)
			return
		}
		base := "[q](fg:cyan)uit  [↑/↓](fg:cyan) nav  [r](fg:cyan)efresh  [t](fg:cyan)ext  [e](fg:cyan)nable  [d](fg:cyan)isable  [u](fg:cyan)ndo  [a](fg:cyan)pply  [x](fg:cyan) discard  [/](fg:cyan) filter  [?](fg:cyan) help"
		if len(pending) > 0 {
			base += fmt.Sprintf("  •  [pending: %d](fg:magenta,mod:bold)", len(pending))
		}
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
		allRows = buildAuditRowsForTUI()
		sort.SliceStable(allRows, func(i, j int) bool {
			return allRows[i].Tier < allRows[j].Tier
		})
		applyFilter()
	}

	// applyPending commits the queued overrides: merges them into the
	// on-disk conf, then runs the full applier (sysctl file + modprobe
	// file + bootloader cmdline + runtime sysctl -w). Output from
	// applyCore is captured into a buffer so it doesn't shatter the
	// TUI; the operator just sees a flash with rc + count.
	applyPending := func() {
		if len(pending) == 0 {
			flash("no pending changes")
			return
		}
		if os.Geteuid() != 0 {
			flash("apply: must run as root")
			return
		}
		conf, err := LoadConf(true)
		if err != nil {
			flash("apply: load conf: " + err.Error())
			return
		}
		if conf.Overrides == nil {
			conf.Overrides = map[string]RuleOverride{}
		}
		for id, ov := range pending {
			if ov == OverrideDefault {
				delete(conf.Overrides, id)
			} else {
				conf.Overrides[id] = ov
			}
		}
		if err := WriteConf(conf); err != nil {
			flash("apply: write conf: " + err.Error())
			return
		}
		var buf bytes.Buffer
		rc := applyCore(&buf, conf, ApplyOptions{AssumeYes: true}, "APPLY")
		count := len(pending)
		if rc != 0 {
			flash(fmt.Sprintf("apply failed (rc=%d) — conf saved; re-run `cfm kernsec apply` from shell", rc))
			return
		}
		pending = map[string]RuleOverride{}
		refresh()
		flash(fmt.Sprintf("applied %d change(s)", count))
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
				cursor -= pageSize()
				if cursor < 0 {
					cursor = 0
				}
				render()
			case "<PageDown>":
				cursor += pageSize()
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
				if cursor >= 0 && cursor < len(rows) {
					pending[rows[cursor].ID] = OverrideForce
				}
				render()
			case "d":
				if cursor >= 0 && cursor < len(rows) {
					pending[rows[cursor].ID] = OverrideSkip
				}
				render()
			case "u":
				if cursor >= 0 && cursor < len(rows) {
					delete(pending, rows[cursor].ID)
				}
				render()
			case "a":
				applyPending()
				render()
			case "x":
				if len(pending) > 0 {
					n := len(pending)
					pending = map[string]RuleOverride{}
					flash(fmt.Sprintf("discarded %d pending change(s)", n))
				}
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
	case StateSKIP, StateOFF, StateEXT:
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
	case StateSKIP, StateOFF, StateEXT:
		return "white"
	case StateDIFF, StateWARN, StateMISSING:
		return "yellow"
	case StateDRIFT:
		return "red"
	}
	return "white"
}

// buildAuditRowsForTUI is the wrapper TUI / status callers use when they
// haven't already loaded conf + profile. Best-effort: a missing or
// unreadable conf falls back to tier=1 in memory (matching first-run UX
// and what `cfm kernsec status` prints on hosts that haven't run init).
func buildAuditRowsForTUI() []AuditRow {
	conf, err := LoadConf(false)
	if err != nil {
		conf = &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	}
	profile := DetectHostProfile()
	return BuildAuditRows(conf, profile)
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

// stateCell is the STATE column value, swapped for a PEND-* badge when
// the rule has a queued override the operator hasn't committed yet.
func stateCell(r AuditRow, pending map[string]RuleOverride) string {
	if ov, ok := pending[r.ID]; ok {
		switch ov {
		case OverrideForce:
			return "PEND-ON"
		case OverrideSkip:
			return "PEND-OFF"
		default:
			return "PEND-DEF"
		}
	}
	return string(r.State)
}

// rowColor returns the table row color, using magenta for pending rows
// so queued changes pop visually against the State palette.
func rowColor(r AuditRow, pending map[string]RuleOverride) ui.Color {
	if _, ok := pending[r.ID]; ok {
		return ui.ColorMagenta
	}
	return StateColor(r.State)
}
