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

// focus identifies which pane currently receives keyboard navigation
// (↑/↓/PageUp/PageDown/Home/End). The Detail pane is read-only and
// never takes focus.
const (
	focusGroups = 0
	focusRules  = 1
)

// groupKey is one row in the LEFT pane: a (Tier, Kind, Group) tuple
// from the audit set, with the count of rules that share it. Used for
// hierarchical navigation — operator picks a group on the left, sees
// the group's rules on the middle pane, and the selected rule's
// detail on the right.
type groupKey struct {
	Tier  Tier
	Kind  RuleKind
	Group string
	Count int
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

	// LEFT pane — distinct groups with rule counts.
	groupsTable := widgets.NewTable()
	groupsTable.Title = " Groups "
	groupsTable.RowSeparator = false
	groupsTable.FillRow = false
	// TIER | KIND | GROUP | COUNT
	groupsTable.ColumnWidths = []int{4, 8, 24, 4}
	groupsTable.TextAlignment = ui.AlignLeft

	// MIDDLE pane — rules belonging to the currently-selected group.
	rulesTable := widgets.NewTable()
	rulesTable.Title = " Rules "
	rulesTable.RowSeparator = false
	rulesTable.FillRow = false
	// STATE | RULE (RULE width is computed each render from panel Dx).
	rulesTable.ColumnWidths = []int{9, 30}
	rulesTable.TextAlignment = ui.AlignLeft

	// RIGHT pane — detail for the selected rule.
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
				ui.NewCol(0.25, groupsTable),
				ui.NewCol(0.30, rulesTable),
				ui.NewCol(0.45, detail),
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
	var groups []groupKey
	var rulesInGroup []AuditRow
	groupCursor, groupOffset := 0, 0
	ruleCursor, ruleOffset := 0, 0
	focus := focusGroups
	// pending maps rule ID -> queued RuleOverride. The user stages
	// enable/disable with e/d/u and commits the batch with `a`. Held
	// only in TUI memory until apply; `x` discards.
	pending := map[string]RuleOverride{}
	statusMsg := ""
	statusUntil := time.Time{}
	showHelp := false
	filterEditing := false
	filterBuf := ""
	activeFilter := ""

	recomputeRulesInGroup := func() {
		rulesInGroup = rulesInGroup[:0]
		if groupCursor < 0 || groupCursor >= len(groups) {
			ruleCursor, ruleOffset = 0, 0
			return
		}
		g := groups[groupCursor]
		for _, r := range rows {
			if r.Tier == g.Tier && r.Kind == g.Kind && r.Group == g.Group {
				rulesInGroup = append(rulesInGroup, r)
			}
		}
		if ruleCursor >= len(rulesInGroup) {
			ruleCursor = len(rulesInGroup) - 1
		}
		if ruleCursor < 0 {
			ruleCursor = 0
		}
		ruleOffset = 0
	}

	recomputeGroups := func() {
		groups = buildGroupList(rows)
		if groupCursor >= len(groups) {
			groupCursor = len(groups) - 1
		}
		if groupCursor < 0 {
			groupCursor = 0
		}
		groupOffset = 0
		recomputeRulesInGroup()
	}

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
		recomputeGroups()
	}

	// pageSizeOf computes how many data rows fit in a Table's inner
	// viewport (minus 1 for the sticky header). On first render the
	// Grid hasn't called Draw yet (gizak/termui/v3 grid.go:154 is what
	// sets child Rects), so t.Inner.Dy() is 0. Fall back to the
	// terminal-height fraction the layout assigns to the middle row.
	pageSizeOf := func(t *widgets.Table) int {
		n := t.Inner.Dy() - 1
		if n < 1 {
			_, h := ui.TerminalDimensions()
			n = int(float64(h)*0.84) - 3
		}
		if n < 1 {
			n = 1
		}
		return n
	}
	groupsPageSize := func() int { return pageSizeOf(groupsTable) }
	rulesPageSize := func() int { return pageSizeOf(rulesTable) }

	clampOffset := func(cursor, length, page int, offset *int) {
		if cursor < *offset {
			*offset = cursor
		}
		if cursor >= *offset+page {
			*offset = cursor - page + 1
		}
		max := length - page
		if max < 0 {
			max = 0
		}
		if *offset > max {
			*offset = max
		}
		if *offset < 0 {
			*offset = 0
		}
	}

	rebuildGroupsTable := func() {
		clampOffset(groupCursor, len(groups), groupsPageSize(), &groupOffset)
		ps := groupsPageSize()
		end := groupOffset + ps
		if end > len(groups) {
			end = len(groups)
		}
		visible := groups[groupOffset:end]

		rs := make([][]string, 0, len(visible)+1)
		rs = append(rs, []string{"TIER", "KIND", "GROUP", "N"})
		for _, g := range visible {
			rs = append(rs, []string{
				"T" + g.Tier.label(),
				string(g.Kind),
				g.Group,
				fmt.Sprintf("%d", g.Count),
			})
		}
		groupsTable.Rows = rs
		groupsTable.RowStyles = make(map[int]ui.Style, len(visible)+1)
		groupsTable.RowStyles[0] = ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)
		for i, g := range visible {
			groupsTable.RowStyles[i+1] = ui.NewStyle(groupWorstColor(rows, g, pending))
		}
		if groupCursor >= groupOffset && groupCursor < end {
			sel := groupCursor - groupOffset + 1
			selColor := groupWorstColor(rows, groups[groupCursor], pending)
			if focus == focusGroups {
				groupsTable.RowStyles[sel] = ui.NewStyle(ui.ColorBlack, selColor)
			} else {
				groupsTable.RowStyles[sel] = ui.NewStyle(selColor, ui.ColorClear, ui.ModifierBold)
			}
		}
		groupsTable.BorderStyle = paneBorderStyle(focus == focusGroups)
		groupsTable.TitleStyle = paneTitleStyle(focus == focusGroups)
	}

	rebuildRulesTable := func() {
		clampOffset(ruleCursor, len(rulesInGroup), rulesPageSize(), &ruleOffset)
		ps := rulesPageSize()
		end := ruleOffset + ps
		if end > len(rulesInGroup) {
			end = len(rulesInGroup)
		}
		visible := rulesInGroup[ruleOffset:end]

		// Fill the RULE column with whatever's left in the panel after
		// the STATE column. termui doesn't auto-size a "0" width column
		// (widgets/table.go:51 uses the slice verbatim), so we recompute
		// each render. Falls back to terminal-dim on the first frame
		// when Inner.Dx() is still zero — see pageSizeOf rationale.
		ruleW := rulesTable.Inner.Dx() - 9 - 1
		if ruleW <= 0 {
			w, _ := ui.TerminalDimensions()
			ruleW = int(float64(w)*0.30) - 9 - 2
		}
		if ruleW < 8 {
			ruleW = 8
		}
		rulesTable.ColumnWidths = []int{9, ruleW}

		rs := make([][]string, 0, len(visible)+1)
		rs = append(rs, []string{"STATE", "RULE"})
		for _, r := range visible {
			rs = append(rs, []string{
				stateCell(r, pending),
				r.Display,
			})
		}
		rulesTable.Rows = rs
		rulesTable.RowStyles = make(map[int]ui.Style, len(visible)+1)
		rulesTable.RowStyles[0] = ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)
		for i, r := range visible {
			rulesTable.RowStyles[i+1] = ui.NewStyle(rowColor(r, pending))
		}
		if ruleCursor >= ruleOffset && ruleCursor < end {
			sel := ruleCursor - ruleOffset + 1
			selColor := rowColor(rulesInGroup[ruleCursor], pending)
			if focus == focusRules {
				rulesTable.RowStyles[sel] = ui.NewStyle(ui.ColorBlack, selColor)
			} else {
				rulesTable.RowStyles[sel] = ui.NewStyle(selColor, ui.ColorClear, ui.ModifierBold)
			}
		}
		rulesTable.BorderStyle = paneBorderStyle(focus == focusRules)
		rulesTable.TitleStyle = paneTitleStyle(focus == focusRules)
		// Title gains the current group so the operator always knows
		// which group's rules are listed.
		if len(groups) > 0 && groupCursor < len(groups) {
			rulesTable.Title = fmt.Sprintf(" Rules — %s (%d) ",
				groups[groupCursor].Group, len(rulesInGroup))
		} else {
			rulesTable.Title = " Rules "
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
		if msg := bootDivergenceMsg(rows); msg != "" {
			header.Text += fmt.Sprintf("  •  [BOOT: %s](fg:yellow,mod:bold)", msg)
		}
	}

	renderDetail := func() {
		if ruleCursor < 0 || ruleCursor >= len(rulesInGroup) {
			detail.Text = ""
			return
		}
		r := rulesInGroup[ruleCursor]
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
			switch {
			case r.NextBootKnown:
				fmt.Fprintf(&b, "  next-boot config: %s\n", presence(r.InNextBoot))
			case r.Error != "":
				fmt.Fprintf(&b, "  next-boot config: [unreadable](fg:yellow)\n")
				fmt.Fprintf(&b, "  bootloader error: %s\n", r.Error)
			default:
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
			// Render a one-line tip summary; the full copy-pasteable
			// guide lives in `cfm kernsec status` text output where
			// it isn't subject to TUI line-truncation.
			for _, mr := range Tier1Mounts {
				if mr.ID != r.ID {
					continue
				}
				if tip := BuildMountTip(mr); tip.Headline != "" {
					fmt.Fprintln(&b, "")
					fmt.Fprintf(&b, "  [Tip:](fg:yellow,mod:bold) %s\n", tip.Headline)
					fmt.Fprintln(&b, "  Run `cfm kernsec status` for the full copy-pasteable guide.")
				}
				break
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
			footer.Text = "[help](fg:cyan,mod:bold)  Audit-only TUI. Run [cfm kernsec apply](fg:cyan)/[disable](fg:cyan) from the shell to mutate state. Press [?](fg:cyan) to dismiss."
			return
		}
		if statusMsg != "" && time.Now().Before(statusUntil) {
			footer.Text = fmt.Sprintf("[%s](fg:yellow)", statusMsg)
			return
		}
		base := "[q](fg:cyan)uit  [←/→/Tab](fg:cyan) pane  [↑/↓](fg:cyan) nav  [r](fg:cyan)efresh  [t](fg:cyan)ext  [m](fg:cyan)odules  [e](fg:cyan)nable  [d](fg:cyan)isable  [u](fg:cyan)ndo  [a](fg:cyan)pply  [x](fg:cyan) discard  [/](fg:cyan) filter  [?](fg:cyan) help"
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
		rebuildGroupsTable()
		rebuildRulesTable()
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
		conf, lerr := LoadConf(true)
		if lerr != nil {
			flash("apply: load conf: " + lerr.Error())
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
		if werr := WriteConf(conf); werr != nil {
			flash("apply: write conf: " + werr.Error())
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
		msg := fmt.Sprintf("applied %d change(s)", count)
		if summary := unloadSummaryLine(buf.String()); summary != "" {
			msg += " — " + summary
		}
		flash(msg)
	}

	applyFilter()
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
			case "<Tab>", "<Right>", "l":
				if focus == focusGroups {
					focus = focusRules
				}
				render()
			case "<Left>", "h":
				if focus == focusRules {
					focus = focusGroups
				}
				render()
			case "<Enter>":
				if focus == focusGroups && len(rulesInGroup) > 0 {
					focus = focusRules
				}
				render()
			case "<Up>", "k":
				if focus == focusGroups {
					if groupCursor > 0 {
						groupCursor--
						recomputeRulesInGroup()
					}
				} else if ruleCursor > 0 {
					ruleCursor--
				}
				render()
			case "<Down>", "j":
				if focus == focusGroups {
					if groupCursor < len(groups)-1 {
						groupCursor++
						recomputeRulesInGroup()
					}
				} else if ruleCursor < len(rulesInGroup)-1 {
					ruleCursor++
				}
				render()
			case "<Home>", "g":
				if focus == focusGroups {
					if groupCursor != 0 {
						groupCursor = 0
						recomputeRulesInGroup()
					}
				} else {
					ruleCursor = 0
				}
				render()
			case "<End>", "G":
				if focus == focusGroups {
					if last := len(groups) - 1; last >= 0 && groupCursor != last {
						groupCursor = last
						recomputeRulesInGroup()
					}
				} else if len(rulesInGroup) > 0 {
					ruleCursor = len(rulesInGroup) - 1
				}
				render()
			case "<PageUp>":
				if focus == focusGroups {
					groupCursor -= groupsPageSize()
					if groupCursor < 0 {
						groupCursor = 0
					}
					recomputeRulesInGroup()
				} else {
					ruleCursor -= rulesPageSize()
					if ruleCursor < 0 {
						ruleCursor = 0
					}
				}
				render()
			case "<PageDown>":
				if focus == focusGroups {
					groupCursor += groupsPageSize()
					if groupCursor >= len(groups) {
						groupCursor = len(groups) - 1
					}
					recomputeRulesInGroup()
				} else {
					ruleCursor += rulesPageSize()
					if ruleCursor >= len(rulesInGroup) {
						ruleCursor = len(rulesInGroup) - 1
					}
				}
				render()
			case "r":
				refresh()
				flash("refreshed")
				render()
			case "t":
				return true, nil
			case "e":
				if ruleCursor >= 0 && ruleCursor < len(rulesInGroup) {
					pending[rulesInGroup[ruleCursor].ID] = OverrideForce
				}
				render()
			case "d":
				if ruleCursor >= 0 && ruleCursor < len(rulesInGroup) {
					pending[rulesInGroup[ruleCursor].ID] = OverrideSkip
				}
				render()
			case "u":
				if ruleCursor >= 0 && ruleCursor < len(rulesInGroup) {
					delete(pending, rulesInGroup[ruleCursor].ID)
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
			case "m":
				if runModulesScreen() {
					return false, nil
				}
				layout()
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

// bootDivergenceMsg surfaces bootloader-read failures in the TUI
// header. BuildAuditRows attaches the bootloader error to every
// boot-arg row's Error field; all such rows share the same message,
// so we just pick the first non-empty one and short-summarise it.
func bootDivergenceMsg(rows []AuditRow) string {
	for _, r := range rows {
		if r.Kind != KindBoot || r.Error == "" {
			continue
		}
		if strings.Contains(r.Error, "diverge") {
			return "divergence — will auto-reconcile on apply"
		}
		return "next-boot unreadable"
	}
	return ""
}

// buildGroupList returns the distinct (Tier, Kind, Group) tuples in
// the same stable order as `rows`, with a count of rules per tuple.
// Sorted upstream by Tier (in RunTUI), so groups inherit that order:
// all T1 groups before T2.
func buildGroupList(rows []AuditRow) []groupKey {
	seen := map[string]int{}
	var groups []groupKey
	for _, r := range rows {
		key := fmt.Sprintf("%d|%s|%s", r.Tier, r.Kind, r.Group)
		if idx, ok := seen[key]; ok {
			groups[idx].Count++
			continue
		}
		seen[key] = len(groups)
		groups = append(groups, groupKey{
			Tier:  r.Tier,
			Kind:  r.Kind,
			Group: r.Group,
			Count: 1,
		})
	}
	return groups
}

// groupWorstColor returns the worst state color across all rules in a
// group, so the LEFT pane's row color flags any group that contains a
// drifted/diff/missing rule. Pending overrides anywhere in the group
// promote the row to magenta, matching the rule-pane convention.
func groupWorstColor(rows []AuditRow, g groupKey, pending map[string]RuleOverride) ui.Color {
	rank := func(c ui.Color) int {
		switch c {
		case ui.ColorRed:
			return 4
		case ui.ColorYellow:
			return 3
		case ui.ColorWhite:
			return 2
		case ui.ColorGreen:
			return 1
		}
		return 0
	}
	worst := ui.ColorGreen
	hasPending := false
	for _, r := range rows {
		if r.Tier != g.Tier || r.Kind != g.Kind || r.Group != g.Group {
			continue
		}
		if _, p := pending[r.ID]; p {
			hasPending = true
		}
		if c := StateColor(r.State); rank(c) > rank(worst) {
			worst = c
		}
	}
	if hasPending {
		return ui.ColorMagenta
	}
	return worst
}

// paneBorderStyle / paneTitleStyle make the focused pane's border and
// title pop in bold cyan so the operator can see at a glance which
// pane consumes ↑/↓ and apply-queue keys.
func paneBorderStyle(focused bool) ui.Style {
	if focused {
		return ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)
	}
	return ui.NewStyle(ui.ColorWhite)
}

func paneTitleStyle(focused bool) ui.Style {
	if focused {
		return ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold)
	}
	return ui.NewStyle(ui.ColorWhite)
}
