package kernsec

import (
	"fmt"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// runModulesScreen renders a self-contained "loaded modules signature
// audit" screen on top of the main TUI grid. Same Buckets | Items |
// Detail layout the audit screen uses, but the data source is
// CollectModuleAudit. Returns quit=true when the operator pressed q
// to exit the entire TUI; otherwise the caller should re-render the
// main rules screen.
//
// Lifecycle: the caller owns ui.Init / ui.Close. We just borrow the
// already-initialised termui session, swap the grid contents, and
// poll events until exit.
func runModulesScreen() (quit bool) {
	header := widgets.NewParagraph()
	header.Border = false
	header.PaddingLeft = 1

	bucketsTable := widgets.NewTable()
	bucketsTable.Title = " Buckets "
	bucketsTable.RowSeparator = false
	bucketsTable.FillRow = false
	bucketsTable.ColumnWidths = []int{20, 6}
	bucketsTable.TextAlignment = ui.AlignLeft

	modsTable := widgets.NewTable()
	modsTable.Title = " Modules "
	modsTable.RowSeparator = false
	modsTable.FillRow = false
	modsTable.ColumnWidths = []int{30}
	modsTable.TextAlignment = ui.AlignLeft

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
				ui.NewCol(0.25, bucketsTable),
				ui.NewCol(0.30, modsTable),
				ui.NewCol(0.45, detail),
			),
			ui.NewRow(0.08, ui.NewCol(1.0, footer)),
		)
	}
	layout()

	audit := CollectModuleAudit()
	// Display order matches the rendered text report: surface the
	// risk-relevant buckets (unsigned, signed-untrusted, unknown)
	// before trusted, since "trusted" is the no-action bucket.
	bucketOrder := []ModuleSigBucket{
		ModuleSigUnsigned,
		ModuleSigSignedUntrusted,
		ModuleSigUnknown,
		ModuleSigTrusted,
	}
	visibleBuckets := bucketOrder[:0:0]
	for _, b := range bucketOrder {
		if audit.Counts[b] > 0 {
			visibleBuckets = append(visibleBuckets, b)
		}
	}

	// Empty audit (no modinfo, empty /proc/modules): drop in a single
	// pseudo-bucket so the panes still render something useful instead
	// of three empty boxes.
	emptyAudit := len(visibleBuckets) == 0

	const (
		focusBucketsM = 0
		focusModsM    = 1
	)
	focus := focusBucketsM
	bucketCursor, bucketOffset := 0, 0
	modCursor, modOffset := 0, 0
	statusMsg := ""
	statusUntil := time.Time{}
	showHelp := false

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

	currentBucket := func() (ModuleSigBucket, bool) {
		if emptyAudit || bucketCursor < 0 || bucketCursor >= len(visibleBuckets) {
			return ModuleSigUnknown, false
		}
		return visibleBuckets[bucketCursor], true
	}

	modsInBucket := func() []ModuleAuditEntry {
		bk, ok := currentBucket()
		if !ok {
			return nil
		}
		out := make([]ModuleAuditEntry, 0, audit.Counts[bk])
		for _, e := range audit.Entries {
			if e.Bucket == bk {
				out = append(out, e)
			}
		}
		return out
	}

	flash := func(msg string) {
		statusMsg = msg
		statusUntil = time.Now().Add(3 * time.Second)
	}

	bucketColor := func(b ModuleSigBucket) ui.Color {
		switch b {
		case ModuleSigTrusted:
			return ui.ColorGreen
		case ModuleSigSignedUntrusted:
			return ui.ColorYellow
		case ModuleSigUnsigned:
			return ui.ColorRed
		default:
			return ui.ColorMagenta
		}
	}
	bucketColorName := func(b ModuleSigBucket) string {
		switch b {
		case ModuleSigTrusted:
			return "green"
		case ModuleSigSignedUntrusted:
			return "yellow"
		case ModuleSigUnsigned:
			return "red"
		default:
			return "magenta"
		}
	}

	renderHeader := func() {
		header.Text = fmt.Sprintf(
			"[cfm kernsec — modules audit](fg:cyan,mod:bold)  •  loaded: %d  •  trusted: [%d](fg:green)  •  signed-untrusted: [%d](fg:yellow)  •  unsigned: [%d](fg:red)  •  unknown: [%d](fg:magenta)",
			len(audit.Entries),
			audit.Counts[ModuleSigTrusted],
			audit.Counts[ModuleSigSignedUntrusted],
			audit.Counts[ModuleSigUnsigned],
			audit.Counts[ModuleSigUnknown],
		)
		if audit.TaintBitUnsigned {
			header.Text += "  •  [TAINT 13: unsigned module loaded since boot](fg:red,mod:bold)"
		}
		if audit.ModinfoMissing {
			header.Text += "  •  [modinfo missing — verdicts unavailable](fg:yellow,mod:bold)"
		}
	}

	rebuildBucketsTable := func() {
		ps := pageSizeOf(bucketsTable)
		clampOffset(bucketCursor, len(visibleBuckets), ps, &bucketOffset)
		end := bucketOffset + ps
		if end > len(visibleBuckets) {
			end = len(visibleBuckets)
		}
		visible := visibleBuckets[bucketOffset:end]

		rs := make([][]string, 0, len(visible)+1)
		rs = append(rs, []string{"BUCKET", "N"})
		for _, b := range visible {
			rs = append(rs, []string{b.String(), fmt.Sprintf("%d", audit.Counts[b])})
		}
		if emptyAudit {
			rs = append(rs, []string{"(none loaded)", "0"})
		}
		bucketsTable.Rows = rs
		bucketsTable.RowStyles = map[int]ui.Style{
			0: ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold),
		}
		for i, b := range visible {
			bucketsTable.RowStyles[i+1] = ui.NewStyle(bucketColor(b))
		}
		if !emptyAudit && bucketCursor >= bucketOffset && bucketCursor < end {
			sel := bucketCursor - bucketOffset + 1
			c := bucketColor(visibleBuckets[bucketCursor])
			if focus == focusBucketsM {
				bucketsTable.RowStyles[sel] = ui.NewStyle(ui.ColorBlack, c)
			} else {
				bucketsTable.RowStyles[sel] = ui.NewStyle(c, ui.ColorClear, ui.ModifierBold)
			}
		}
		bucketsTable.BorderStyle = paneBorderStyle(focus == focusBucketsM)
		bucketsTable.TitleStyle = paneTitleStyle(focus == focusBucketsM)
	}

	rebuildModsTable := func() {
		mods := modsInBucket()
		if modCursor >= len(mods) {
			modCursor = len(mods) - 1
		}
		if modCursor < 0 {
			modCursor = 0
		}
		ps := pageSizeOf(modsTable)
		clampOffset(modCursor, len(mods), ps, &modOffset)
		end := modOffset + ps
		if end > len(mods) {
			end = len(mods)
		}
		visible := mods[modOffset:end]

		modW := modsTable.Inner.Dx() - 1
		if modW < 16 {
			modW = 16
		}
		modsTable.ColumnWidths = []int{modW}

		rs := make([][]string, 0, len(visible)+1)
		rs = append(rs, []string{"MODULE"})
		for _, e := range visible {
			rs = append(rs, []string{e.Name})
		}
		modsTable.Rows = rs
		modsTable.RowStyles = map[int]ui.Style{
			0: ui.NewStyle(ui.ColorCyan, ui.ColorClear, ui.ModifierBold),
		}
		bk, ok := currentBucket()
		var c ui.Color = ui.ColorWhite
		if ok {
			c = bucketColor(bk)
		}
		for i := range visible {
			modsTable.RowStyles[i+1] = ui.NewStyle(c)
		}
		if len(mods) > 0 && modCursor >= modOffset && modCursor < end {
			sel := modCursor - modOffset + 1
			if focus == focusModsM {
				modsTable.RowStyles[sel] = ui.NewStyle(ui.ColorBlack, c)
			} else {
				modsTable.RowStyles[sel] = ui.NewStyle(c, ui.ColorClear, ui.ModifierBold)
			}
		}
		bk2, ok2 := currentBucket()
		if ok2 {
			modsTable.Title = fmt.Sprintf(" Modules — %s (%d) ", bk2, audit.Counts[bk2])
		} else {
			modsTable.Title = " Modules "
		}
		modsTable.BorderStyle = paneBorderStyle(focus == focusModsM)
		modsTable.TitleStyle = paneTitleStyle(focus == focusModsM)
	}

	renderDetail := func() {
		mods := modsInBucket()
		if len(mods) == 0 || modCursor < 0 || modCursor >= len(mods) {
			detail.Text = "(no module selected)"
			return
		}
		e := mods[modCursor]
		var b strings.Builder
		fmt.Fprintf(&b, "[Module:](fg:cyan,mod:bold) %s\n\n", e.Name)
		fmt.Fprintf(&b, "[Bucket:](fg:cyan)  [%s](fg:%s,mod:bold)\n",
			e.Bucket, bucketColorName(e.Bucket))
		fmt.Fprintf(&b, "[Path:](fg:cyan)    %s\n", nonEmpty(e.Path, "(unknown)"))
		if e.Size > 0 {
			fmt.Fprintf(&b, "[Size:](fg:cyan)    %d bytes\n", e.Size)
		}
		fmt.Fprintf(&b, "[Signed:](fg:cyan)  %s\n", yesNo(e.Signed))
		if e.Signer != "" {
			fmt.Fprintf(&b, "[Signer:](fg:cyan)  %s\n", e.Signer)
		}
		if e.SigHashAlgo != "" {
			fmt.Fprintf(&b, "[Hash:](fg:cyan)    %s\n", e.SigHashAlgo)
		}
		if e.SigKeyID != "" {
			fmt.Fprintf(&b, "[Key ID:](fg:cyan)  %s\n", e.SigKeyID)
		}
		if e.TrustReason != "" {
			fmt.Fprintf(&b, "\n[Verdict:](fg:cyan)\n  %s\n", e.TrustReason)
		}
		if e.ReadErr != "" {
			fmt.Fprintf(&b, "\n[Read error:](fg:yellow)\n  %s\n", e.ReadErr)
		}
		if audit.TaintBitUnsigned {
			fmt.Fprintln(&b, "")
			fmt.Fprintln(&b, "[Note:](fg:yellow,mod:bold) kernel taint bit 13 is set —")
			fmt.Fprintln(&b, "an unsigned module loaded into this kernel since boot,")
			fmt.Fprintln(&b, "potentially one no longer in /proc/modules.")
		}
		detail.Text = b.String()
	}

	renderFooter := func() {
		if showHelp {
			footer.Text = "[help](fg:cyan,mod:bold)  Read-only signature audit. [m](fg:cyan)/[Esc](fg:cyan) return to rules.  [r](fg:cyan)efresh re-runs modinfo across loaded modules."
			return
		}
		if statusMsg != "" && time.Now().Before(statusUntil) {
			footer.Text = fmt.Sprintf("[%s](fg:yellow)", statusMsg)
			return
		}
		footer.Text = "[m/Esc](fg:cyan) back  [q](fg:cyan)uit  [←/→/Tab](fg:cyan) pane  [↑/↓](fg:cyan) nav  [r](fg:cyan)efresh  [?](fg:cyan) help"
	}

	render := func() {
		renderHeader()
		rebuildBucketsTable()
		rebuildModsTable()
		renderDetail()
		renderFooter()
		ui.Render(grid)
	}
	render()

	events := ui.PollEvents()
	for {
		e := <-events
		switch e.ID {
		case "q", "<C-c>":
			return true
		case "m", "<Escape>":
			return false
		case "<Tab>", "<Right>", "l":
			if focus == focusBucketsM {
				focus = focusModsM
			}
			render()
		case "<Left>", "h":
			if focus == focusModsM {
				focus = focusBucketsM
			}
			render()
		case "<Up>", "k":
			if focus == focusBucketsM {
				if bucketCursor > 0 {
					bucketCursor--
					modCursor, modOffset = 0, 0
				}
			} else if modCursor > 0 {
				modCursor--
			}
			render()
		case "<Down>", "j":
			if focus == focusBucketsM {
				if bucketCursor < len(visibleBuckets)-1 {
					bucketCursor++
					modCursor, modOffset = 0, 0
				}
			} else {
				if mods := modsInBucket(); modCursor < len(mods)-1 {
					modCursor++
				}
			}
			render()
		case "<Home>", "g":
			if focus == focusBucketsM {
				bucketCursor = 0
				modCursor, modOffset = 0, 0
			} else {
				modCursor = 0
			}
			render()
		case "<End>", "G":
			if focus == focusBucketsM {
				if last := len(visibleBuckets) - 1; last >= 0 {
					bucketCursor = last
					modCursor, modOffset = 0, 0
				}
			} else if mods := modsInBucket(); len(mods) > 0 {
				modCursor = len(mods) - 1
			}
			render()
		case "<PageUp>":
			if focus == focusBucketsM {
				bucketCursor -= pageSizeOf(bucketsTable)
				if bucketCursor < 0 {
					bucketCursor = 0
				}
				modCursor, modOffset = 0, 0
			} else {
				modCursor -= pageSizeOf(modsTable)
				if modCursor < 0 {
					modCursor = 0
				}
			}
			render()
		case "<PageDown>":
			if focus == focusBucketsM {
				bucketCursor += pageSizeOf(bucketsTable)
				if bucketCursor >= len(visibleBuckets) {
					bucketCursor = len(visibleBuckets) - 1
				}
				modCursor, modOffset = 0, 0
			} else {
				mods := modsInBucket()
				modCursor += pageSizeOf(modsTable)
				if modCursor >= len(mods) {
					modCursor = len(mods) - 1
				}
			}
			render()
		case "r":
			audit = CollectModuleAudit()
			visibleBuckets = bucketOrder[:0:0]
			for _, b := range bucketOrder {
				if audit.Counts[b] > 0 {
					visibleBuckets = append(visibleBuckets, b)
				}
			}
			emptyAudit = len(visibleBuckets) == 0
			if bucketCursor >= len(visibleBuckets) {
				bucketCursor = 0
			}
			modCursor, modOffset = 0, 0
			flash("refreshed")
			render()
		case "?":
			showHelp = !showHelp
			render()
		case "<Resize>":
			layout()
			render()
		}
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
