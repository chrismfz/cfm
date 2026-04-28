package healthcli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

const liveTrendLen = 1800 // enough for 30m @ 1s polls

type liveRing struct {
	buf  [liveTrendLen]float64
	head int
	size int
}

func (r *liveRing) push(v float64) {
	r.buf[r.head] = v
	r.head = (r.head + 1) % liveTrendLen
	if r.size < liveTrendLen {
		r.size++
	}
}

func (r *liveRing) slice(n int) []float64 {
	if n > r.size {
		n = r.size
	}
	if n < 2 {
		return []float64{0, 0}
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		idx := (r.head - n + i + liveTrendLen) % liveTrendLen
		out[i] = r.buf[idx]
	}
	return out
}

type liveCfg struct {
	interval    time.Duration
	windowIndex int
}

var liveWindows = []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute}

func parseLiveConfig(args []string) liveCfg {
	cfg := liveCfg{interval: 2 * time.Second}
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		switch {
		case a == "--interval" || a == "-i":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
					cfg.interval = d
				}
			}
		case strings.HasPrefix(a, "--interval="):
			if d, err := time.ParseDuration(strings.TrimPrefix(a, "--interval=")); err == nil && d > 0 {
				cfg.interval = d
			}
		default:
			if n, err := strconv.Atoi(a); err == nil && n > 0 {
				cfg.interval = time.Duration(n) * time.Second
			}
		}
	}
	return cfg
}

func runLive(baseURL string, args []string, opts cliOptions) error {
	cfg := parseLiveConfig(args)
	if err := ui.Init(); err != nil {
		return fmt.Errorf("termui init: %w", err)
	}
	defer ui.Close()

	header := widgets.NewParagraph()
	header.Border = false
	help := widgets.NewParagraph()
	help.Border = false

	cpuPlot := widgets.NewPlot()
	cpuPlot.Title = " CPU % "
	cpuPlot.LineColors = []ui.Color{ui.ColorRed}
	cpuPlot.Data = [][]float64{{0, 0}}
	cpuPlot.AxesColor = ui.ColorWhite

	ramPlot := widgets.NewPlot()
	ramPlot.Title = " RAM % "
	ramPlot.LineColors = []ui.Color{ui.ColorCyan}
	ramPlot.Data = [][]float64{{0, 0}}
	ramPlot.AxesColor = ui.ColorWhite

	diskPlot := widgets.NewPlot()
	diskPlot.Title = " Disk % (max mount) "
	diskPlot.LineColors = []ui.Color{ui.ColorYellow}
	diskPlot.Data = [][]float64{{0, 0}}
	diskPlot.AxesColor = ui.ColorWhite

	netPlot := widgets.NewPlot()
	netPlot.Title = " Network throughput MiB/s (in/out) "
	netPlot.LineColors = []ui.Color{ui.ColorGreen, ui.ColorMagenta}
	netPlot.Data = [][]float64{{0, 0}, {0, 0}}
	netPlot.AxesColor = ui.ColorWhite

	diskTable := widgets.NewTable()
	diskTable.Title = " Disk mounts "
	diskTable.FillRow = true
	diskTable.RowSeparator = false
	diskTable.Rows = [][]string{{"state", "mount", "used/total/free", "disk %", "inode %"}}

	runtimeTable := widgets.NewTable()
	runtimeTable.Title = " Runtime "
	runtimeTable.FillRow = true
	runtimeTable.RowSeparator = false
	runtimeTable.Rows = [][]string{{"cfm live", "dnat"}, {"down", "unknown"}}

	svcTable := widgets.NewTable()
	svcTable.Title = " Service states "
	svcTable.FillRow = true
	svcTable.RowSeparator = false
	svcTable.Rows = [][]string{{"service", "state", "enabled", "last_error"}}

	diskDevices := widgets.NewTable()
	diskDevices.Title = " Disk SMART devices "
	diskDevices.FillRow = true
	diskDevices.RowSeparator = false
	diskDevices.Rows = [][]string{{"device", "model", "serial", "type", "normalized health", "wearout %", "wearout source", "temp", "probe/error"}}

	grid := ui.NewGrid()
	layout := func() {
		w, h := ui.TerminalDimensions()
		grid.SetRect(0, 0, w, h)
		grid.Set(
			ui.NewRow(0.08, ui.NewCol(1.0, header)),
			ui.NewRow(0.06, ui.NewCol(1.0, help)),
			ui.NewRow(0.24, ui.NewCol(0.5, cpuPlot), ui.NewCol(0.5, ramPlot)),
			ui.NewRow(0.24, ui.NewCol(0.5, diskPlot), ui.NewCol(0.5, netPlot)),
			ui.NewRow(0.20, ui.NewCol(0.55, diskTable), ui.NewCol(0.45, runtimeTable)),
			ui.NewRow(0.22, ui.NewCol(0.5, svcTable), ui.NewCol(0.5, diskDevices)),
		)
	}
	layout()

	var (
		cpuRing   liveRing
		ramRing   liveRing
		diskRing  liveRing
		netInRing liveRing
		netOuRing liveRing

		lastErr   string
		lastStamp string
		paused    bool
	)

	render := func() {
		window := liveWindows[cfg.windowIndex]
		points := int(window / cfg.interval)
		if points < 2 {
			points = 2
		}
		if points > liveTrendLen {
			points = liveTrendLen
		}

		state := "running"
		if paused {
			state = "paused"
		}
		header.Text = fmt.Sprintf(
			"cfm health live  host=%s  interval=%s  window=%s  status=%s  updated=%s",
			baseURL, cfg.interval, window, state, nonEmptyOr(lastStamp, "n/a"),
		)
		help.Text = "keys: q quit • p/space pause-resume • w switch window (1m/5m/15m)"
		if lastErr != "" {
			header.Text += "  error=" + lastErr
		}

		cpuPlot.Data = [][]float64{cpuRing.slice(points)}
		ramPlot.Data = [][]float64{ramRing.slice(points)}
		diskPlot.Data = [][]float64{diskRing.slice(points)}
		netPlot.Data = [][]float64{netInRing.slice(points), netOuRing.slice(points)}

		ui.Render(grid)
	}

	refresh := func() {
		s, err := fetchSnapshot(baseURL)
		if err != nil {
			lastErr = err.Error()
			return
		}
		lastErr = ""
		lastStamp = chooseCollectedAt(s).Local().Format("15:04:05")
		cpu := nonZero(s.Modern.Host.CPUPercent, nonZero(s.Legacy.Load1*25, s.Modern.Host.LoadAvg1*25))
		ramPct := s.Legacy.RamUsedPct
		if s.Modern.Host.MemTotalBytes > 0 {
			ramPct = 100 * float64(s.Modern.Host.MemUsedBytes) / float64(s.Modern.Host.MemTotalBytes)
		}
		maxDisk := nonZero(s.Legacy.DiskRootPct, s.Legacy.DiskTmpPct)
		for _, m := range s.Modern.Disk.Mounts {
			if m.UsedPct > maxDisk {
				maxDisk = m.UsedPct
			}
		}
		inBps, outBps := networkBps(s)

		cpuRing.push(cpu)
		ramRing.push(ramPct)
		diskRing.push(maxDisk)
		netInRing.push(float64(inBps) / (1024 * 1024))
		netOuRing.push(float64(outBps) / (1024 * 1024))

		diskRows := collectDiskMountRows(s)
		diskTableRows := [][]string{{"state", "mount", "used/total/free", "disk %", "inode %"}}
		for _, r := range diskRows {
			status := labelByPct(r.usedPct)
			if r.hasInode && labelByPct(r.inodePct) > status {
				status = labelByPct(r.inodePct)
			}
			capacity := "n/a"
			if r.totalBytes > 0 {
				capacity = fmt.Sprintf("%s/%s/%s", bytesIEC(r.usedBytes), bytesIEC(r.totalBytes), bytesIEC(r.freeBytes))
			}
			inode := "n/a"
			if r.hasInode {
				inode = pctStr(r.inodePct)
			}
			diskTableRows = append(diskTableRows, []string{badge(status, opts), r.mount, capacity, pctStr(r.usedPct), inode})
		}
		if len(diskTableRows) == 1 {
			diskTableRows = append(diskTableRows, []string{"-", "(no data)", "-", "-", "-"})
		}
		diskTable.Rows = diskTableRows

		dnat := strings.TrimSpace(s.Modern.Runtime.DNATEnabled)
		if dnat == "" {
			dnat = "unknown"
		}
		liveState := "down"
		if s.Modern.Runtime.CFMDaemonLive {
			liveState = "live"
		}
		runtimeTable.Rows = [][]string{{"cfm live", "dnat"}, {liveState, dnat}}

		services := s.Modern.Services
		if len(services) == 0 {
			services = servicesFromRaw(s.RawMap)
		}
		svcRows := [][]string{{"service", "state", "enabled", "last_error"}}
		hasErr := false
		for _, svc := range services {
			state := strings.TrimSpace(svc.State)
			if state == "" {
				if svc.Active {
					state = "active"
				} else {
					state = "inactive"
				}
			}
			errText := strings.TrimSpace(svc.LastError)
			if errText != "" {
				hasErr = true
			}
			svcRows = append(svcRows, []string{svc.Name, state, boolYN(svc.Enabled), truncateText(errText, 36)})
		}
		if len(svcRows) == 1 {
			svcRows = append(svcRows, []string{"(no data)", "-", "-", "-"})
		} else if !hasErr {
			svcRows[0][3] = "-"
		}
		svcTable.Rows = svcRows

		devRows := collectDiskSmartRows(s)
		devTable := [][]string{{"device", "model", "serial", "type", "normalized health", "wearout %", "wearout source", "temp", "probe/error"}}
		maxRows := 8
		if len(devRows) > maxRows {
			devRows = devRows[:maxRows]
		}
		for _, row := range devRows {
			wear := "n/a"
			if row.WearoutUsed != nil {
				wear = fmt.Sprintf("%d%%", *row.WearoutUsed)
			}
			wearSource := nonEmptyOr(row.WearoutSource, "-")
			devTable = append(devTable, []string{
				row.Key,
				truncateIdentifier(nonEmptyOr(row.Model, "-"), 18, opts.FullIdent),
				maskOrTrimSerial(row.Serial, opts.FullIdent),
				truncateText(nonEmptyOr(row.DeviceType, "-"), 8),
				nonEmptyOr(row.Normalized, "unknown"),
				wear,
				truncateText(wearSource, 14),
				nonEmptyOr(row.TemperatureC, "-"),
				truncateText(nonEmptyOr(row.ProbeOrErr, "-"), 22),
			})
		}
		if len(devTable) == 1 {
			devTable = append(devTable, []string{"(no data)", "-", "-", "-", "-", "-", "-", "-", "-"})
		}
		diskDevices.Rows = devTable
	}

	refresh()
	render()

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	uiEvents := ui.PollEvents()
	for {
		select {
		case <-ticker.C:
			if !paused {
				refresh()
			}
			render()
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return nil
			case "p", "<Space>":
				paused = !paused
				render()
			case "w":
				cfg.windowIndex = (cfg.windowIndex + 1) % len(liveWindows)
				render()
			case "<Resize>":
				layout()
				render()
			}
		}
	}
}

func boolYN(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func truncateText(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) <= n {
		return v
	}
	if n <= 2 {
		return v[:n]
	}
	return v[:n-2] + ".."
}

func servicesFromRaw(m map[string]any) []serviceStatus {
	v, ok := m["services"]
	if !ok {
		return nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]serviceStatus, 0, len(raw))
	for _, item := range raw {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		s := serviceStatus{
			Name:      strings.TrimSpace(anyToString(row["name"])),
			Active:    anyToBool(row["active"]),
			Enabled:   anyToBool(row["enabled"]),
			State:     strings.TrimSpace(anyToString(row["state"])),
			LastError: strings.TrimSpace(anyToString(row["last_error"])),
		}
		if s.Name == "" {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func anyToString(v any) string {
	s, _ := v.(string)
	return s
}

func anyToBool(v any) bool {
	b, ok := v.(bool)
	if ok {
		return b
	}
	return false
}
