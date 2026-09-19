package mcpserver

// whats_wrong.go implements the flagship triage tool: one read-only call that
// pulls the key health/process/security/mail/db signals concurrently (the SAME allow-listed
// GET endpoints the other tools use), runs a CONSERVATIVE rule set over them, and
// returns a severity-ranked list of concrete problems — each with a one-line
// detail and a pointer to the drill-down tool to call next.
//
// Design notes:
//   - Read-only + bounded like security_overview: sections run concurrently under
//     the shared per-section budget, so latency is ~the slowest section.
//   - The evaluator (evaluateWhatsWrong) is pure and unit-tested: (sections) →
//     result. The handler only does the fetch + marshal.
//   - Deliberately under-flags. Every threshold is a named constant grounded in a
//     field the endpoint already computes; routine activity (WAF firing, normal
//     firewall blocks, busy top-talkers) is NOT a finding. Over-flagging is the
//     cardinal sin for a triage tool, so ambiguous signals stay out until proven.
//   - A section that errors or is unavailable (collector/governor off) is reported
//     in `sources` as error/unavailable — NOT silently treated as healthy. A
//     semantically degraded process-health snapshot is also surfaced explicitly.
//     status "ok" means "no findings among the signals we could actually read".

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Severity levels, ranked most-severe first.
const (
	sevCritical = "critical"
	sevWarning  = "warning"
	sevInfo     = "info"
)

// Thresholds — every one grounded in a field the source endpoint already computes.
// Kept conservative on purpose (see file header): under-flag rather than over-flag.
const (
	wwDiskWarnPct  = 90.0 // filesystem used%
	wwDiskCritPct  = 95.0
	wwInodeWarnPct = 90.0 // inode used%
	wwInodeCritPct = 95.0

	wwLoadWarnRatio = 4.0 // load_avg_5 ÷ cpu_threads (sustained load vs cores)
	wwLoadCritRatio = 8.0

	wwMemAvailWarnPct     = 5.0  // warn when <5% of RAM is available (accounts for cache)
	wwMemPressureAvailPct = 10.0 // swap only counts as pressure when RAM is also this tight
	wwSwapWarnPct         = 50.0 // ...AND at least this much swap is in use

	wwConntrackWarnPct = 90.0
	wwConntrackCritPct = 98.0

	wwMySQLConnWarnPct = 85.0
	wwMySQLConnCritPct = 95.0

	wwMailFrozenWarn = 100 // stuck (frozen) messages in the mail queue
	wwMailFrozenCrit = 1000

	wwSvcFlapRestarts = 5 // systemd NRestarts — a flapping service

	wwAPIAnomalyWarnCount = 10 // >= this many API-abuse anomaly events → warning, else info
	wwMailAnomalyCap      = 5  // max individual mail-anomaly findings to emit

	// Memory ECC (EDAC) — cumulative-since-boot counters from the health snapshot.
	// An uncorrected error is a data-integrity/imminent-crash event → critical at
	// the first one. Corrected errors are surfaced as a warning at the first one:
	// a single corrected flip is benign, but a rising count is the classic DIMM
	// pre-failure signal, and this operator's stated priority is to SEE hardware
	// errors rather than have them silently pass a green health check. The finding
	// carries the raw count and points at dmesg_tail for the rate/timing; raise
	// wwECCCorrectedWarn if lifetime one-offs prove noisy across a fleet.
	wwECCUncorrectedCrit = 1
	wwECCCorrectedWarn   = 1
)

// categoryOrder gives a stable secondary sort within a severity tier.
var categoryOrder = map[string]int{
	"edge":       0,
	"hardware":   1,
	"service":    2,
	"process":    3,
	"disk":       4,
	"memory":     5,
	"load":       6,
	"network":    7,
	"firewall":   8,
	"mysql":      9,
	"mail_queue": 10,
	"mail":       11,
	"panel":      12,
	"abuse":      13,
	"health":     14,
}

// finding is one ranked triage item.
type finding struct {
	Severity string         `json:"severity"`
	Category string         `json:"category"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
	Tool     string         `json:"tool,omitempty"` // MCP tool to drill in with
	Args     map[string]any `json:"args,omitempty"`
}

// whatsWrongResult is the tool's rendered output.
type whatsWrongResult struct {
	Status   string            `json:"status"`  // "ok" | "issues"
	Summary  string            `json:"summary"` // human one-liner
	Counts   map[string]int    `json:"counts"`  // critical/warning/info
	Sources  map[string]string `json:"sources"` // per-signal: ok | unavailable | degraded: <msg> | error: <msg>
	Findings []finding         `json:"findings"`
}

func registerWhatsWrong(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "whats_wrong",
		Description: "Triage in one call: pulls host health, memory ECC/hardware errors, process-health anomalies, systemd services, netfilter priority diagnostics, MySQL saturation, mail/runtime anomalies, API abuse, panel burn-in, and the edge→origin hop (edge_health: origin premature-closes/gateway 5xx, cross-SNI 421 reuse, origin-keepalive degradation) together, then returns a SEVERITY-RANKED list of concrete problems with the drill-down tool. Catches the class where the edge and every daemon are 'up' but the ORIGIN is dropping requests — 502s no host metric shows. Deliberately conservative: it flags equal-priority netfilter ambiguity and CFM runtime/config priority drift, but not intentional ordered Imunify/CFM overlap or routine WAF/firewall activity. `status:\"ok\"` means no problems among readable signals; `sources` shows unavailable/degraded/error inputs.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		secs := []struct {
			key, path string
			q         url.Values
		}{
			{"health", "/api/v1/health/snapshot", nil},
			{"process_health", "/api/v1/system/process-health", nil},
			{"anomalies", "/api/v1/health/anomalies", nil},
			{"services", "/api/v1/system/services", nil},
			{"netfilter_path", "/api/v1/firewall/path", nil},
			{"mysql", "/api/v1/mysql/top", nil},
			{"mail_queue", "/api/v1/system/mail-queue", nil},
			{"mail_traffic", "/api/v1/mail/traffic", nil},
			{"mail_runtime", "/api/v1/mail/runtime", nil},
			{"panel_burnin", "/api/v1/system/waf-fp-hunt", nil},
			{"edge_health", "/api/v1/system/edge-health", nil},
		}
		bodies := make(map[string]json.RawMessage, len(secs))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, s := range secs {
			wg.Add(1)
			go func(key, path string, q url.Values) {
				defer wg.Done()
				res := sectionBudgeted(ctx, d, path, q)
				mu.Lock()
				bodies[key] = res
				mu.Unlock()
			}(s.key, s.path, s.q)
		}
		wg.Wait()

		b, err := marshal(evaluateWhatsWrong(bodies))
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

// evaluateWhatsWrong applies the rule set to the fetched section bodies and returns
// the ranked result. Pure (no I/O) so it is fully unit-tested. Each body is either
// an endpoint payload or a section stub ({"error":...}); a missing/errored/unavailable
// section is recorded in Sources rather than silently passing.
func evaluateWhatsWrong(sections map[string]json.RawMessage) whatsWrongResult {
	var fs []finding
	sources := map[string]string{}

	// mark records a section's read outcome. Returns true when the body is usable
	// (parsed as a JSON object and not a section-error stub).
	usable := func(key string, body json.RawMessage) bool {
		if len(body) == 0 {
			sources[key] = "error: no response"
			return false
		}
		if e := sectionError(body); e != "" {
			sources[key] = "error: " + e
			return false
		}
		if !json.Valid(body) {
			sources[key] = "error: invalid JSON"
			return false
		}
		sources[key] = "ok"
		return true
	}

	// Resolve the active edge engine (angie|openresty|nginx) from the health
	// snapshot. A node runs ONE edge; the idle alternate is installed-but-
	// disabled and legitimately reports failed/inactive, so evalServices uses
	// this to suppress that false "service failed" critical. When the edge can't
	// be resolved the collector emits the sentinel "unknown" (and a missing/
	// errored health section leaves this ""); neither is a known engine, so
	// evalServices suppresses nothing and still flags a failed edge — never
	// masking a real edge-down. The ACTIVE edge's own health is additionally
	// evaluated authoritatively by evalHealth (edge_status / frontend_working).
	edgeService := ""
	if body, ok := sections["health"]; ok && json.Valid(body) && sectionError(body) == "" {
		var h struct {
			Runtime struct {
				EdgeService string `json:"edge_service"`
			} `json:"runtime"`
		}
		if json.Unmarshal(body, &h) == nil {
			edgeService = strings.ToLower(strings.TrimSpace(h.Runtime.EdgeService))
		}
	}

	if body, ok := sections["health"]; ok && usable("health", body) {
		fs = append(fs, evalHealth(body)...)
		fs = append(fs, evalHardware(body)...)
	}
	if body, ok := sections["process_health"]; ok && usable("process_health", body) {
		fs = append(fs, evalProcessHealth(body, sources)...)
	}
	if body, ok := sections["services"]; ok && usable("services", body) {
		fs = append(fs, evalServices(body, edgeService)...)
	}
	if body, ok := sections["netfilter_path"]; ok && usable("netfilter_path", body) {
		fs = append(fs, evalNetfilterPath(body, sources)...)
	}
	if body, ok := sections["mysql"]; ok && usable("mysql", body) {
		fs = append(fs, evalMySQL(body)...)
	}
	if body, ok := sections["mail_queue"]; ok && usable("mail_queue", body) {
		fs = append(fs, evalMailQueue(body, sources)...)
	}
	if body, ok := sections["mail_traffic"]; ok && usable("mail_traffic", body) {
		fs = append(fs, evalMailTraffic(body, sources)...)
	}
	if body, ok := sections["mail_runtime"]; ok && usable("mail_runtime", body) {
		fs = append(fs, evalMailRuntime(body)...)
	}
	if body, ok := sections["anomalies"]; ok && usable("anomalies", body) {
		fs = append(fs, evalAnomalies(body)...)
	}
	if body, ok := sections["panel_burnin"]; ok && usable("panel_burnin", body) {
		fs = append(fs, evalPanelBurnIn(body)...)
	}
	// Edge→origin hop. Gated on the health snapshot resolving a KNOWN edge
	// engine (the same edgeEngineUnits predicate evalServices uses): on a node
	// that runs no edge, a stale access log left behind by a removed engine
	// must not be read as live origin failure. When the engine is unresolved we
	// evaluate nothing here — evalHealth still covers edge liveness, and the
	// section's own read outcome is recorded in `sources` either way.
	if body, ok := sections["edge_health"]; ok && usable("edge_health", body) {
		if edgeEngineUnits[edgeService] {
			fs = append(fs, evalEdgeHealth(body)...)
		} else {
			// The gate fired, so nothing here was evaluated. Say so: leaving
			// `sources` reading "ok" would drop a live origin-drop critical with
			// no trace in the output — and this path is reached not only on a
			// node that runs no edge, but whenever the `health` section itself
			// timed out or failed, which is precisely when a silent drop is
			// most misleading.
			sources["edge_health"] = "degraded: not evaluated — active edge engine unresolved (no edge on this node, or the health section was unreadable)"
		}
	}

	sortFindings(fs)

	counts := map[string]int{sevCritical: 0, sevWarning: 0, sevInfo: 0}
	for _, f := range fs {
		counts[f.Severity]++
	}
	status := "ok"
	if counts[sevCritical] > 0 || counts[sevWarning] > 0 {
		status = "issues"
	}
	return whatsWrongResult{
		Status:   status,
		Summary:  summarize(counts),
		Counts:   counts,
		Sources:  sources,
		Findings: fs,
	}
}

func summarize(counts map[string]int) string {
	if counts[sevCritical] == 0 && counts[sevWarning] == 0 && counts[sevInfo] == 0 {
		return "no problems detected among the readable signals"
	}
	parts := make([]string, 0, 3)
	for _, s := range []string{sevCritical, sevWarning, sevInfo} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

// readonlyImageFS reports read-only image filesystems that legitimately sit at
// ~100% used (snaps, mounted ISOs), so a disk-fullness rule must skip them.
func readonlyImageFS(fsType string) bool {
	switch fsType {
	case "squashfs", "iso9660", "erofs", "cramfs", "romfs":
		return true
	}
	return false
}

// catRank orders a category within a severity tier. An unmapped category sorts
// LAST (not first), so adding a category without a categoryOrder entry degrades
// gracefully instead of silently jumping to the top.
func catRank(c string) int {
	if r, ok := categoryOrder[c]; ok {
		return r
	}
	return len(categoryOrder) + 1
}

func sevRank(s string) int {
	switch s {
	case sevCritical:
		return 0
	case sevWarning:
		return 1
	default:
		return 2
	}
}

func sortFindings(fs []finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := sevRank(fs[i].Severity), sevRank(fs[j].Severity); a != b {
			return a < b
		}
		if a, b := catRank(fs[i].Category), catRank(fs[j].Category); a != b {
			return a < b
		}
		return fs[i].Title < fs[j].Title
	})
}

// ── per-section evaluators ──────────────────────────────────────────────────────

func evalHealth(body json.RawMessage) []finding {
	// Note: a snapshot with a total-collector-panic `error` set carries no host/disk
	// data, and the section-error stub check in usable() already routes such a body
	// to an errored source before we get here — so there is no h.Error rule; when we
	// reach this point the snapshot has real data to evaluate.
	var h struct {
		Host struct {
			Load5      float64 `json:"load_avg_5"`
			CPUThreads int     `json:"cpu_threads"`
			MemTotal   uint64  `json:"mem_total_bytes"`
			MemAvail   uint64  `json:"mem_available_bytes"`
			SwapUsed   uint64  `json:"swap_used_bytes"`
			SwapTotal  uint64  `json:"swap_total_bytes"`
		} `json:"host"`
		Disk struct {
			Mounts []struct {
				Mount        string  `json:"mount"`
				FSType       string  `json:"fs_type"`
				UsedPct      float64 `json:"used_pct"`
				InodeUsedPct float64 `json:"inode_used_pct"`
				TotalInodes  uint64  `json:"total_inodes"`
			} `json:"mounts"`
		} `json:"disk"`
		Network struct {
			ConntrackPct float64 `json:"conntrack_usage_pct"`
			ConntrackMax int     `json:"conntrack_max"`
		} `json:"network"`
		Runtime struct {
			FrontendWorking string `json:"frontend_working"`
			FrontendReason  string `json:"frontend_reason"`
			EdgeStatus      string `json:"edge_status"`
			EdgeReason      string `json:"edge_reason_code"`
		} `json:"runtime"`
	}
	if json.Unmarshal(body, &h) != nil {
		return nil
	}
	var fs []finding

	// Edge / frontend liveness — act only on explicit bad enums.
	switch h.Runtime.FrontendWorking {
	case "down":
		fs = append(fs, finding{sevCritical, "edge", "frontend not serving (down)",
			strings.TrimSpace("end-to-end frontend check: down. " + h.Runtime.FrontendReason), "system_health", nil})
	case "degraded":
		fs = append(fs, finding{sevWarning, "edge", "frontend degraded",
			strings.TrimSpace("end-to-end frontend check: degraded. " + h.Runtime.FrontendReason), "system_health", nil})
	}
	switch h.Runtime.EdgeStatus {
	case "inactive":
		fs = append(fs, finding{sevCritical, "edge", "edge proxy inactive",
			strings.TrimSpace("edge service reports inactive. " + h.Runtime.EdgeReason), "service_status", nil})
	case "degraded":
		fs = append(fs, finding{sevWarning, "edge", "edge proxy degraded",
			strings.TrimSpace("edge service reports degraded. " + h.Runtime.EdgeReason), "service_status", nil})
	}

	// Disk fullness + inode exhaustion, per real mount. Read-only image
	// filesystems (squashfs/iso9660/erofs — snaps, mounted ISOs) sit at 100% by
	// design and are pure noise here, so skip them.
	for _, m := range h.Disk.Mounts {
		if readonlyImageFS(m.FSType) {
			continue
		}
		switch {
		case m.UsedPct >= wwDiskCritPct:
			fs = append(fs, finding{sevCritical, "disk", "disk almost full: " + m.Mount,
				fmt.Sprintf("%s at %.1f%% used", m.Mount, m.UsedPct), "system_health", nil})
		case m.UsedPct >= wwDiskWarnPct:
			fs = append(fs, finding{sevWarning, "disk", "disk filling up: " + m.Mount,
				fmt.Sprintf("%s at %.1f%% used", m.Mount, m.UsedPct), "system_health", nil})
		}
		if m.TotalInodes > 0 {
			switch {
			case m.InodeUsedPct >= wwInodeCritPct:
				fs = append(fs, finding{sevCritical, "disk", "inodes almost exhausted: " + m.Mount,
					fmt.Sprintf("%s at %.1f%% inodes used", m.Mount, m.InodeUsedPct), "system_health", nil})
			case m.InodeUsedPct >= wwInodeWarnPct:
				fs = append(fs, finding{sevWarning, "disk", "inodes filling up: " + m.Mount,
					fmt.Sprintf("%s at %.1f%% inodes used", m.Mount, m.InodeUsedPct), "system_health", nil})
			}
		}
	}

	// Sustained load relative to core count.
	if h.Host.CPUThreads > 0 {
		ratio := h.Host.Load5 / float64(h.Host.CPUThreads)
		switch {
		case ratio >= wwLoadCritRatio:
			fs = append(fs, finding{sevCritical, "load", "very high load",
				fmt.Sprintf("load_avg_5=%.2f on %d cores (%.1f× cores)", h.Host.Load5, h.Host.CPUThreads, ratio), "process_list", nil})
		case ratio >= wwLoadWarnRatio:
			fs = append(fs, finding{sevWarning, "load", "high load",
				fmt.Sprintf("load_avg_5=%.2f on %d cores (%.1f× cores)", h.Host.Load5, h.Host.CPUThreads, ratio), "process_list", nil})
		}
	}

	// Memory available (accounts for reclaimable cache) + swap pressure.
	availKnown := h.Host.MemTotal > 0 && h.Host.MemAvail > 0
	availPct := 0.0
	if availKnown {
		availPct = float64(h.Host.MemAvail) / float64(h.Host.MemTotal) * 100
		if availPct < wwMemAvailWarnPct {
			fs = append(fs, finding{sevWarning, "memory", "low free memory",
				fmt.Sprintf("only %.1f%% of RAM available", availPct), "process_list", nil})
		}
	}
	// Swap OCCUPANCY alone is normal — with default swappiness the kernel parks
	// idle anonymous pages in swap on a perfectly healthy box. Only flag swap when
	// it is heavily used AND RAM is genuinely tight (real memory pressure), and
	// only when mem_available is known (0 = unknown, don't guess).
	if h.Host.SwapTotal > 0 && availKnown && availPct < wwMemPressureAvailPct {
		swapPct := float64(h.Host.SwapUsed) / float64(h.Host.SwapTotal) * 100
		if swapPct >= wwSwapWarnPct {
			fs = append(fs, finding{sevWarning, "memory", "memory pressure (swapping)",
				fmt.Sprintf("%.1f%% RAM available with %.1f%% of swap in use", availPct, swapPct), "process_list", nil})
		}
	}

	// Conntrack table saturation → dropped connections.
	if h.Network.ConntrackMax > 0 {
		switch {
		case h.Network.ConntrackPct >= wwConntrackCritPct:
			fs = append(fs, finding{sevCritical, "network", "conntrack table almost full",
				fmt.Sprintf("conntrack at %.1f%% of max", h.Network.ConntrackPct), "system_health", nil})
		case h.Network.ConntrackPct >= wwConntrackWarnPct:
			fs = append(fs, finding{sevWarning, "network", "conntrack table filling up",
				fmt.Sprintf("conntrack at %.1f%% of max", h.Network.ConntrackPct), "system_health", nil})
		}
	}

	return fs
}

// eccDimmView is one DIMM's counters as carried in the health snapshot's
// hardware.ecc.dimms array.
type eccDimmView struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	Location         string `json:"location"`
	CorrectedCount   uint64 `json:"corrected_count"`
	UncorrectedCount uint64 `json:"uncorrected_count"`
}

// evalHardware flags memory ECC errors from the health snapshot's hardware
// block. Uncorrected errors are critical (data-integrity / imminent crash);
// corrected errors are a warning (pre-failure signal). Both point at dmesg_tail
// for the timing/rate behind the cumulative counters. When ECC info is absent
// (present=false and no ring-buffer fallback), nothing is flagged — the signal
// is unreadable here, not proven healthy.
func evalHardware(body json.RawMessage) []finding {
	var h struct {
		Hardware struct {
			ECC struct {
				Present          bool          `json:"present"`
				Source           string        `json:"source"`
				CorrectedTotal   uint64        `json:"corrected_total"`
				UncorrectedTotal uint64        `json:"uncorrected_total"`
				DIMMs            []eccDimmView `json:"dimms"`
			} `json:"ecc"`
		} `json:"hardware"`
	}
	if json.Unmarshal(body, &h) != nil {
		return nil
	}
	ecc := h.Hardware.ECC
	if !ecc.Present {
		return nil
	}
	// EDAC sysfs gives durable cumulative counters; the kernel-ring fallback only
	// sees machine-check messages still in the ring, so note that caveat.
	src := ""
	if ecc.Source == "kernel_ring" {
		src = " (counted from the kernel ring buffer; EDAC sysfs unavailable)"
	}
	// Each finding gets its own Args map (never a shared instance) so a later
	// annotation pass can't mutate one finding's drilldown via another's.
	drill := func() map[string]any { return map[string]any{"grep": "Hardware Error"} }
	var fs []finding
	if ecc.UncorrectedTotal >= wwECCUncorrectedCrit {
		fs = append(fs, finding{sevCritical, "hardware", "uncorrected memory errors (ECC)",
			fmt.Sprintf("%d uncorrected ECC error(s) since boot%s — data-integrity risk / imminent DIMM failure; replace the affected module%s",
				ecc.UncorrectedTotal, eccDimmSuffix(eccWorstDimm(ecc.DIMMs, true)), src), "dmesg_tail", drill()})
		// The critical already tells the operator to replace the module; the
		// corrected warning would be redundant noise on the same box, so suppress it.
		return fs
	}
	if ecc.CorrectedTotal >= wwECCCorrectedWarn {
		fs = append(fs, finding{sevWarning, "hardware", "corrected memory errors (ECC)",
			fmt.Sprintf("%d corrected ECC error(s) since boot%s — a single flip is benign but a rising count predicts DIMM failure; check the rate/timing%s",
				ecc.CorrectedTotal, eccDimmSuffix(eccWorstDimm(ecc.DIMMs, false)), src), "dmesg_tail", drill()})
	}
	return fs
}

// eccWorstDimm returns a label for the DIMM with the highest count of the
// requested kind (uncorrected when unc=true, else corrected), or "" when none
// is attributed — AMD often reports "noinfo" errors it can't pin to a module.
func eccWorstDimm(dimms []eccDimmView, unc bool) string {
	best, bestN := "", uint64(0)
	for _, d := range dimms {
		n := d.CorrectedCount
		if unc {
			n = d.UncorrectedCount
		}
		if n > bestN {
			bestN = n
			switch {
			case strings.TrimSpace(d.Label) != "":
				best = d.Label
			case strings.TrimSpace(d.Location) != "":
				best = d.Location
			default:
				best = d.ID
			}
		}
	}
	return best
}

func eccDimmSuffix(dimm string) string {
	if strings.TrimSpace(dimm) == "" {
		return ""
	}
	return " (worst: " + dimm + ")"
}

// edgeEngineUnits are the mutually-exclusive edge proxies: a node fronts its
// traffic with exactly one of these, so the others are installed-but-disabled
// alternates whose failed/inactive state is not a fault. (httpd/apache2 are the
// ORIGIN, not an edge alternate, so they are deliberately absent here.)
var edgeEngineUnits = map[string]bool{"angie": true, "openresty": true, "nginx": true}

// evalServices flags failed/inactive/flapping units. edgeService is the resolved
// active edge engine (from the health snapshot, lowercased, no ".service"); when
// non-empty it suppresses state faults for the IDLE alternate edge engine — the
// classic false "openresty.service failed" on an Angie node. Explicitly-disabled
// non-edge services are also not treated as current state faults: systemd can keep
// a stale failed state for a unit that is intentionally disabled. Edge engines
// retain the stricter fail-safe behavior when the active engine is unresolved.
func evalServices(body json.RawMessage, edgeService string) []finding {
	var s struct {
		Services []struct {
			Unit     string `json:"unit"`
			Load     string `json:"load"`
			Active   string `json:"active"`
			Sub      string `json:"sub"`
			Enabled  string `json:"enabled"`
			Restarts int    `json:"restarts"`
		} `json:"services"`
	}
	if json.Unmarshal(body, &s) != nil {
		return nil
	}
	var fs []finding
	for _, u := range s.Services {
		// Skip units that aren't installed / are masked — not a fault.
		if u.Load == "not-found" || u.Load == "masked" {
			continue
		}
		// Skip the idle alternate edge engine (e.g. a failed/disabled openresty
		// while Angie owns the edge). Suppress ONLY when the active edge resolved
		// to a KNOWN engine (edgeEngineUnits[edgeService]) and this is a DIFFERENT
		// edge engine. Fail-safe: any value that is not a known engine — the
		// collector's unresolved sentinel "unknown", "" from a missing health
		// section, or any unexpected string — is not in edgeEngineUnits, so it
		// suppresses nothing and a genuinely-failed edge is still flagged. The
		// active edge's own health is additionally covered by evalHealth
		// (edge_status / frontend_working).
		unitBase := strings.ToLower(strings.TrimSuffix(u.Unit, ".service"))
		if edgeEngineUnits[edgeService] && edgeEngineUnits[unitBase] && unitBase != edgeService {
			continue
		}

		failed := u.Active == "failed" || u.Sub == "failed"
		// A disabled non-edge service is not expected to be running. systemd can
		// retain active=failed after a previous/manual start, so treating that stale
		// state as a current critical creates persistent false positives (e.g.
		// memcached disabled on Orion). Keep failures critical when enablement is
		// anything other than explicitly "disabled" (including unknown/static), and
		// keep edge engines fail-safe: the resolved active edge is required even if
		// disabled, while an unresolved edge still flags failed edge candidates.
		reportFailed := u.Enabled != "disabled" ||
			(edgeEngineUnits[unitBase] && (!edgeEngineUnits[edgeService] || unitBase == edgeService))

		switch {
		case failed && reportFailed:
			fs = append(fs, finding{sevCritical, "service", "service failed: " + u.Unit,
				fmt.Sprintf("%s active=%s sub=%s", u.Unit, u.Active, u.Sub), "service_status",
				map[string]any{"units": u.Unit}})
		case u.Active == "inactive" && u.Enabled == "enabled" && u.Sub != "exited":
			// sub=="exited" is a cleanly-completed oneshot (enabled + inactive is
			// normal for it), not a fault. whats_wrong only ever reads the curated
			// long-running set (no units= arg), so oneshots are unlikely here, but
			// this keeps the rule safe if it is ever pointed at the full unit list.
			fs = append(fs, finding{sevCritical, "service", "enabled service not running: " + u.Unit,
				fmt.Sprintf("%s is enabled at boot but active=inactive (sub=%s)", u.Unit, u.Sub), "service_status",
				map[string]any{"units": u.Unit}})
		}
		// Flapping is orthogonal to current state (a unit can be active yet restarting).
		if u.Restarts >= wwSvcFlapRestarts {
			fs = append(fs, finding{sevWarning, "service", "service flapping: " + u.Unit,
				fmt.Sprintf("%s has restarted %d times", u.Unit, u.Restarts), "service_status",
				map[string]any{"units": u.Unit}})
		}
	}
	return fs
}

func evalMySQL(body json.RawMessage) []finding {
	var m struct {
		ConnPct float64 `json:"conn_pct"`
		Total   int     `json:"total"`
		Max     int     `json:"max"`
	}
	if json.Unmarshal(body, &m) != nil || m.Max <= 0 {
		return nil
	}
	switch {
	case m.ConnPct >= wwMySQLConnCritPct:
		return []finding{{sevCritical, "mysql", "MySQL connections near max",
			fmt.Sprintf("%d/%d connections used (%.1f%%)", m.Total, m.Max, m.ConnPct), "mysql_pressure", nil}}
	case m.ConnPct >= wwMySQLConnWarnPct:
		return []finding{{sevWarning, "mysql", "MySQL connection pressure",
			fmt.Sprintf("%d/%d connections used (%.1f%%)", m.Total, m.Max, m.ConnPct), "mysql_pressure", nil}}
	}
	return nil
}

func evalMailQueue(body json.RawMessage, sources map[string]string) []finding {
	var q struct {
		Available bool `json:"available"`
		Report    struct {
			Frozen   int `json:"frozen"`
			Deferred int `json:"deferred"`
			Total    int `json:"total"`
		} `json:"report"`
	}
	if json.Unmarshal(body, &q) != nil {
		return nil
	}
	if !q.Available {
		sources["mail_queue"] = "unavailable"
		return nil
	}
	// Deliberately keyed on FROZEN only, not deferred. Deferred messages are the
	// normal retry/greylisting backlog and swing widely on a healthy node, so
	// thresholding them would over-flag; frozen messages are genuinely stuck. A
	// pure-deferred outage is therefore an accepted blind spot for this tool (use
	// mail_queue_summary to see the deferred count + reasons).
	switch {
	case q.Report.Frozen >= wwMailFrozenCrit:
		return []finding{{sevCritical, "mail_queue", "large frozen mail backlog",
			fmt.Sprintf("%d frozen (of %d queued, %d deferred)", q.Report.Frozen, q.Report.Total, q.Report.Deferred), "mail_queue_summary", nil}}
	case q.Report.Frozen >= wwMailFrozenWarn:
		return []finding{{sevWarning, "mail_queue", "frozen messages stuck in mail queue",
			fmt.Sprintf("%d frozen (of %d queued, %d deferred)", q.Report.Frozen, q.Report.Total, q.Report.Deferred), "mail_queue_summary", nil}}
	}
	return nil
}

func evalMailTraffic(body json.RawMessage, sources map[string]string) []finding {
	var t struct {
		Available bool `json:"available"`
		Traffic   struct {
			Anomalies []struct {
				Addr            string  `json:"addr"`
				Recent          int64   `json:"recent"`
				BaselinePerHour float64 `json:"baseline_per_hour"`
				Ratio           float64 `json:"ratio"`
				Kind            string  `json:"kind"`
			} `json:"anomalies"`
		} `json:"traffic"`
	}
	if json.Unmarshal(body, &t) != nil {
		return nil
	}
	if !t.Available {
		sources["mail_traffic"] = "unavailable"
		return nil
	}
	var fs []finding
	for i, a := range t.Traffic.Anomalies {
		if i >= wwMailAnomalyCap {
			break
		}
		var detail, title string
		if a.Kind == "new-sender" {
			title = "new sender blasting outbound mail"
			detail = fmt.Sprintf("%s: %d msgs in last 2h with no prior baseline", a.Addr, a.Recent)
		} else {
			title = "outbound mail spike"
			detail = fmt.Sprintf("%s: %d msgs in last 2h, %.1f× its 7-day baseline (%.2f/h)", a.Addr, a.Recent, a.Ratio, a.BaselinePerHour)
		}
		// Warning, not critical: a spike can be legitimate bulk/transactional mail;
		// this is a "look at this account" signal, not proof of compromise.
		fs = append(fs, finding{sevWarning, "mail", title, detail, "mail_traffic", nil})
	}
	// Don't silently drop the tail — say how many more there are (a mass compromise
	// can far exceed the cap), pointing at mail_traffic for the full list.
	if extra := len(t.Traffic.Anomalies) - wwMailAnomalyCap; extra > 0 {
		fs = append(fs, finding{sevWarning, "mail", "more outbound-mail anomalies",
			fmt.Sprintf("%d more sender anomaly(ies) beyond the top %d shown", extra, wwMailAnomalyCap), "mail_traffic", nil})
	}
	return fs
}

func evalAnomalies(body json.RawMessage) []finding {
	var a struct {
		Count     int `json:"count"`
		Anomalies []struct {
			Reason string `json:"reason"`
			Signal string `json:"signal"`
			Count  int    `json:"count"`
		} `json:"anomalies"`
	}
	if json.Unmarshal(body, &a) != nil || a.Count <= 0 {
		return nil
	}
	// Group into one finding — these API-abuse events can be many and individually
	// low-signal; the aggregate + top signals is what matters.
	sig := map[string]int{}
	for _, e := range a.Anomalies {
		s := e.Signal
		if s == "" {
			s = e.Reason
		}
		if s == "" {
			s = "unknown"
		}
		sig[s]++
	}
	sev := sevInfo
	if a.Count >= wwAPIAnomalyWarnCount {
		sev = sevWarning
	}
	detail := fmt.Sprintf("%d anomaly event(s) over the window", a.Count)
	if ts := topSignals(sig); ts != "" {
		detail += "; " + ts
	}
	return []finding{{sev, "abuse", "API-abuse anomalies detected", detail, "system_health", nil}}
}

// evalPanelBurnIn flags panel enforcement burn-in residue from waf_fp_hunt: the
// customer-facing signal that separates known-scanner noise from real clients a
// panel BLOCK rule (or the bridge) would/did act on. During burn-in these two
// counters gate whether panel enforcement is safe to arm; once enforcing (Phase
// 4a/4c default), a non-zero count is a LIVE false positive worth a look. Scanner
// noise is already excluded upstream, so any residue here is real — hence a
// conservative >0 threshold fits this tool's under-flag ethos. Drill in with
// waf_fp_hunt (per-rule breakdown + sample requests).
func evalPanelBurnIn(body json.RawMessage) []finding {
	var w struct {
		Summary struct {
			WAF struct {
				NonScannerWouldBlk int `json:"nonscanner_would_block"`
			} `json:"panel_waf"`
			Decision struct {
				IPBlockCount int `json:"ip_block_count"`
			} `json:"panel_decision"`
		} `json:"summary"`
	}
	if json.Unmarshal(body, &w) != nil {
		return nil
	}
	var out []finding
	if n := w.Summary.WAF.NonScannerWouldBlk; n > 0 {
		out = append(out, finding{sevWarning, "panel", "panel WAF hitting real clients",
			fmt.Sprintf("%d non-scanner client(s) a panel BLOCK rule would/did deny on the cPanel/WHM ports — review before/while enforcing", n), "waf_fp_hunt", nil})
	}
	if n := w.Summary.Decision.IPBlockCount; n > 0 {
		out = append(out, finding{sevWarning, "panel", "panel bridge IP-blocking on a panel port",
			fmt.Sprintf("%d request(s) the bridge would/did IP-block on a panel port — confirm none are real admins", n), "waf_fp_hunt", nil})
	}
	return out
}

// topSignals renders the up-to-3 most frequent signal names as "top: sig(n), …",
// or "" when there are none (so the caller omits a dangling label).
func topSignals(sig map[string]int) string {
	if len(sig) == 0 {
		return ""
	}
	type kv struct {
		k string
		n int
	}
	rows := make([]kv, 0, len(sig))
	for k, n := range sig {
		rows = append(rows, kv{k, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].k < rows[j].k
	})
	parts := make([]string, 0, 3)
	for i, r := range rows {
		if i >= 3 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s(%d)", r.k, r.n))
	}
	return "top: " + strings.Join(parts, ", ")
}
