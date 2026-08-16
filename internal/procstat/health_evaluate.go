package procstat

import (
	"fmt"
	"math"
	"sort"
)

const (
	processHealthScanDegradedMinSkipped = 3
	processHealthScanDegradedPct        = 10.0

	processHealthDWarnCount = 8
	processHealthDWarnPct   = 2.0
	processHealthDCritCount = 32
	processHealthDCritPct   = 10.0

	processHealthZWarnCount = 16
	processHealthZWarnPct   = 1.0
	processHealthZCritCount = 64
	processHealthZCritPct   = 5.0

	processHealthFindingFamilyLimit = 3
)

// HealthFinding is one conservative single-snapshot process anomaly. The
// evaluator intentionally covers only signals that are meaningful without a
// historical baseline; family-count/fanout/RSS verdicts are deferred until a
// rolling baseline exists.
type HealthFinding struct {
	Code        string               `json:"code"`
	Severity    string               `json:"severity"`
	State       string               `json:"state"`
	Count       int                  `json:"count"`
	Percent     float64              `json:"percent"`
	TopFamilies []StateFamilySummary `json:"top_families,omitempty"`
	Detail      string               `json:"detail"`
}

// HealthEvaluation is the conservative verdict over one HealthSummary.
// Reliable=false/status=degraded means the snapshot was too incomplete or
// internally inconsistent to classify safely; callers must not treat that as OK.
type HealthEvaluation struct {
	Status   string          `json:"status"` // ok | issues | degraded
	Reliable bool            `json:"reliable"`
	Reason   string          `json:"reason,omitempty"`
	Findings []HealthFinding `json:"findings"`
}

// EvaluateHealth applies intentionally high single-snapshot gates to process
// states that are generically pathological in accumulation: uninterruptible
// sleep (D) and zombies (Z). It deliberately does NOT classify COMM counts,
// fanout, aggregate RSS, or total process count without a historical baseline.
func EvaluateHealth(h HealthSummary) HealthEvaluation {
	out := HealthEvaluation{
		Status:   "ok",
		Reliable: true,
		Findings: []HealthFinding{},
	}

	if reason := processHealthUnreliableReason(h); reason != "" {
		out.Status = "degraded"
		out.Reliable = false
		out.Reason = reason
		return out
	}

	if f, ok := processStateFinding(
		h, "D", "process_d_state_pileup",
		processHealthDWarnCount, processHealthDWarnPct,
		processHealthDCritCount, processHealthDCritPct,
	); ok {
		out.Findings = append(out.Findings, f)
	}
	if f, ok := processStateFinding(
		h, "Z", "process_zombie_accumulation",
		processHealthZWarnCount, processHealthZWarnPct,
		processHealthZCritCount, processHealthZCritPct,
	); ok {
		out.Findings = append(out.Findings, f)
	}

	if len(out.Findings) == 0 {
		return out
	}
	out.Status = "issues"
	sort.SliceStable(out.Findings, func(i, j int) bool {
		if processHealthSeverityRank(out.Findings[i].Severity) != processHealthSeverityRank(out.Findings[j].Severity) {
			return processHealthSeverityRank(out.Findings[i].Severity) < processHealthSeverityRank(out.Findings[j].Severity)
		}
		return out.Findings[i].Code < out.Findings[j].Code
	})
	return out
}

func processHealthUnreliableReason(h HealthSummary) string {
	if h.TotalProcesses <= 0 {
		return "process snapshot has no readable processes"
	}
	s := h.Scan
	if s.PIDsEnumerated <= 0 || s.PIDsReadable <= 0 || s.PIDsSkipped < 0 ||
		s.PIDsReadable != h.TotalProcesses || s.PIDsReadable+s.PIDsSkipped != s.PIDsEnumerated {
		return "process snapshot scan accounting is inconsistent"
	}

	stateTotal := 0
	for _, n := range h.States {
		if n < 0 {
			return "process snapshot state accounting is inconsistent"
		}
		stateTotal += n
	}
	if stateTotal != h.TotalProcesses {
		return "process snapshot state accounting is inconsistent"
	}

	skippedPct := processPercentRaw(s.PIDsSkipped, s.PIDsEnumerated)
	if s.PIDsSkipped >= processHealthScanDegradedMinSkipped && skippedPct >= processHealthScanDegradedPct {
		return fmt.Sprintf("process snapshot is materially partial: %d/%d PIDs skipped (%.1f%%)",
			s.PIDsSkipped, s.PIDsEnumerated, processPercentRounded(s.PIDsSkipped, s.PIDsEnumerated))
	}
	return ""
}

func processStateFinding(h HealthSummary, state, code string, warnCount int, warnPct float64, critCount int, critPct float64) (HealthFinding, bool) {
	count := h.States[state]
	pct := processPercentRaw(count, h.TotalProcesses)
	severity := ""
	switch {
	case count >= critCount && pct >= critPct:
		severity = "critical"
	case count >= warnCount && pct >= warnPct:
		severity = "warning"
	default:
		return HealthFinding{}, false
	}

	families := append([]StateFamilySummary(nil), h.TopFamiliesByState[state]...)
	if len(families) > processHealthFindingFamilyLimit {
		families = families[:processHealthFindingFamilyLimit]
	}

	label := "processes in uninterruptible D-state"
	if state == "Z" {
		label = "zombie processes"
	}
	detail := fmt.Sprintf("%d/%d readable processes (%.1f%%) are %s",
		count, h.TotalProcesses, processPercentRounded(count, h.TotalProcesses), label)
	if len(families) > 0 {
		detail += fmt.Sprintf("; top family %q contributes %d", families[0].Comm, families[0].Count)
	}

	return HealthFinding{
		Code:        code,
		Severity:    severity,
		State:       state,
		Count:       count,
		Percent:     processPercentRounded(count, h.TotalProcesses),
		TopFamilies: families,
		Detail:      detail,
	}, true
}

func processPercentRaw(n, total int) float64 {
	if n <= 0 || total <= 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

func processPercentRounded(n, total int) float64 {
	return math.Round(processPercentRaw(n, total)*10) / 10
}

func processHealthSeverityRank(severity string) int {
	if severity == "critical" {
		return 0
	}
	return 1
}
