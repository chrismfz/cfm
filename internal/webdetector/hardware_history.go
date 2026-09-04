package webdetector

import (
	"fmt"
	"time"

	"cfm/internal/detectors/health"
)

// RecordHardwareECCEvent persists a memory-ECC observation from the health
// detector into the durable history store, so a corrected/uncorrected DRAM error
// survives a dmesg ring wrap or a reboot (which resets the live EDAC counters)
// and stays queryable from any later session via detection_history
// (type=hardware_ecc) / /api/v1/webdet/history/events.
//
// Wired as the ECC sink in internal/detectors/webdetector_register.go. Mirrors
// RecordClamScanEvent: the health detector is a leaf package that publishes, and
// this subscribes.
func (e *Engine) RecordHardwareECCEvent(ev health.ECCEvent) {
	if e == nil || e.history == nil {
		return
	}
	ts := ev.When
	if ts.IsZero() {
		ts = time.Now()
	}
	payload := map[string]interface{}{
		"kind":              ev.Kind,
		"corrected_total":   ev.Corrected,
		"uncorrected_total": ev.Uncorrected,
		"delta_corrected":   ev.DeltaCorrected,
		"delta_uncorrected": ev.DeltaUncorrected,
		"source":            ev.Source,
	}
	if ev.WorstDIMM != "" {
		payload["worst_dimm"] = ev.WorstDIMM
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  ts.Unix(),
		Type:    "hardware_ecc",
		Host:    ev.Host,
		Reason:  hardwareECCReason(ev),
		Payload: payload,
	})
}

// hardwareECCReason renders a short, human-readable summary for the history row.
func hardwareECCReason(ev health.ECCEvent) string {
	switch ev.Kind {
	case "uncorrected":
		return fmt.Sprintf("UNCORRECTED memory ECC error (+%d, total %d)", ev.DeltaUncorrected, ev.Uncorrected)
	case "baseline":
		return fmt.Sprintf("memory ECC baseline at startup (corrected %d, uncorrected %d)", ev.Corrected, ev.Uncorrected)
	default:
		return fmt.Sprintf("corrected memory ECC error (+%d, total %d)", ev.DeltaCorrected, ev.Corrected)
	}
}
