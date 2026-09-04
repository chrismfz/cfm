package webdetector

import (
	"time"

	"cfm/internal/detectors/health"
)

// RecordNodeFaultEvent persists a durable hardware/storage fault (failed SMART
// device, degraded mdadm array, …) from the health detector into the history
// store, so it is queryable via detection_history (type=disk_smart_fail /
// disk_mdadm_degraded) and can be pinned/acknowledged fleet-side — surviving a
// dmesg ring wrap or a daemon restart. Wired as the node-fault sink in
// internal/detectors/webdetector_register.go; mirrors RecordHardwareECCEvent.
func (e *Engine) RecordNodeFaultEvent(ev health.NodeFaultEvent) {
	if e == nil || e.history == nil || ev.Type == "" {
		return
	}
	ts := ev.When
	if ts.IsZero() {
		ts = time.Now()
	}
	payload := map[string]interface{}{
		"severity": ev.Severity,
	}
	if ev.Key != "" {
		payload["key"] = ev.Key
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  ts.Unix(),
		Type:    ev.Type,
		Host:    ev.Host,
		Reason:  ev.Message,
		Payload: payload,
	})
}
