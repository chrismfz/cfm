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
// It reports whether the row was written: the publishers keep a finding armed
// (retry next cycle) instead of marking it sent when there is no history store
// or the write failed.
func (e *Engine) RecordNodeFaultEvent(ev health.NodeFaultEvent) bool {
	if e == nil || e.history == nil || ev.Type == "" {
		return false
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
	return e.history.AppendChecked(HistoryEvent{
		TsUnix:  ts.Unix(),
		Type:    ev.Type,
		Host:    ev.Host,
		Reason:  ev.Message,
		Payload: payload,
	})
}
