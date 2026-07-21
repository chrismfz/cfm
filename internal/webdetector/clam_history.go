package webdetector

import (
	"time"

	"cfm/internal/clam"
)

// RecordClamScanEvent persists a ClamAV scan event into the webdetector history
// store so it is queryable, scoped, via the existing
// /api/v1/webdet/history/events?type=clam_infected&host=<h> path (which already
// enforces scopeCheckHost). Wired as the clam scan-event sink in
// internal/detectors/webdetector_register.go.
//
// v1 only receives infections (clam publishes only those). The rich fields
// notify's JSONL drops — filename, uri, evidence — are preserved in Payload.
func (e *Engine) RecordClamScanEvent(ev clam.ScanEvent) {
	if e == nil || e.history == nil {
		return
	}
	ts := ev.When
	if ts.IsZero() {
		ts = time.Now()
	}
	typ := ev.EventType
	if typ == "" {
		typ = "clam_infected"
	}
	payload := map[string]interface{}{
		"uri":       ev.URI,
		"filename":  ev.FileName,
		"signature": ev.Signature,
		"evidence":  ev.Evidence,
	}
	// A sig-ignored hit stays queryable (the ClamAV page greys it out) but is
	// explicitly marked so the UI/CLI can distinguish "acted on" from
	// "downgraded to log-only by the signature-trust layer".
	if ev.SigIgnored {
		payload["sig_ignored"] = true
		payload["ignored_by"] = ev.IgnoredBy
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  ts.Unix(),
		Type:    typ,
		Host:    ev.Host,
		IP:      ev.IP,
		Reason:  ev.Signature,
		Payload: payload,
	})
}
