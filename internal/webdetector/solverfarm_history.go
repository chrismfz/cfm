package webdetector

import (
	"fmt"
	"time"

	"cfm/internal/detectors/solverfarm"
)

// RecordSolverFarmFinding persists one emitted challenge_solver_farm finding into
// the durable webdetector history store as event_type=solver_farm, so a
// distributed-farm conviction — which today reaches only cfm.detector.log + mail
// — becomes queryable via detection_history and can be PULLed into the fleet
// fingerprint-reputation store (cfm-web). Wired as the finding sink in
// internal/detectors/webdetector_register.go; mirrors RecordClamScanEvent /
// RecordHardwareECCEvent (the detector package publishes, this subscribes).
//
// The Payload keys are the ingest CONTRACT (docs/fleet-fingerprint-reputation.md
// §5 → cfm-web:docs/fingerprint-reputation.md): keep them stable. `fingerprint`
// is the GROUP-BY key that flagged the vhost (empty for a subnet-spread-only
// finding), never a matched signature; `solves_per_ip` is evidence, not a gate.
func (e *Engine) RecordSolverFarmFinding(f solverfarm.Finding) {
	if e == nil || e.history == nil {
		return
	}
	ts := f.When
	if ts.IsZero() {
		ts = time.Now()
	}
	payload := map[string]interface{}{
		"fingerprint":        f.Fingerprint,
		"tracks":             f.Tracks,
		"solves":             f.Solves,
		"distinct_ips":       f.DistinctIPs,
		"distinct_subnets":   f.Subnets,
		"distinct_countries": f.Countries,
		"host_share":         f.HostShare,
		"solves_per_ip":      f.SolvesPerIP,
		"hosts":              f.Hosts,
	}
	// A bounded, fingerprint-accurate sample of the client addresses (the fleet
	// store enriches these — PTR/ASN/country/datacenter — so an operator can tell a
	// residential-proxy pool from a datacenter crawler and, on the non-edge nodes,
	// block them via the firewall). Omitted when empty so older/spread-only rows
	// stay compact.
	if len(f.IPs) > 0 {
		payload["ips"] = f.IPs
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  ts.Unix(),
		Type:    "solver_farm",
		Host:    f.Host,
		Reason:  solverFarmReason(f),
		UniqIP:  f.DistinctIPs,
		Payload: payload,
	})
}

// solverFarmReason renders a short, human-readable summary for the history row.
func solverFarmReason(f solverfarm.Finding) string {
	fp := f.Fingerprint
	if fp == "" {
		fp = "(none)"
	}
	return fmt.Sprintf("solver farm on %s — fp %s [%s]: %d solves, %d /24, %d countries",
		f.Host, fp, f.Tracks, f.Solves, f.Subnets, f.Countries)
}
