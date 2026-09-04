package health

// nodefault.go carries durable, edge-triggered "hard fault" events for
// non-self-healing hardware/storage conditions the health detector already
// evaluates — a failed SMART device, a degraded mdadm array — into the same
// publish/persist path the memory-ECC events use (see edac.go). A subscriber
// (webdetector's history store) persists them so they survive a dmesg ring wrap
// or a daemon restart and can be pinned/acknowledged fleet-side.
//
// These are boolean STATE faults (unlike ECC's cumulative counters): the
// detector fires one event when a device/array ENTERS the fault state (edge
// triggered), including once at first sight if it is already faulted at startup,
// and does not re-fire while the fault persists.

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// NodeFaultEvent is one durable hardware/storage fault observation.
type NodeFaultEvent struct {
	Type     string    // detection_history event_type, e.g. "disk_smart_fail" | "disk_mdadm_degraded"
	Severity string    // "critical" | "warning"
	Host     string    //
	Key      string    // dedupe key within a type (e.g. the device node), optional
	Message  string    // human summary for the history row
	When     time.Time //
}

var (
	nodeFaultSinkMu sync.RWMutex
	nodeFaultSink   func(NodeFaultEvent)
)

// SetNodeFaultEventSink registers (replacing any prior) the consumer of node
// fault events. Mirrors SetECCEventSink / clam.SetScanEventSink: the detector is
// a leaf package, so the persister subscribes. nil detaches. Concurrency-safe.
func SetNodeFaultEventSink(fn func(NodeFaultEvent)) {
	nodeFaultSinkMu.Lock()
	nodeFaultSink = fn
	nodeFaultSinkMu.Unlock()
}

// publishNodeFaultEvent delivers ev to the sink if set; a misbehaving sink must
// never take down the detector loop, so panics are contained. Returns true when
// a sink was invoked: the caller only advances its edge state on a delivered
// event, so a fault present before the persister has registered its sink (a
// startup ordering race) is retried next cycle rather than dropped forever.
func publishNodeFaultEvent(ev NodeFaultEvent) bool {
	nodeFaultSinkMu.RLock()
	fn := nodeFaultSink
	nodeFaultSinkMu.RUnlock()
	if fn == nil {
		return false
	}
	defer func() { _ = recover() }()
	fn(ev)
	return true
}

// smartFaultMessage renders a one-line summary for a failed SMART device.
func smartFaultMessage(dev string, info SmartInfo) string {
	health := strings.TrimSpace(info.Health)
	if health == "" {
		health = "FAILED"
	}
	msg := fmt.Sprintf("SMART health %s on %s", health, dev)
	if m := strings.TrimSpace(info.Model); m != "" {
		msg += " (" + m + ")"
	}
	return msg
}

// mdadmFaultMessage names the degraded array(s) and their member shortfall.
func mdadmFaultMessage(m MdstatSummary) string {
	var bad []string
	for _, a := range m.Arrays {
		// readMdstat sets FailedMissing = ExpectedMembers - ActiveMembers, so this
		// is exactly the "array is short members" test.
		if a.FailedMissing > 0 {
			bad = append(bad, fmt.Sprintf("%s (%d/%d members)", a.Name, a.ActiveMembers, a.ExpectedMembers))
		}
	}
	if len(bad) > 0 {
		return "mdadm array degraded: " + strings.Join(bad, ", ")
	}
	return "mdadm array degraded"
}

// diskDeadMissingCycles is how many consecutive health cycles a previously-
// healthy disk must be absent from the SMART enumeration before it is reported
// dead/removed — filters a brief partial-scan omission (with the default
// EVERY=10s, ~30s of continuous absence).
const diskDeadMissingCycles = 3

// zfsFaultMessage summarizes a degraded ZFS pool.
func zfsFaultMessage(name string, info ZpoolStatus) string {
	state := strings.TrimSpace(info.State)
	msg := "ZFS pool " + name
	if state != "" {
		msg += " " + state
	} else {
		msg += " unhealthy"
	}
	if info.UnhealthyVdevs > 0 {
		msg += fmt.Sprintf(" (%d unhealthy vdev(s))", info.UnhealthyVdevs)
	}
	if info.Resilvering {
		p := strings.TrimSpace(info.ResilverPercent)
		if p != "" {
			msg += " — resilvering " + p
		} else {
			msg += " — resilvering"
		}
	}
	return msg
}
