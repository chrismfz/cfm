package agent

// Bounded DNAT-status probe for the heartbeat.
//
// The heartbeat reports dnat_enabled, which means reading the firewall BEFORE
// the POST goes out. On the exec-nft backend that read is an `nft` subprocess
// bounded by the command runner's timeout. On the nftlib backend it takes the
// backend mutex and then does a netlink dump (ListChains + GetRules) on the one
// lasting connection, with no deadline on either. If the dump stalls, or a
// long write holds the mutex, the heartbeat used to wait with it: no POST, and
// no log line either (the failure log sits after the send), so cfm-web's
// last_seen went stale past its 3-minute threshold and the node was reported
// "offline" while it was up. That is the intermittent false "agent down" seen
// only on the nftlib node.
//
// Liveness must not depend on the data plane, so the probe is bounded: past
// heartbeatDNATTimeout the heartbeat goes out WITHOUT dnat_enabled. The field
// is omitempty and cfm-web only updates dnat_enabled when the key is present,
// so an omitted value keeps the last known state rather than flapping it (the
// same outcome as the existing probe-error path). The heartbeat also runs on
// its own goroutine (heartbeatLoop), so the work loop's firewall calls can't
// hold it back either.
//
// The probe is single-flight. A timed-out probe keeps running (neither the
// mutex wait nor the netlink call can be cancelled), so starting another one
// per beat would only pile goroutines up behind it. While one is in flight,
// later heartbeats skip the probe. This does not unstick the backend itself —
// a stalled read still blocks firewall writes until it returns; hardening the
// nftlib connection is separate work.

import (
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/dnat"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

var (
	// heartbeatDNATStatusFn is the probe itself; a var so tests can stub it.
	heartbeatDNATStatusFn = dnat.Status

	// heartbeatDNATTimeout bounds how long a heartbeat waits for the probe.
	// A whole heartbeat is then bounded at roughly this + edgeengine.Detect
	// (3s per systemctl probe + 3s for `-v`) + the 15s HTTP client timeout —
	// under 30s, far below cfm-web's 3-minute offline threshold.
	heartbeatDNATTimeout = 5 * time.Second

	// heartbeatDNATSlowLog logs a probe that answered in time but slowly, so a
	// degrading backend is visible before it ever reaches the timeout.
	heartbeatDNATSlowLog = 1 * time.Second

	// heartbeatDNATLogEvery throttles the probe's diagnostic lines (slow,
	// timed out, still in flight, returned late). One throttle covers all of
	// them: a backend that stays slow or wedged must not write a line per
	// beat forever. The first line after a quiet period always gets through.
	heartbeatDNATLogEvery = 5 * time.Minute
)

// dnatProbeState is the single-flight guard and log throttle for
// heartbeatDNATStatus.
type dnatProbeState struct {
	// inflight is held by the probe goroutine for the whole probe and
	// released when it returns, however late; TryLock is the skip test.
	inflight  sync.Mutex
	startedAt atomic.Int64 // unix nanos of the in-flight probe's start

	logMu      sync.Mutex
	lastLog    time.Time
	suppressed int
}

type dnatProbeResult struct {
	on  bool
	err error
}

// Who owns a probe's result: the waiting heartbeat, or nobody (it gave up).
const (
	probePending int32 = iota
	probeDelivered
	probeAbandoned
)

// heartbeatDNATStatus returns the DNAT state for the heartbeat, or nil when it
// is unknown this beat (no backend, probe error, probe too slow, or a previous
// probe still stuck). nil means "omit dnat_enabled", never "DNAT is off".
func (r *Runner) heartbeatDNATStatus() *bool {
	if r.backend == nil {
		return nil
	}
	return r.dnatProbe.run(r.backend)
}

func (p *dnatProbeState) run(be firewall.Backend) *bool {
	start := time.Now()
	if !p.inflight.TryLock() {
		started := time.Unix(0, p.startedAt.Load())
		p.logThrottled("[agent] heartbeat dnat status probe still in flight after %s; sending heartbeat without dnat_enabled",
			start.Sub(started).Round(time.Millisecond))
		return nil
	}
	p.startedAt.Store(start.UnixNano())

	// Read the knobs here, not in the goroutine: a probe can outlive this call.
	probe, timeout := heartbeatDNATStatusFn, heartbeatDNATTimeout
	var state atomic.Int32
	ch := make(chan dnatProbeResult, 1)
	go func() {
		defer p.inflight.Unlock()
		on, err := probe(be)
		// Exactly one side wins: either the heartbeat is still waiting and
		// gets the result, or it already gave up and the result is only logged.
		if state.CompareAndSwap(probePending, probeDelivered) {
			ch <- dnatProbeResult{on: on, err: err}
			return
		}
		p.logThrottled("[agent] heartbeat dnat status probe returned late after %s (err=%v)",
			time.Since(start).Round(time.Millisecond), err)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return p.accept(res, start)
	case <-timer.C:
		if !state.CompareAndSwap(probePending, probeAbandoned) {
			// The probe won the race at the deadline; its send is imminent.
			return p.accept(<-ch, start)
		}
		p.logThrottled("[agent] heartbeat dnat status probe timed out after %s; sending heartbeat without dnat_enabled",
			timeout)
		return nil
	}
}

func (p *dnatProbeState) accept(res dnatProbeResult, start time.Time) *bool {
	if res.err != nil {
		logging.LogfAPI("[agent] heartbeat dnat status check failed: %v", res.err)
		return nil
	}
	if took := time.Since(start); took >= heartbeatDNATSlowLog {
		p.logThrottled("[agent] heartbeat dnat status probe slow: %s", took.Round(time.Millisecond))
	}
	on := res.on
	return &on
}

// logThrottled writes at most one probe diagnostic per heartbeatDNATLogEvery,
// noting how many were held back since the last one.
func (p *dnatProbeState) logThrottled(format string, args ...any) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	now := time.Now()
	if !p.lastLog.IsZero() && now.Sub(p.lastLog) < heartbeatDNATLogEvery {
		p.suppressed++
		return
	}
	if p.suppressed > 0 {
		format += " (%d similar suppressed)"
		args = append(args, p.suppressed)
	}
	p.lastLog, p.suppressed = now, 0
	logging.LogfAPI(format, args...)
}
