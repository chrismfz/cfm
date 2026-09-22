package agent

// Bounded DNAT-status probe for the heartbeat.
//
// The heartbeat reports dnat_enabled, which means reading the firewall BEFORE
// the POST goes out. On the exec-nft backend that read is an `nft` subprocess
// bounded by the command runner's 10s timeout. On the nftlib backend it takes
// the backend mutex and then does a netlink dump (ListChains + GetRules) on
// the one lasting connection, with no timeout on either. If the dump stalled,
// or a long firewall write held the mutex, the heartbeat used to wait with it:
// no POST, and no log line either (the failure log sits after the send), so
// cfm-web's last_seen went stale past its 3-minute threshold and the node was
// reported "offline" while it was up. That is the intermittent false
// "agent down" seen only on the nftlib node.
//
// Liveness must not depend on the data plane, so the probe is bounded: past
// heartbeatDNATTimeout the heartbeat goes out WITHOUT dnat_enabled. The field
// is omitempty and cfm-web only updates dnat_enabled when the key is present,
// so an omitted value keeps the last known state rather than flapping it. A
// probe error is omitted the same way — but note the exec-nft backend never
// returns one: its DNATStatus reads any failed `nft list table` as "off"
// (pre-existing), so there only a slow probe is omitted. The heartbeat also
// runs on its own goroutine (heartbeatLoop), so the work loop's firewall calls
// can't hold it back either.
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
	// A whole heartbeat is then bounded at this + edgeengine.Detect (up to
	// 2×3s of `systemctl is-active` + 2×3s of `-v`) + the 15s HTTP client
	// timeout — about 32s worst case, far below cfm-web's 3-minute offline
	// threshold.
	heartbeatDNATTimeout = 5 * time.Second

	// heartbeatDNATSlowLog logs a probe that answered in time but slowly, so a
	// degrading backend is visible before it ever reaches the timeout.
	heartbeatDNATSlowLog = 1 * time.Second

	// heartbeatDNATLogEvery throttles the probe's diagnostic lines (slow,
	// failed, timed out, still in flight). One throttle covers all of them: a
	// backend that stays slow, failing or wedged must not write a line per
	// beat forever. The first line after a quiet period always gets through,
	// and a stall whose "timed out" line was written always gets its
	// "returned late after …" line too, so every logged stall has a duration.
	heartbeatDNATLogEvery = 5 * time.Minute

	// heartbeatLogf is where the probe's lines go; a var so tests can read them.
	heartbeatLogf = logging.LogfAPI
)

// dnatProbeState is the single-flight guard and log throttle for
// heartbeatDNATStatus.
type dnatProbeState struct {
	inflight  atomic.Bool  // set while a probe runs, however late it returns
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
	// Read the knobs once: a probe can outlive this call, and its goroutine
	// must not read package state after the caller has moved on.
	probe, timeout, every := heartbeatDNATStatusFn, heartbeatDNATTimeout, heartbeatDNATLogEvery

	start := time.Now()
	if !p.inflight.CompareAndSwap(false, true) {
		started := time.Unix(0, p.startedAt.Load())
		p.logThrottled(every, "[agent] heartbeat dnat status probe still in flight after %s; sending heartbeat without dnat_enabled",
			start.Sub(started).Round(time.Millisecond))
		return nil
	}
	p.startedAt.Store(start.UnixNano())

	var state atomic.Int32
	var timeoutLogged atomic.Bool
	settled := make(chan struct{}) // closed once the caller has handled a timeout
	ch := make(chan dnatProbeResult, 1)
	go func() {
		on, err := probe(be)
		// Exactly one side wins: either the heartbeat is still waiting and
		// gets the result, or it already gave up and the result is only logged.
		if state.CompareAndSwap(probePending, probeDelivered) {
			p.inflight.Store(false) // clear before handing over: the probe is done
			ch <- dnatProbeResult{on: on, err: err}
			return
		}
		<-settled
		took := time.Since(start).Round(time.Millisecond)
		if timeoutLogged.Load() {
			// The stall's start was logged, so its end is too — unthrottled,
			// at most one per probe.
			p.logNow("[agent] heartbeat dnat status probe returned late after %s (err=%v)", took, err)
		} else {
			p.logThrottled(every, "[agent] heartbeat dnat status probe returned late after %s (err=%v)", took, err)
		}
		// Last: once the flag clears, this goroutine touches nothing else.
		p.inflight.Store(false)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return p.accept(every, res, start)
	case <-timer.C:
		if !state.CompareAndSwap(probePending, probeAbandoned) {
			// The probe won the race at the deadline; its send is imminent.
			return p.accept(every, <-ch, start)
		}
		timeoutLogged.Store(p.logThrottled(every,
			"[agent] heartbeat dnat status probe timed out after %s; sending heartbeat without dnat_enabled", timeout))
		close(settled)
		return nil
	}
}

func (p *dnatProbeState) accept(every time.Duration, res dnatProbeResult, start time.Time) *bool {
	if res.err != nil {
		p.logThrottled(every, "[agent] heartbeat dnat status check failed: %v", res.err)
		return nil
	}
	if took := time.Since(start); took >= heartbeatDNATSlowLog {
		p.logThrottled(every, "[agent] heartbeat dnat status probe slow: %s", took.Round(time.Millisecond))
	}
	on := res.on
	return &on
}

// logThrottled writes at most one probe diagnostic per `every`, noting how
// many were held back since the last one. It reports whether it wrote.
func (p *dnatProbeState) logThrottled(every time.Duration, format string, args ...any) bool {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	now := time.Now()
	if !p.lastLog.IsZero() && now.Sub(p.lastLog) < every {
		p.suppressed++
		return false
	}
	p.lastLog = now
	p.writeLocked(format, args...)
	return true
}

// logNow writes regardless of the throttle window (and without moving it),
// still flushing the held-back count.
func (p *dnatProbeState) logNow(format string, args ...any) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	p.writeLocked(format, args...)
}

func (p *dnatProbeState) writeLocked(format string, args ...any) {
	if p.suppressed > 0 {
		format += " (%d similar suppressed)"
		args = append(args, p.suppressed)
		p.suppressed = 0
	}
	heartbeatLogf(format, args...)
}
