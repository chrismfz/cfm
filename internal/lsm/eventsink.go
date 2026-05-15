//go:build linux

package lsm

import (
	"fmt"
	"sync"
	"time"

	"cfm/internal/logging"
	"cfm/internal/notify"
)

// eventsink.go — userspace DETECT emission with per-policy rate caps.
//
// The kmsg sink already caps its output via KmsgConf.DetectRatePerMin
// (see kmsg.go). Until this slice the cfm.log and notify pipelines
// took the full event stream regardless — fine on a quiet host, but
// on a busy shared-hosting box a single chatty trigger (one
// CFML-CRED-002 false positive from cagefsctl/python3.11) can spam
// hundreds of identical lines per second.
//
// This file adds an independent per-policy cap covering cfm.log and
// notify. The two userspace sinks share one bucket because they are
// always emitted together; downstream notify subscribers can already
// dedupe via their own keys, but a single cap upstream is cheaper
// than relying on each subscriber's deduper to absorb a flood.
//
// Window roll behaviour matches kmsg.go: surplus events accumulate
// in `suppressed`; on the next event past the minute boundary a
// summary line is emitted before the new event, so an operator
// reading cfm.log sees how much was dropped.

// EventSinkConf controls userspace DETECT emission. Sister type to
// KmsgConf; the two caps are independent so an operator can tighten
// dmesg without dropping cfm.log entries (or vice versa).
type EventSinkConf struct {
	// DetectRatePerMin caps cfm.log + notify emissions per policy ID
	// per minute. When the cap is hit, the surplus is counted and a
	// "suppressed=N in_last=60s" summary line is emitted on the next
	// window roll. 0 disables the cap (not recommended on shared
	// hosts where one chatty FP can fill the log). Default 30.
	DetectRatePerMin int
}

// DefaultEventSinkConf is the documented default: 30 per minute per
// policy. Higher than kmsg's 10 because cfm.log is a rotated file
// rather than a fixed-size kernel buffer, but tight enough that a
// runaway trigger cannot bury real events under thousands of lines.
func DefaultEventSinkConf() EventSinkConf {
	return EventSinkConf{DetectRatePerMin: 30}
}

type eventSink struct {
	cfgMu sync.Mutex
	cfg   EventSinkConf

	rateMu sync.Mutex
	rate   map[PolicyID]*eventRateBucket
}

type eventRateBucket struct {
	windowStart time.Time
	emitted     int
	suppressed  int
}

var defaultEventSink = &eventSink{
	cfg:  DefaultEventSinkConf(),
	rate: map[PolicyID]*eventRateBucket{},
}

// ConfigureEventSink installs c on the package-level event sink.
// Called by the enable + lifecycle paths after parsing lsm.conf.
// Idempotent; safe to call from any goroutine.
func ConfigureEventSink(c EventSinkConf) {
	defaultEventSink.cfgMu.Lock()
	defaultEventSink.cfg = c
	defaultEventSink.cfgMu.Unlock()
}

// emitDetectEvent routes ev through cfm.log + notify under the
// per-policy cap. The kmsg path is independent and the caller is
// expected to invoke KmsgDetect alongside. When the cap rolls a
// window with suppressed events, a summary line is logged + emitted
// before the current event.
func emitDetectEvent(ev Event, reason string, extra map[string]string) {
	defaultEventSink.cfgMu.Lock()
	rate := defaultEventSink.cfg.DetectRatePerMin
	defaultEventSink.cfgMu.Unlock()
	allow, summary := defaultEventSink.rateAllow(ev.PolicyID, rate, time.Now())
	if summary != "" {
		// Window-roll summary. Emitted at most once per minute per
		// policy regardless of cap, so it cannot itself flood.
		logging.LogfLSM("[lsm] %s", summary)
		_ = notify.Emit(notify.Event{
			Kind:     "lsm_detect_summary",
			Section:  "lsm",
			When:     time.Now(),
			Reason:   summary,
			Severity: "notice",
		})
	}
	if !allow {
		return
	}
	logging.LogfLSM("[lsm] %s", reason)
	_ = notify.Emit(notify.Event{
		Kind:     "lsm_detect",
		Section:  "lsm",
		When:     time.Now(),
		Reason:   reason,
		Severity: "warning",
		Extra:    extra,
	})
}

// rateAllow returns (allow, summary). allow is whether ev passes the
// per-policy cap. summary is non-empty when the call rolled the
// per-policy window and the previous window had suppressed events.
//
// ratePerMin <= 0 means no cap (operator opted out); always allow.
// Treating negative values as uncapped rather than as cap-of-zero
// keeps an out-of-band misconfiguration from silently dropping every
// event — ParseConf rejects negatives, but ConfigureEventSink could
// in principle be called programmatically with one.
func (s *eventSink) rateAllow(id PolicyID, ratePerMin int, now time.Time) (bool, string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	if ratePerMin <= 0 {
		// Track the bucket so a later reconfigure picks up an accurate
		// window, but don't gate.
		b := s.rate[id]
		if b == nil {
			b = &eventRateBucket{windowStart: now}
			s.rate[id] = b
		}
		return true, ""
	}

	b := s.rate[id]
	if b == nil {
		b = &eventRateBucket{windowStart: now}
		s.rate[id] = b
	}

	var summary string
	if now.Sub(b.windowStart) >= time.Minute {
		if b.suppressed > 0 {
			summary = fmt.Sprintf("%s suppressed=%d in_last=60s (cfm.log+notify)", id, b.suppressed)
		}
		b.windowStart = now
		b.emitted = 0
		b.suppressed = 0
	}

	if b.emitted >= ratePerMin {
		b.suppressed++
		return false, summary
	}
	b.emitted++
	return true, summary
}
