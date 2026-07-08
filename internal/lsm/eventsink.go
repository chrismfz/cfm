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

	// Enrich turns on the /proc forensic snapshot of the event's caller
	// (user, real exe path + deleted flag, cwd, cmdline, parent, login
	// uid) folded into the cfm.log line and the notify email. Default
	// true. The BPF event only carries the spoofable comm; this is what
	// makes an alert actionable ("who / what / where"). Best-effort:
	// a caller that already exited yields `proc=gone`.
	Enrich bool

	// EnrichHash includes the SHA-256 of the caller's exe in the
	// enrichment. Default true. The hash identifies the binary even when
	// its on-disk path was unlinked, and feeds a VirusTotal / YARA
	// lookup directly. Costs one bounded read+hash per new caller pid
	// (cached for the pid's event burst); set false to skip it on hosts
	// where the extra I/O per novel pid is unwelcome. Ignored when
	// Enrich is false.
	EnrichHash bool

	// EnrichPeers adds the "uid swarm roster" — every other process
	// sharing the caller's real uid, with its pid, comm, and real exe
	// path — into the email + log. Default true. This is the evidence a
	// 3am alert needs by morning: a malware swarm typically runs many
	// processes under one hosting account with spoofed comms (all
	// pointing at one dropped binary), and those pids are gone by the
	// time an operator reads the mail. Bounded and cached per uid.
	// Skipped for uid 0 (would enumerate every root process). Ignored
	// when Enrich is false.
	EnrichPeers bool

	// EnrichCapture copies the offending binary out of /proc/<pid>/exe
	// into CaptureDir at event time, so a dropper that unlinks itself
	// after running can still be analysed. Default true. Only fires for
	// SUSPICIOUS images (exe already unlinked, or living under
	// /tmp,/var/tmp,/dev/shm,/run,/home) so system binaries are never
	// copied; deduplicated by SHA-256; bounded per event and by a
	// directory file cap. Files are written root-only (0600) and never
	// executed. Ignored when Enrich is false.
	EnrichCapture bool

	// CaptureDir is where EnrichCapture writes preserved binaries
	// (named <sha256>.bin). Default DefaultCaptureDir. Created 0700 on
	// first capture.
	CaptureDir string
}

// DefaultCaptureDir is where forensic binary captures land by default.
// Under /var/lib/cfm (runtime/generated artifacts) per the repo's
// config-model convention, not /var/log (human-readable logs).
const DefaultCaptureDir = "/var/lib/cfm/lsm/capture"

// DefaultEventSinkConf is the documented default: 30 per minute per
// policy, with full /proc enrichment (exe hash + uid swarm roster +
// suspicious-binary capture) on. Higher rate than kmsg's 10 because
// cfm.log is a rotated file rather than a fixed-size kernel buffer, but
// tight enough that a runaway trigger cannot bury real events under
// thousands of lines.
func DefaultEventSinkConf() EventSinkConf {
	return EventSinkConf{
		DetectRatePerMin: 30,
		Enrich:           true,
		EnrichHash:       true,
		EnrichPeers:      true,
		EnrichCapture:    true,
		CaptureDir:       DefaultCaptureDir,
	}
}

// enrichConf is the immutable snapshot of the enrichment toggles the
// drain path reads once per event before touching /proc.
type enrichConf struct {
	Enrich, Hash, Peers, Capture bool
	CaptureDir                   string
}

// eventSinkEnrichCfg returns the current enrichment toggles under the
// config lock. Read by the drain path (emitNotify) before snapshotting
// /proc.
func eventSinkEnrichCfg() enrichConf {
	defaultEventSink.cfgMu.Lock()
	defer defaultEventSink.cfgMu.Unlock()
	c := defaultEventSink.cfg
	dir := c.CaptureDir
	if dir == "" {
		dir = DefaultCaptureDir
	}
	return enrichConf{
		Enrich:     c.Enrich,
		Hash:       c.EnrichHash,
		Peers:      c.EnrichPeers,
		Capture:    c.EnrichCapture,
		CaptureDir: dir,
	}
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

// emitDetectEvent routes an event through cfm.log + notify under the
// per-policy cap. The kmsg path is independent and the caller is
// expected to invoke KmsgDetect alongside. When the cap rolls a
// window with suppressed events, a summary line is logged + emitted
// before the current event.
//
// logReason and notifyReason are deliberately distinct. logReason is
// the full per-event forensic line (caller + this specific target)
// written to cfm.log. notifyReason is caller-identity-stable — no pid,
// no target — so the notify deduper (keyed on Reason) collapses a whole
// caller burst (e.g. an OBS-004 /proc sweep hitting dozens of targets)
// into a single email rather than one per target. The per-target detail
// rides along in samples, rendered under "Sample lines:" in the email
// body, so the first email of the burst still shows a concrete target.
func emitDetectEvent(ev Event, logReason, notifyReason string, extra map[string]string, samples []string) {
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
	logging.LogfLSM("[lsm] %s", logReason)
	_ = notify.Emit(notify.Event{
		Kind:     "lsm_detect",
		Section:  "lsm",
		When:     time.Now(),
		Reason:   notifyReason,
		Severity: "warning",
		Extra:    extra,
		Samples:  samples,
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
