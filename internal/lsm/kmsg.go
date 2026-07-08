//go:build linux

package lsm

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// kmsg.go — emit operational lines to the kernel printk ring buffer
// (visible via `dmesg` and `journalctl -k`) so cfm-lsm activity shows
// up alongside kernel events. The shape mirrors LKRG's tag convention:
//
//	[ ts ] CFM-LSM: ALIVE: enabled (CFML-EXEC-001=monitor ...) pinned=/sys/fs/bpf/cfm
//	[ ts ] CFM-LSM: ADOPT: daemon attached to pinned state, draining ringbuf
//	[ ts ] CFM-LSM: DETECT: CFML-EXEC-001 pid=12345 uid=1001 comm=php-fpm path=memfd:payload
//	[ ts ] CFM-LSM: STATE: daemon stopping; pinned state remains attached
//	[ ts ] CFM-LSM: STATE: disabled, all programs detached
//	[ ts ] CFM-LSM: ISSUE: drain error: ringbuf reader returned EAGAIN
//
// The BPF program itself cannot write to dmesg — the kernel does not
// expose printk to BPF. These emissions all happen in userspace, via
// /dev/kmsg, which is the standard CAP_SYS_ADMIN-gated interface for
// "write a line that shows up in dmesg". cfm runs as root, so it has
// the cap; in containers without /dev/kmsg access the writes silently
// no-op (the cfm.log + notify paths still get the event).

// Default /dev/kmsg location. Declared as var so tests can redirect.
var devKmsgPath = "/dev/kmsg"

// kmsgOpenFn opens the kmsg sink. Var so tests can inject a buffer
// without needing root or a real /dev/kmsg.
var kmsgOpenFn = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
}

// Syslog priority bytes. /dev/kmsg accepts a leading "<N>" where N is
// facility*8 + level. We use LOG_USER (facility=1) + standard levels.
const (
	kmsgPriNotice  = 13 // 1*8 + 5 — informational state transitions
	kmsgPriWarning = 12 // 1*8 + 4 — DETECT events
	kmsgPriErr     = 11 // 1*8 + 3 — ISSUE lines
)

// Kernel printk truncates lines longer than this; truncate ourselves
// so we control where the cut happens.
const kmsgMaxLine = 1024

// KmsgConf controls dmesg emission behaviour. Loaded from the
// `[kmsg]` section of /etc/cfm/lsm.conf.
type KmsgConf struct {
	// StateTransitions emits ALIVE / ADOPT / STATE / ISSUE lines on
	// enable / disable / daemon adopt / daemon stop / drain error.
	// Default true. These are infrequent and operationally important.
	StateTransitions bool

	// DetectEvents emits a DETECT line per detection, subject to
	// DetectRatePerMin. Default true.
	DetectEvents bool

	// DetectRatePerMin caps DETECT emissions per policy ID per minute.
	// Surplus events are counted and a "suppressed=N in_last=60s"
	// summary line is emitted on window roll. Default 10.
	// Zero or negative falls back to 10.
	DetectRatePerMin int
}

// DefaultKmsgConf returns the documented defaults: state transitions
// on, DETECT on, 10 per minute per policy.
func DefaultKmsgConf() KmsgConf {
	return KmsgConf{
		StateTransitions: true,
		DetectEvents:     true,
		DetectRatePerMin: 10,
	}
}

// kmsgWriter is the package-internal writer singleton. Three concerns
// guarded by three locks: config, file handle, rate-limit state.
type kmsgWriter struct {
	cfgMu sync.Mutex
	cfg   KmsgConf

	fileMu sync.Mutex
	file   io.WriteCloser
	opened bool

	rateMu sync.Mutex
	rate   map[PolicyID]*kmsgRateBucket
}

type kmsgRateBucket struct {
	windowStart time.Time
	emitted     int
	suppressed  int
}

var defaultKmsg = &kmsgWriter{
	cfg:  DefaultKmsgConf(),
	rate: map[PolicyID]*kmsgRateBucket{},
}

// ConfigureKmsg installs a fresh config on the global kmsg writer.
// Called by the enable + lifecycle paths after parsing lsm.conf.
// Idempotent.
func ConfigureKmsg(c KmsgConf) {
	defaultKmsg.cfgMu.Lock()
	defaultKmsg.cfg = c
	defaultKmsg.cfgMu.Unlock()
}

// KmsgStatef emits an operational state-transition line. The tag is
// the LKRG-style category (ALIVE / ADOPT / STATE / ISSUE); format /
// args build the message body. No rate limiting — these are rare.
func KmsgStatef(tag, format string, args ...any) {
	defaultKmsg.cfgMu.Lock()
	enabled := defaultKmsg.cfg.StateTransitions
	defaultKmsg.cfgMu.Unlock()
	if !enabled {
		return
	}
	pri := kmsgPriNotice
	if tag == "ISSUE" {
		pri = kmsgPriErr
	}
	defaultKmsg.writeLine(pri, tag, fmt.Sprintf(format, args...))
}

// KmsgDetect emits a single DETECT line for one event. Rate-limited
// per policy ID to KmsgConf.DetectRatePerMin. If the rate-window
// rolls and suppressed events accumulated during the previous window,
// a summary line is emitted before the current event's line.
func KmsgDetect(ev Event) {
	defaultKmsg.cfgMu.Lock()
	enabled := defaultKmsg.cfg.DetectEvents
	rate := defaultKmsg.cfg.DetectRatePerMin
	defaultKmsg.cfgMu.Unlock()
	if !enabled {
		return
	}
	if rate <= 0 {
		rate = 10
	}

	allow, summary := defaultKmsg.rateAllow(ev.PolicyID, rate, time.Now())
	if summary != "" {
		defaultKmsg.writeLine(kmsgPriNotice, "STATE", summary)
	}
	if !allow {
		return
	}

	msg := fmt.Sprintf("%s pid=%d uid=%d comm=%s",
		ev.PolicyID, ev.PID, ev.UID, ev.Comm)
	if ev.Filename != "" {
		msg += " path=" + ev.Filename
	}
	if ev.Op != FSOpNone {
		msg += " op=" + ev.Op.String()
	}
	if webOriginPolicy(ev.PolicyID) && ev.Flags&EventFlagWebOrigin != 0 {
		msg += " origin=web"
	}
	if signal := ev.ExecStdioSignal(); signal != "" {
		msg += " stdio=" + signal
	}
	if prim := ev.PrivInstallPrimitive(); prim != "" {
		msg += " primitive=" + prim
	}
	if mode := ev.PtraceMode(); mode != "" {
		msg += " ptrace=" + mode
		if ev.PtraceSameUid() {
			msg += " sameuid=1"
		}
	}
	if sets := ev.CapRaiseSets(); sets != "" {
		msg += " cap_raise=" + sets
	}
	defaultKmsg.writeLine(kmsgPriWarning, "DETECT", msg)
}

// rateAllow returns (allow, summary). allow is whether the current
// event passes the per-policy rate cap. summary is non-empty when
// the call rolled the per-policy window and the previous window had
// suppressed events; the caller should emit it before the current
// event line.
func (w *kmsgWriter) rateAllow(id PolicyID, ratePerMin int, now time.Time) (bool, string) {
	w.rateMu.Lock()
	defer w.rateMu.Unlock()

	b := w.rate[id]
	if b == nil {
		b = &kmsgRateBucket{windowStart: now}
		w.rate[id] = b
	}

	var summary string
	if now.Sub(b.windowStart) >= time.Minute {
		if b.suppressed > 0 {
			summary = fmt.Sprintf("%s suppressed=%d in_last=60s", id, b.suppressed)
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

// writeLine formats and writes a single kmsg line. Lazy-opens the
// /dev/kmsg sink on first use. Errors (no /dev/kmsg, EACCES, EBADF)
// are silently swallowed — kmsg emission is best-effort, never
// load-bearing.
func (w *kmsgWriter) writeLine(pri int, tag, msg string) {
	w.fileMu.Lock()
	defer w.fileMu.Unlock()

	if !w.opened {
		w.opened = true
		f, err := kmsgOpenFn(devKmsgPath)
		if err != nil {
			// Leave w.file nil; subsequent calls remain no-ops.
			return
		}
		w.file = f
	}
	if w.file == nil {
		return
	}

	line := fmt.Sprintf("<%d>CFM-LSM: %s: %s\n", pri, tag, msg)
	if len(line) > kmsgMaxLine {
		line = line[:kmsgMaxLine-1] + "\n"
	}
	_, _ = w.file.Write([]byte(line))
}
