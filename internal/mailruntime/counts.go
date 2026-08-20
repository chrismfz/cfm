package mailruntime

import "time"

// counts.go — the 1a-sig collector's counting layer (docs/whats-wrong-
// rootcause.md §5a). It turns a scanned window of Exim mainlog lines into
// saturation-event tallies by classifying each line (sig.go) and counting the
// kinds. Pure/no-I/O: the tailing is the caller's job (maillog.ScanTail); this
// just classifies + counts, so it is unit-tested in isolation.
//
// v1 scope is exim_mainlog only — both SpamdError and InboundConnRefused are
// logged there. SpamdChildKilled lives in the spamd/syslog stream (a second log
// source) and is deferred; AddEximLine deliberately never increments it.

// SigCounts tallies saturation-event signatures over a scanned window.
type SigCounts struct {
	SpamdError         int `json:"spamd_error"`
	InboundConnRefused int `json:"inbound_conn_refused"`
	SpamdChildKilled   int `json:"spamd_child_killed"`
}

// AddEximLine classifies one Exim mainlog line and bumps the matching counter.
// It only ever increments the two exim_mainlog-borne kinds; a spamd child-kill
// (ClassifySpamdLine, a different log) is not reachable here by construction.
func (c *SigCounts) AddEximLine(line string) {
	switch ClassifyEximLine(line) {
	case SigSpamdError:
		c.SpamdError++
	case SigInboundConnRefused:
		c.InboundConnRefused++
	}
}

// CountEximSignatures tallies the signatures across a slice of Exim mainlog
// lines. Convenience wrapper over AddEximLine for tests and non-streaming
// callers; the endpoint streams via ScanTail + AddEximLine instead.
func CountEximSignatures(lines []string) SigCounts {
	var c SigCounts
	for _, line := range lines {
		c.AddEximLine(line)
	}
	return c
}

// eximTimeLayout is Exim's mainlog leading timestamp: "2026-08-15 16:51:48".
const eximTimeLayout = "2006-01-02 15:04:05"

// EximLineTime parses the leading Exim timestamp of a mainlog line. It returns
// (t, true) only for a native Exim line whose first 19 bytes are the standard
// "YYYY-MM-DD HH:MM:SS" stamp. A syslog/crond-wrapped line (leading "Aug 18
// 02:18:02 host crond[…]:") does NOT start with that shape and yields
// (zero, false) — such lines are still COUNTED by AddEximLine (the signature
// substrings are anchored on the Exim text, not the line start), they just
// don't anchor the observed window. Since the mainlog is overwhelmingly native
// lines, the first/last parsed stamp still bracket the window accurately.
//
// The stamp is parsed as UTC; callers use it only for a window DURATION (last −
// first), so the fixed zone is consistent and the absolute offset is irrelevant.
func EximLineTime(line string) (time.Time, bool) {
	if len(line) < len(eximTimeLayout) {
		return time.Time{}, false
	}
	t, err := time.Parse(eximTimeLayout, line[:len(eximTimeLayout)])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// EximWindow returns the observed time span of a mainlog line stream: the
// earliest and latest parseable Exim timestamps, and whether any were parsed.
// It is fed one line at a time (mirrors the streaming collector). Lines whose
// leading stamp doesn't parse (crond-wrapped, blank, truncated) are skipped for
// windowing but the caller still counts them.
type EximWindow struct {
	First time.Time
	Last  time.Time
	Seen  bool
}

// Observe folds one line's timestamp into the window.
func (w *EximWindow) Observe(line string) {
	t, ok := EximLineTime(line)
	if !ok {
		return
	}
	if !w.Seen {
		w.First, w.Last, w.Seen = t, t, true
		return
	}
	if t.Before(w.First) {
		w.First = t
	}
	if t.After(w.Last) {
		w.Last = t
	}
}

// Seconds returns the window span in whole seconds. It is 0 whenever fewer than
// two distinct timestamps were seen — no lines parsed, a single line, or a burst
// all in the same wall-clock second — so a positive count can legitimately pair
// with a 0 span. Callers turning counts into a RATE must therefore gate on Seen
// (exposed as window_known) AND Seconds()>0 before dividing. Never negative.
func (w *EximWindow) Seconds() int {
	if !w.Seen {
		return 0
	}
	// Mainlog lines are chronological, so Last ≥ First; the abs() is a cheap
	// guard in case a crond-wrapped island carries an out-of-order stamp.
	d := w.Last.Sub(w.First)
	if d < 0 {
		d = -d
	}
	return int(d / time.Second)
}
