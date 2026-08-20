// Package mailruntime meters SMTP/scanner runtime *saturation* — the "the mail
// stack is up but wedged" view that the queue/traffic tools miss. A server can
// have CPU/RAM fine, Exim and spamd both "active", and a non-catastrophic queue,
// yet in practice spamd is saturated → SMTP sessions pile up → Exim hits its
// connection cap → submission (587) goes unavailable. The queue-centric mail
// summary (exim/postfix queues detectors) cannot see this; this package supplies
// the missing runtime capacity signal.
//
// This is the pure leaf of the mail_runtime subsystem (see
// docs/whats-wrong-rootcause.md §5a): read-only, no I/O, no enforcement. A later
// stage adds the collector (tailing + config reads + a published summary that
// extends the existing mail detector report) and the what's_wrong integration.
//
// PR 1a scope — GEOMETRY ONLY. This file provides the effective-geometry math
// (current-in-use vs configured-max → utilisation% → a saturation class) plus
// the config-maxima parsers (config.go). The log-signature parsers (Exim
// "too many connections" rejections, spam-ACL "error reading from spamd", spamd
// timeouts / --max-children reached) are deliberately NOT here: per the repo
// rule and docs/whats-wrong-rootcause.md §3, a log-line signature must be
// grounded in a real captured line, not written from memory. They land in a
// follow-up (1a-sig) once real samples are in hand.
//
// Deliberately Exim+spamd scoped (the cPanel fleet). On another stack (rspamd,
// Postfix-native limits) the maxima are read differently; a caller that cannot
// resolve a max gets Utilisation.Known == false → SatUnknown, never a false
// SatOK. This mirrors the MySQL governor's connection-pressure geometry
// (ConnPct/MaxConn/warn/crit), not the queue summary.
package mailruntime

// Saturation classifies a capacity-limited resource's fill level. SatUnknown is
// first-class: when the configured maximum could not be resolved we cannot
// judge, and "unknown" must never collapse to "ok" (docs/whats-wrong-rootcause
// §3).
type Saturation int

const (
	SatUnknown  Saturation = iota // max not known — cannot judge
	SatOK                         // below the warn line
	SatWarn                       // approaching the cap
	SatCritical                   // at / over the cap
)

func (s Saturation) String() string {
	switch s {
	case SatOK:
		return "ok"
	case SatWarn:
		return "warn"
	case SatCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON renders the class as its human string ("ok"/"warn"/"critical"/
// "unknown") rather than the raw int, so the served snapshot and any MCP/tool
// consumer reads a label, not a magic number.
func (s Saturation) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Saturation thresholds, as an integer percent of the configured maximum.
// Conservative on purpose (under-flag): a resource is only "warn" once it is
// genuinely close to its cap. Integer percents (not float fractions) so Classify
// compares by exact cross-multiplication — no float-rounding ambiguity on a
// boundary. Grounded as named constants like the what's_wrong thresholds.
const (
	SatWarnPct = 80 // ≥80% of the cap in use → warn
	SatCritPct = 95 // ≥95% of the cap in use → critical
)

// Utilisation is one resource's current-in-use vs its configured maximum.
// Known == false means the maximum was not resolvable (config unreadable, an
// Exim string-expansion value, a non-Exim stack, …); Pct is then 0 and Classify
// returns SatUnknown. Current is still carried so a caller can display it.
type Utilisation struct {
	Current int     `json:"current"`
	Max     int     `json:"max"`
	Pct     float64 `json:"pct"`   // (Current/Max)*100, 0 when !Known
	Known   bool    `json:"known"` // false → Max unresolved → SatUnknown
}

// NewUtilisation builds a Utilisation from a current count and a resolved
// maximum. max <= 0 is treated as "unknown" (not "0 capacity"): a zero/negative
// cap is never a real limit and must not read as 100%/critical. A negative
// current is clamped to 0.
func NewUtilisation(current, max int) Utilisation {
	if current < 0 {
		current = 0
	}
	if max <= 0 {
		return Utilisation{Current: current, Max: 0, Pct: 0, Known: false}
	}
	return Utilisation{
		Current: current,
		Max:     max,
		// Multiply before dividing so integer-friendly inputs land on an exact
		// value (e.g. 79/100 → 79.0, not 78.999…).
		Pct:   float64(current) * 100 / float64(max),
		Known: true,
	}
}

// Unknown returns a Utilisation whose maximum could not be resolved, carrying
// the current count (if any) for display. Use this instead of NewUtilisation
// when the max is genuinely unknown, to keep the "unknown ≠ ok" contract
// explicit at the call site.
func Unknown(current int) Utilisation {
	if current < 0 {
		current = 0
	}
	return Utilisation{Current: current, Max: 0, Pct: 0, Known: false}
}

// Classify maps the utilisation to a Saturation class. An unresolved maximum is
// SatUnknown, never SatOK. Comparison is exact integer cross-multiplication
// (current/max ≥ pct/100 ⇔ current*100 ≥ max*pct), so a value sitting exactly on
// a threshold classifies deterministically with no float rounding.
func (u Utilisation) Classify() Saturation {
	if !u.Known || u.Max <= 0 {
		return SatUnknown
	}
	switch {
	case u.Current*100 >= u.Max*SatCritPct:
		return SatCritical
	case u.Current*100 >= u.Max*SatWarnPct:
		return SatWarn
	default:
		return SatOK
	}
}
