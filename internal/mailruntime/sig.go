package mailruntime

import "strings"

// sig.go — the log-signature classifier for mail_runtime (docs/whats-wrong-
// rootcause.md §5a, "1a-sig"). Pure/no-I/O: it turns ONE log line into a
// saturation-event kind. A later collector tails the logs and counts these over
// a rolling window to enrich the geometry snapshot ("spamd 10/10 + N read-from-
// spamd timeouts in 5m").
//
// Every pattern here is GROUNDED in real fleet log lines captured across six
// cPanel nodes (orion/titan/virgo/earth/mars/rigel), not written from memory —
// see the verbatim fixtures in sig_test.go.

// SigKind classifies one mail-stack log line as a saturation event, or SigNone.
type SigKind int

const (
	SigNone SigKind = iota

	// SigSpamdError: Exim's spam ACL could not get a verdict from spamd — the
	// smoking gun of spamd saturation/unreachability. Real forms:
	//   spam acl condition: error reading from spamd [127.0.0.1]:783, socket: Connection timed out
	//   spam acl condition: cannot parse spamd [127.0.0.1]:783 output
	// (also seen wrapped by crond[...] when the sender is a local cron job).
	SigSpamdError

	// SigInboundConnRefused: THIS box's Exim refused an INBOUND connection at its
	// smtp_accept_max cap. Real form (no message-id, our daemon's own phrasing):
	//   Connection from [51.89.47.4]:24244 refused: too many connections
	// Deliberately distinct from an OUTBOUND delivery being refused by a REMOTE
	// MX ("H=host [ip]: SMTP error from remote mail server ... 421 Too many
	// concurrent SMTP connections"), which is a deliverability signal, not our
	// saturation, and must NOT match here.
	SigInboundConnRefused

	// SigSpamdChildKilled: spamd's prefork scaler killed a failed/hung scanner
	// child — a sign of spamd struggling under load. Real form:
	//   spamd[1782837]: prefork: killing failed child 1806856 fd=7 at .../SpamdForkScaling.pm line 169.
	//   spamd[1782837]: prefork: killed child 1806856
	// The routine "prefork: child states: II" and "prefork: adjust: … children"
	// lines are normal scaler chatter and are NOT events.
	SigSpamdChildKilled
)

func (k SigKind) String() string {
	switch k {
	case SigSpamdError:
		return "spamd_error"
	case SigInboundConnRefused:
		return "inbound_conn_refused"
	case SigSpamdChildKilled:
		return "spamd_child_killed"
	default:
		return "none"
	}
}

// ClassifyEximLine classifies one Exim mainlog line (also matches a line wrapped
// by crond[...], since the substrings are anchored on the Exim text, not the
// line start).
//
// Matching is case-SENSITIVE on purpose: the phrases are Exim/SpamAssassin
// compile-time constants, and the case difference is itself load-bearing — our
// daemon writes lowercase "refused: too many connections" whereas a remote MX's
// 421 says capital-T "Too many concurrent SMTP connections". Do NOT "harden"
// this into case-insensitive matching; that would reintroduce the false positive
// the two-substring guard below prevents.
func ClassifyEximLine(line string) SigKind {
	// spamd unreachable / unparseable (both mention "spamd" explicitly).
	if strings.Contains(line, "error reading from spamd") ||
		strings.Contains(line, "cannot parse spamd") {
		return SigSpamdError
	}
	// Our own inbound cap rejection. Require BOTH the daemon's own line shape
	// ("Connection from [ip]:port …") AND its exact reject phrase, so a remote
	// MX's 421 text echoed verbatim into the mainlog (which carries "H=… SMTP
	// error from remote mail server …", never a leading "Connection from … ")
	// can never be misread as our inbound saturation — even if some third-party
	// banner happened to contain the lowercase phrase.
	if strings.Contains(line, "Connection from ") &&
		strings.Contains(line, "refused: too many connections") {
		return SigInboundConnRefused
	}
	return SigNone
}

// ClassifySpamdLine classifies one spamd log line (maillog / messages). Only a
// killed failed/hung child counts; routine prefork state/adjust chatter does not.
func ClassifySpamdLine(line string) SigKind {
	if strings.Contains(line, "prefork: killing failed child") ||
		strings.Contains(line, "prefork: killed child") {
		return SigSpamdChildKilled
	}
	return SigNone
}
