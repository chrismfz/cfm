// Package mailmeter turns a mail server's log into per-mailbox send/receive
// counters — the "who is sending a lot" view for spotting compromised accounts
// and outbound spam. It is pure metering: read-only, visibility only, with no
// enforcement and no I/O. This package is the leaf of the Mail Monitor
// subsystem; a later stage adds the tailing collector and persistence.
//
// It is MTA-agnostic. Two log formats are recognised, one per platform:
//
//   - ParseMaillogLine parses the syslog-prefixed mail.log/maillog that Postfix
//     and Dovecot share (DA / plain-Postfix hosts, and Dovecot's own auth lines
//     on any host). Its Postfix branch is a straight port of NGM's parser, which
//     is validated against real Postfix 3.8.5 (AlmaLinux) log lines.
//   - ParseEximLine parses Exim's mainlog (cPanel hosts). Its regexes are lifted
//     verbatim from CFM's production exim/relays detector, which parses the same
//     `<=` message-arrival lines in the field.
//
// Both parsers emit the SAME Event stream, so Aggregate is MTA-agnostic. Events
// are correlated by the mail server's queue/message id (Postfix QID, Exim
// message-id): a Postfix outbound message is logged across two lines (the
// submission daemon records the authenticated sender for a QID; the relay client
// later records status=sent for that QID), whereas Exim records the
// authenticated sender on the single `<=` arrival line. Aggregate handles both:
// OutboundSent with an empty Addr is resolved through the sender map, while
// OutboundSent that already carries its Addr (Exim) is counted directly.
//
// One cross-MTA caveat: Postfix logs one status=sent line per recipient, so a
// message fanned out to N recipients counts as N outbound (recipient-deliveries),
// whereas Exim's `<=` is one event per message. For the abuse view "recipients
// fanned out" is the more useful signal, and a host runs a single MTA, so the
// difference never mixes within one host's numbers.
package mailmeter

import (
	"sort"
	"strings"
)

// Kind classifies a parsed mail-log line.
type Kind int

const (
	None         Kind = iota
	AuthSender        // Postfix submission: QID authenticated as Addr (sasl_username). Populates correlation only.
	OutboundSent      // a message left the server for a local sender. Addr set (Exim) or resolved via ID (Postfix).
	LocalSubmit       // a local script/cron submission (Exim `U=user P=local`); Addr = the submitting local user.
	InboundLocal      // a message delivered into local mailbox Addr.
	Rejected          // an inbound recipient permanently (5xx) rejected — host-wide, no Addr.
	OverQuota         // a message rejected/bounced because recipient Addr is over quota.
	Throttled         // an authenticated sender Addr was rate-limited (rspamd).
	AuthFailed        // a failed mailbox login; Addr = targeted mailbox, "" when host-wide/unknown.
	QueueDone         // Postfix qmgr freed a QID — drop its correlation entry.
)

// Event is one meaningful mail-log line. ID ties a Postfix outbound send back to
// the authenticated sender captured on an earlier line; Addr holds a mailbox
// address (lowercased) or "" for a host-wide signal.
type Event struct {
	Kind Kind
	ID   string
	Addr string
}

// AddrCount is one row of a top-N breakdown.
type AddrCount struct {
	Addr  string `json:"addr"`
	Count int    `json:"count"`
}

// Report is the aggregated view over a batch of events. Callers set Window as a
// human label ("15m", "since boot", …); this package never reads the clock.
type Report struct {
	Window string `json:"window,omitempty"`

	OutboundBySender   map[string]int `json:"-"`
	LocalSubmitByUser  map[string]int `json:"-"` // Exim local-script (PHP/cron) submitters, keyed on unix user
	InboundByMailbox   map[string]int `json:"-"`
	OverQuotaByMailbox map[string]int `json:"-"`
	ThrottledBySender  map[string]int `json:"-"`
	AuthFailByMailbox  map[string]int `json:"-"` // key HostWide ("*") = host-wide failures

	OutboundTotal    int `json:"outbound_total"`
	LocalSubmitTotal int `json:"local_submit_total"`
	InboundTotal     int `json:"inbound_total"`
	RejectedTotal    int `json:"rejected_total"`
}

// NewReport returns a Report with all counter maps initialised. The streaming
// collector makes a fresh one per poll (feeding it that poll's events) and
// flushes the deltas, so the maps never grow across polls.
func NewReport() Report {
	return Report{
		OutboundBySender:   map[string]int{},
		LocalSubmitByUser:  map[string]int{},
		InboundByMailbox:   map[string]int{},
		OverQuotaByMailbox: map[string]int{},
		ThrottledBySender:  map[string]int{},
		AuthFailByMailbox:  map[string]int{},
	}
}

// HostWide is the sentinel address for signals not tied to one mailbox (inbound
// rejects, and failed-login attempts on attacker-supplied junk usernames).
const HostWide = "*"

// maxCorrelated caps the QID→sender correlation map. Entries are normally freed
// on `qmgr: removed`; the cap is a backstop against QIDs leaked because tailing
// began mid-queue — clearing it only loses attribution for a few in-flight
// messages, never miscounts.
const maxCorrelated = 20000

// Correlator carries the Postfix QID→authenticated-sender map ACROSS Feed calls,
// so a streaming collector can call Feed poll-by-poll and still resolve an
// OutboundSent whose AuthSender arrived in an earlier poll. Not safe for
// concurrent use; a single collector goroutine owns one Correlator.
type Correlator struct {
	sender map[string]string
}

// NewCorrelator returns an empty Correlator.
func NewCorrelator() *Correlator {
	return &Correlator{sender: map[string]string{}}
}

// Feed folds one event into r, resolving Postfix outbound sends against the
// carried QID→sender map. Events must arrive in log order (an AuthSender before
// the OutboundSent it explains). This is the single home for the counting and
// correlation rules, shared by the batch Aggregate and the streaming collector.
func (c *Correlator) Feed(ev Event, r *Report) {
	switch ev.Kind {
	case AuthSender:
		if ev.ID != "" && ev.Addr != "" {
			if len(c.sender) >= maxCorrelated {
				c.sender = map[string]string{} // backstop against leaked QIDs
			}
			c.sender[ev.ID] = ev.Addr
		}
	case OutboundSent:
		addr := ev.Addr
		if addr == "" {
			addr = c.sender[ev.ID]
		}
		if addr != "" {
			r.OutboundBySender[addr]++
			r.OutboundTotal++
		}
	case LocalSubmit:
		if ev.Addr != "" {
			r.LocalSubmitByUser[ev.Addr]++
			r.LocalSubmitTotal++
		}
	case InboundLocal:
		if ev.Addr != "" {
			r.InboundByMailbox[ev.Addr]++
			r.InboundTotal++
		}
	case Rejected:
		r.RejectedTotal++
	case OverQuota:
		if ev.Addr != "" {
			r.OverQuotaByMailbox[ev.Addr]++
		}
	case Throttled:
		if ev.Addr != "" {
			r.ThrottledBySender[ev.Addr]++
		}
	case AuthFailed:
		// Fold empty / non-mailbox / oversized usernames into the host-wide
		// bucket. The tried username is ATTACKER-CONTROLLED, so a password spray
		// with random distinct usernames would otherwise grow this map without
		// bound and drown the real "top targeted mailboxes" view. A bare login
		// name (no "@") is a spray guess, not one of our mailboxes.
		if isMailbox(ev.Addr) {
			r.AuthFailByMailbox[ev.Addr]++
		} else {
			r.AuthFailByMailbox[HostWide]++
		}
	case QueueDone:
		delete(c.sender, ev.ID)
	}
}

// Aggregate folds an event batch into a Report, correlating Postfix outbound
// sends by QID. The events must be in log order (an AuthSender must precede the
// OutboundSent it explains); a tailing collector naturally provides that.
func Aggregate(events []Event) Report {
	c := NewCorrelator()
	r := NewReport()
	for _, ev := range events {
		c.Feed(ev, &r)
	}
	return r
}

// TopN returns the n highest-count entries of m, sorted by count descending then
// address ascending so the result is deterministic regardless of map order. A
// non-positive n returns every entry (still sorted).
func TopN(m map[string]int, n int) []AddrCount {
	out := make([]AddrCount, 0, len(m))
	for a, c := range m {
		out = append(out, AddrCount{Addr: a, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Addr < out[j].Addr
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// isMailbox reports whether s looks like one of our mailbox addresses rather
// than an attacker-supplied login guess: it must contain "@" and fit the
// RFC 5321 forward-path limit. Matches NGM's collector guard.
func isMailbox(s string) bool {
	return len(s) <= 254 && strings.IndexByte(s, '@') >= 0
}

// lower lowercases an ASCII mailbox address without allocating for the common
// already-lowercase case's alphabet check. Mail addresses are ASCII in the log
// fields we key on (sasl_username, to=<…>), so a byte-wise fold is correct.
func lower(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
