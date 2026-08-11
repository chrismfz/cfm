package mailmeter

import (
	"regexp"
	"strings"
)

// ParseEximLine parses one line of Exim's mainlog (cPanel hosts) into an Event.
// Exim records message arrival on a single `<=` line that already names the
// authenticated sender, so — unlike Postfix — no cross-line correlation is
// needed for the outbound-sender signal: an authenticated `<=` becomes an
// OutboundSent that already carries its Addr, and Aggregate counts it directly.
//
// Scope note (PR 1a): only the `<=` arrival line is grounded in-repo (its
// regexes are lifted verbatim from CFM's production exim/relays detector). Exim
// delivery-outcome lines (`=>` sent, `**` bounced, `==` deferred) and inbound
// local-mailbox attribution need real mainlog samples to key safely and are
// deferred to the collector stage — so this parser counts authenticated
// outbound submissions and nothing else. "Outbound submission accepted" is the
// exact compromised-account signal the Mail Monitor was built to surface; it
// mirrors Postfix's sasl_username keying (attribute to the AUTHENTICATED user
// from A=…, never the envelope-from, which a compromised account can spoof).
func ParseEximLine(line string) Event {
	line = strings.TrimRight(line, "\r\n")
	if !reEximArrowIn.MatchString(line) {
		return Event{}
	}
	proto := ""
	if m := reEximProto.FindStringSubmatch(line); m != nil {
		proto = m[1]
	}
	// esmtpa / esmtpsa = authenticated (SMTP AUTH) submission → outbound. The
	// authenticated identity is A=<authenticator>:<user>.
	if proto == "esmtpa" || proto == "esmtpsa" {
		if m := reEximAuthUser.FindStringSubmatch(line); m != nil {
			return Event{Kind: OutboundSent, ID: eximMsgID(line), Addr: lower(m[1])}
		}
	}
	// proto local (cron/PHP via sendmail) and esmtp/esmtps (unauthenticated
	// remote arrival) are not attributed to a mailbox here — see the scope note.
	return Event{}
}

// eximMsgID returns Exim's message-id: the whitespace field immediately before
// " <= ". Exim's default mainlog is `<date> <time> <msgid> <= …`; an optional
// `[pid]` (log_selector) sits before the msgid, so the last field of the prefix
// is the id regardless.
func eximMsgID(line string) string {
	i := strings.Index(line, " <= ")
	if i < 0 {
		return ""
	}
	fields := strings.Fields(line[:i])
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// Regexes lifted verbatim from internal/detectors/exim/relays.go (production
// exim/relays detector), which parses these same `<=` arrival lines in the field.
var (
	reEximArrowIn  = regexp.MustCompile(`\s<=\s`)               // message genesis (arrival into Exim)
	reEximProto    = regexp.MustCompile(`\bP=(\w+)\b`)          // esmtp, esmtps, esmtpa, esmtpsa, local
	reEximAuthUser = regexp.MustCompile(`\bA=[^:\s]+:([^\s]+)`) // A=dovecot_login:<user>
)
