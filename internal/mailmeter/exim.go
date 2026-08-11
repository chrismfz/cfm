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
// regexes are lifted verbatim from CFM's production exim/relays detector). It
// yields the two outbound-origination signals that matter for spotting a
// compromised account on cPanel:
//
//   - authenticated SMTP submission (P=esmtpa/esmtpsa) → OutboundSent, keyed on
//     the AUTHENTICATED user from A=… (never the envelope-from, which a
//     compromised account can spoof), mirroring Postfix's sasl_username keying;
//   - a local script/cron sendmail submission (U=user P=local) → LocalSubmit,
//     keyed on the submitting unix user — the dominant real spam path on cPanel
//     (a hacked PHP app calling mail()), which authenticated-SMTP metering alone
//     would miss.
//
// Exim delivery-outcome lines (`=>` sent, `**` bounced, `==` deferred) and
// inbound local-mailbox attribution need real mainlog samples to key safely and
// are deferred to the collector stage.
func ParseEximLine(line string) Event {
	line = strings.TrimRight(line, "\r\n")
	if !reEximArrowIn.MatchString(line) {
		return Event{}
	}
	proto := ""
	if m := reEximProto.FindStringSubmatch(line); m != nil {
		proto = m[1]
	}
	switch proto {
	case "esmtpa", "esmtpsa":
		// Authenticated (SMTP AUTH) submission → outbound. The authenticated
		// identity is A=<authenticator>:<user>.
		if m := reEximAuthUser.FindStringSubmatch(line); m != nil {
			return Event{Kind: OutboundSent, ID: eximMsgID(line), Addr: lower(m[1])}
		}
	case "local":
		// Local submission via sendmail (cron, or a PHP app's mail()). U=user is
		// the submitting unix account — a login name, not an email address, so it
		// is kept as-is (not @-normalised) and tallied separately from SMTP senders.
		if m := reEximUserLocal.FindStringSubmatch(line); m != nil {
			return Event{Kind: LocalSubmit, ID: eximMsgID(line), Addr: m[1]}
		}
	}
	// esmtp/esmtps (unauthenticated remote arrival) is inbound; recipient
	// attribution needs the `=>` delivery lines — see the scope note.
	return Event{}
}

// eximMsgID returns Exim's message-id: the whitespace field immediately before
// " <= ". Exim's default mainlog is `<date> <time> <msgid> <= …`; an optional
// `[pid]` (log_selector) sits before the msgid, so the last field of the prefix
// is the id regardless.
func eximMsgID(line string) string {
	loc := reEximArrowIn.FindStringIndex(line) // same delimiter as the arrival gate
	if loc == nil {
		return ""
	}
	fields := strings.Fields(line[:loc[0]])
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// Regexes lifted verbatim from internal/detectors/exim/relays.go (production
// exim/relays detector), which parses these same `<=` arrival lines in the field.
var (
	reEximArrowIn   = regexp.MustCompile(`\s<=\s`)                   // message genesis (arrival into Exim)
	reEximProto     = regexp.MustCompile(`\bP=(\w+)\b`)              // esmtp, esmtps, esmtpa, esmtpsa, local
	reEximAuthUser  = regexp.MustCompile(`\bA=[^:\s]+:([^\s]+)`)     // A=dovecot_login:<user>
	reEximUserLocal = regexp.MustCompile(`\bU=([^\s]+)\s+P=local\b`) // local sendmail submitter (cron/PHP)
)
