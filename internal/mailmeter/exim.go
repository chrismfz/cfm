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
// Every shape below was measured on the fleet's cPanel mainlogs (8 nodes,
// 2026-11-22..27), not written from Exim's documentation:
//
//   - `<=` arrival:
//   - authenticated SMTP submission (P=esmtpa/esmtpsa) → OutboundSent, keyed
//     on the AUTHENTICATED user from A=… (never the envelope-from, which a
//     compromised account can spoof), mirroring Postfix's sasl_username;
//   - a local script/cron sendmail submission (U=user P=local) → LocalSubmit,
//     keyed on the submitting unix user — the dominant real spam path on
//     cPanel (a hacked PHP app calling mail()).
//   - `=>` / `->` into a local mailbox (T=dovecot_delivery for a cPanel
//     account's own mailbox, T=dovecot_virtual_delivery for a domain mailbox)
//     → InboundLocal, keyed on the address Dovecot's LMTP accepted (the
//     C="250 2.0.0 <addr> … Saved" completion: the real mailbox, after any
//     alias). One event per recipient, as Postfix's LMTP status=sent.
//   - `**` permanent failure:
//   - on a dovecot transport with a 552 "Mailbox is full" → OverQuota for
//     that mailbox. The 452 defer (`==`) is retried and is NOT counted, as
//     Postfix counts only the LMTP bounce;
//   - R=enforce_mail_permissions "Domain D has exceeded the max emails per
//     hour" / "… max defers and failures per hour" ("Message discarded") →
//     Throttled, keyed "*@D": cPanel's limits are per domain, and the "*@"
//     form keeps the row in that domain for a scoped viewer. Its defer
//     ("Message will be reattempted later") is retried and is NOT counted.
//   - an SMTP-time reject (no message flag), unauthenticated (no A=) and
//     permanent (not "temporarily rejected"):
//   - `rejected RCPT <x>: Mailbox is full …` → OverQuota for x (also from an
//     authenticated local sender: the full mailbox is still ours);
//   - any other `rejected RCPT` or `rejected after DATA` → Rejected
//     (host-wide), except cPanel's outgoing SpamAssassin verdict ("detected
//     OUTGOING … as spam"), which is our own mail, not inbound.
//     An AUTHENTICATED `rejected RCPT` is our own user's mail to a bad
//     address (on titan, 52k of 54k, one mail client retrying typo domains),
//     and is not an inbound reject.
//
// Not counted (measured, deliberately): filter-to-folder deliveries
// (T=address_directory, ~1-4% of local deliveries), autoresponder pipes,
// "temporarily rejected connection" (the connect ACL's host rate limit, 4xx),
// the "Warning: Sender rate" log lines (no action), and cPanel's
// "outgoing mail hold / suspension" (an operator hold, not a rate limit).
func ParseEximLine(line string) Event {
	line = strings.TrimRight(line, "\r\n")
	switch eximFlag(line) {
	case "<=":
		return parseEximArrival(line)
	case "=>", "->":
		return parseEximLocalDelivery(line)
	case "**":
		return parseEximFailure(line)
	case "":
		return parseEximReject(line)
	}
	return Event{}
}

func parseEximArrival(line string) Event {
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
	// esmtp/esmtps (unauthenticated remote arrival) is counted on its local
	// delivery (`=>` into a mailbox), not here: an arrival may be relayed on.
	return Event{}
}

// parseEximLocalDelivery counts a delivery into a local mailbox (Received).
func parseEximLocalDelivery(line string) Event {
	if !reEximLocalT.MatchString(line) {
		return Event{} // remote delivery, pipe, filter folder: not a mailbox delivery
	}
	addr := ""
	if m := reEximLMTPAccepted.FindStringSubmatch(line); m != nil {
		addr = m[1]
	} else if m := reEximOrigRcpt.FindStringSubmatch(line); m != nil {
		addr = m[1]
	}
	if addr == "" {
		return Event{}
	}
	return Event{Kind: InboundLocal, ID: eximMsgIDBefore(line), Addr: mailboxOf(addr)}
}

// parseEximFailure handles a `**` (permanent failure) line: a local mailbox
// over quota, or a message cPanel discarded for its per-domain hourly limits.
func parseEximFailure(line string) Event {
	if reEximLocalT.MatchString(line) && overQuotaRe.MatchString(line) {
		if m := reEximLMTPReject.FindStringSubmatch(line); m != nil {
			return Event{Kind: OverQuota, Addr: mailboxOf(m[1])}
		}
		return Event{}
	}
	if strings.Contains(line, " R=enforce_mail_permissions") {
		if m := reEximDomainLimit.FindStringSubmatch(line); m != nil {
			return Event{Kind: Throttled, Addr: "*@" + lower(m[1])}
		}
	}
	return Event{}
}

// parseEximReject handles an SMTP-time reject line (no message flag).
//
// The line holds text the remote side chose: the HELO name, the envelope
// sender (F=<…>, a quoted local part may hold anything), and a reason that can
// echo the addresses back ("Rejected relay attempt: … From: '…' To: '…'").
// So a line with a second "rejected " is not counted at all (a forged one
// can then only lower the counters, never write a row), the quota text must
// follow the reject itself, and the authenticated check reads the line with
// the sender field taken out.
func parseEximReject(line string) Event {
	if strings.Count(line, "rejected ") != 1 {
		return Event{}
	}
	m := reEximReject.FindStringSubmatchIndex(line)
	if m == nil {
		return Event{}
	}
	pre := line[:m[0]]
	if strings.HasSuffix(strings.TrimRight(pre, " "), " temporarily") {
		return Event{} // 4xx: "retry later", not refused
	}
	reason := line[m[1]:]
	if m[2] >= 0 { // rejected RCPT <x>
		if rcpt := line[m[2]:m[3]]; reEximQuotaReason.MatchString(reason) {
			if strings.ContainsAny(rcpt, "\" \t") || strings.IndexByte(rcpt, '@') <= 0 {
				return Event{}
			}
			return Event{Kind: OverQuota, Addr: mailboxOf(rcpt)}
		}
	}
	if reEximAuthed.MatchString(reEximSender.ReplaceAllString(pre, " ")) {
		return Event{} // our own authenticated user's mail, not inbound
	}
	if m[2] < 0 && strings.Contains(reason, "detected OUTGOING") {
		return Event{} // cPanel's outgoing spam scanner: our own mail
	}
	return Event{Kind: Rejected}
}

// eximFlag returns the message flag (<=, =>, ->, **, ==, …) of a mainlog
// line: the token right after the message-id, which follows the date, the
// time, an optional timezone and an optional [pid]. Positional, so a flag-like
// token inside a logged reason or subject is never taken for it. "" when the
// line has no message flag (an SMTP-session line such as a reject).
func eximFlag(line string) string {
	if m := reEximFlagAt.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
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

// eximMsgIDBefore returns the message-id of a flagged line (any flag).
func eximMsgIDBefore(line string) string {
	if m := reEximFlagAt.FindStringSubmatchIndex(line); m != nil {
		fields := strings.Fields(line[:m[2]])
		if len(fields) > 0 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

// mailboxOf lowercases an address and folds a "+detail" subaddress into its
// mailbox: cPanel files spam as `user+spam@dom`, which is the same mailbox.
func mailboxOf(addr string) string {
	addr = lower(addr)
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return addr
	}
	if plus := strings.IndexByte(addr[:at], '+'); plus > 0 {
		return addr[:plus] + addr[at:]
	}
	return addr
}

// Regexes. The `<=` ones are lifted verbatim from internal/detectors/exim/
// relays.go (the production exim/relays detector); the rest were written
// against the fleet's mainlogs (see ParseEximLine).
var (
	reEximArrowIn   = regexp.MustCompile(`\s<=\s`)                   // message genesis (arrival into Exim)
	reEximProto     = regexp.MustCompile(`\bP=(\w+)\b`)              // esmtp, esmtps, esmtpa, esmtpsa, local
	reEximAuthUser  = regexp.MustCompile(`\bA=[^:\s]+:([^\s]+)`)     // A=dovecot_login:<user>
	reEximUserLocal = regexp.MustCompile(`\bU=([^\s]+)\s+P=local\b`) // local sendmail submitter (cron/PHP)

	// `<date> <time> [<tz>] [[pid]] <msgid> <flag> `.
	reEximFlagAt = regexp.MustCompile(`^\S+ \S+ (?:[+-]\d{4} )?(?:\[\d+\] )?\S+ (<=|=>|->|>>|\*\*|==|\*>|<>) `)
	// cPanel's two local-mailbox transports.
	reEximLocalT = regexp.MustCompile(`\sT=dovecot_(?:virtual_)?delivery\b`)
	// The mailbox Dovecot's LMTP accepted: C="250 2.0.0 <addr> <id> Saved".
	reEximLMTPAccepted = regexp.MustCompile(`\sC="250 [0-9.]+ <([^>\s]+@[^>\s]+)>`)
	// Fallback: the original recipient shown before the router, `<addr> R=`.
	reEximOrigRcpt = regexp.MustCompile(`\s<([^>\s]+@[^>\s]+)> R=`)
	// The mailbox in an LMTP over-quota refusal: `LMTP error after …: 552
	// 5.2.2 <addr> Mailbox is full …` (the quota text right after it).
	reEximLMTPReject = regexp.MustCompile(`LMTP error after [^:]+(?::<[^>]*>)?: 5\d\d [0-9.]+ <([^>\s"]+@[^>\s"]+)> (?i:mailbox is full|over quota|quota exceeded)`)
	// A RCPT reject whose reason IS the quota (it starts the reason).
	reEximQuotaReason = regexp.MustCompile(`^:\s*(?i:mailbox is full|over quota|quota exceeded)`)
	// The envelope sender field, a quoted local part included: taken out
	// before looking for A=, which the sender could otherwise forge.
	reEximSender = regexp.MustCompile(`\sF=<(?:"[^"]*"|[^>"])*>`)
	// cPanel's per-domain hourly limits (enforce_mail_permissions router).
	// One `**` line per recipient: a message to 100 addresses counts 100
	// (Postfix's rspamd reject counts once per attempt).
	reEximDomainLimit = regexp.MustCompile(`Domain ([^\s"]+) has exceeded the max (?:emails|defers and failures) per hour`)
	// An SMTP-time reject; group 1 = the RCPT address when it is a RCPT reject.
	reEximReject = regexp.MustCompile(`\brejected (?:RCPT <([^>]*)>|after DATA)`)
	// An authenticated SMTP session (A=<authenticator>:<user>) before the reject.
	reEximAuthed = regexp.MustCompile(`\sA=[^:\s]+:\S`)
)
