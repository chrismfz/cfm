package mailmeter

import (
	"regexp"
	"strings"
)

// ParseMaillogLine parses one line of the syslog-prefixed mail log that Postfix
// and Dovecot share (mail.log / maillog). It returns a single Event or the None
// zero value. The Postfix branch and its regexes are a direct port of NGM's
// mailmeter parser, validated against a real Postfix 3.8.5 / AlmaLinux maillog;
// the Dovecot branch counts once-per-session failed logins. Correlated Postfix
// signals:
//
//   - OUTBOUND: a submission daemon logs `QID: client=…, sasl_username=<addr>`
//     (AuthSender), then the relay client logs `QID: … status=sent`
//     (OutboundSent with empty Addr — Aggregate resolves it via the QID).
//   - INBOUND: the LMTP client logs `QID: to=<addr>, …dovecot-lmtp… status=sent`
//     (InboundLocal), one message delivered into a local mailbox.
//
// A QID is freed when qmgr logs `QID: removed` (QueueDone), so a streaming
// consumer's correlation map stays bounded to the active queue.
func ParseMaillogLine(line string) Event {
	line = strings.TrimRight(line, "\r\n")
	m := syslogRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}
	}
	prog, rest := m[1], m[2]
	switch {
	case isSubmission(prog):
		if a := authRe.FindStringSubmatch(rest); a != nil {
			return Event{Kind: AuthSender, ID: a[1], Addr: lower(a[2])}
		}
		// A ratelimit soft-reject carries no QID (NOQUEUE), so attribute directly
		// to the sasl_username on the line.
		if rlRejectRe.MatchString(rest) {
			if u := saslInLineRe.FindStringSubmatch(rest); u != nil {
				return Event{Kind: Throttled, Addr: lower(u[1])}
			}
		}
		// A failed submission login (password guessing against 587/465).
		if saslFailRe.MatchString(rest) {
			return Event{Kind: AuthFailed}
		}
	case prog == "dovecot":
		// Failed IMAP/POP logins, attributed to the targeted account when the line
		// names one. Dovecot auth-worker/auth detail lines are deliberately NOT
		// matched — the *-login summary is the once-per-session signal.
		if dovecotAuthFailRe.MatchString(rest) {
			ev := Event{Kind: AuthFailed}
			if u := loginUserRe.FindStringSubmatch(rest); u != nil {
				ev.Addr = lower(u[1])
			}
			return ev
		}
	case prog == "postfix/smtpd":
		// Inbound :25 recipient rejects. An over-quota reject is attributed to the
		// real recipient; any other permanent (5xx) RCPT reject is counted
		// host-wide. 4xx soft-rejects are excluded upstream (retry, not blocked).
		if rcptRejectRe.MatchString(rest) {
			if overQuotaRe.MatchString(rest) {
				if to := toAddrRe.FindStringSubmatch(rest); to != nil {
					return Event{Kind: OverQuota, Addr: lower(to[1])}
				}
			}
			return Event{Kind: Rejected}
		}
	case prog == "postfix/smtp":
		if o := outRe.FindStringSubmatch(rest); o != nil {
			return Event{Kind: OutboundSent, ID: o[1]}
		}
	case prog == "postfix/lmtp":
		if l := lmtpRe.FindStringSubmatch(rest); l != nil {
			return Event{Kind: InboundLocal, ID: l[1], Addr: lower(l[2])}
		}
		// A local delivery that PERMANENTLY failed on quota (5xx bounce): attribute
		// the over-quota error to the recipient mailbox.
		if f := lmtpFailRe.FindStringSubmatch(rest); f != nil && overQuotaRe.MatchString(rest) {
			return Event{Kind: OverQuota, Addr: lower(f[2])}
		}
	case prog == "postfix/qmgr":
		if d := doneRe.FindStringSubmatch(rest); d != nil {
			return Event{Kind: QueueDone, ID: d[1]}
		}
	}
	return Event{}
}

// isSubmission matches the daemons that carry an authenticated local sender: the
// submission (587) and smtps (465) smtpd services. The plain postfix/smtpd
// (inbound :25) never has our users' sasl_username, so it's excluded.
func isSubmission(prog string) bool {
	return prog == "postfix/submission/smtpd" || prog == "postfix/smtps/smtpd"
}

// Regexes ported verbatim from NGM's mailmeter (validated against real Postfix
// 3.8.5 / AlmaLinux lines) plus Dovecot login-failure summaries. Keep in sync
// with their rationale comments if a Postfix version ever changes a shape.
var (
	// syslogRe splits the rsyslog prefix into program + message. Program is the
	// tag before an optional [pid] and the colon, e.g. "postfix/submission/smtpd",
	// "postfix/smtp", "postfix/lmtp", "postfix/qmgr", "dovecot".
	syslogRe = regexp.MustCompile(`^\w{3}\s+\d+\s+[0-9:]+\s+\S+\s+([a-zA-Z0-9/_.-]+?)(?:\[\d+\])?:\s+(.*)$`)

	// `<QID>: client=…, … sasl_username=<addr>` on a submission/smtps daemon.
	authRe = regexp.MustCompile(`^(\w+): client=.*\bsasl_username=([^\s,]+)`)
	// `<QID>: to=<…>, … status=sent` on the relay smtp client (outbound).
	outRe = regexp.MustCompile(`^(\w+): to=<[^>]*>,.*\bstatus=sent\b`)
	// `<QID>: to=<addr>, … dovecot-lmtp … status=sent` — local delivery.
	lmtpRe = regexp.MustCompile(`^(\w+): to=<([^>]+)>,.*dovecot-lmtp.*\bstatus=sent\b`)
	// `<QID>: removed` on qmgr.
	doneRe = regexp.MustCompile(`^(\w+): removed\b`)
	// A rspamd ratelimit soft-reject on a submission daemon (NOQUEUE): kept
	// specific to "rate limit" so a spam reject (5.7.1) isn't counted as a throttle.
	rlRejectRe   = regexp.MustCompile(`(?i)milter-reject:.*\brate limit`)
	saslInLineRe = regexp.MustCompile(`\bsasl_username=([^\s,]+)`)
	// A PERMANENT (5xx) inbound recipient reject on the :25 smtpd. 4xx soft-rejects
	// (greylist, temp policy) are excluded — they mean "retry later", not "blocked".
	rcptRejectRe = regexp.MustCompile(`reject: RCPT from \S+: 5\d\d`)
	// The over-quota signature — our quota-status reply and Dovecot's LMTP
	// "Quota exceeded". Case-insensitive so both the RCPT reject and LMTP bounce hit.
	overQuotaRe = regexp.MustCompile(`(?i)over quota|quota exceeded|mailbox is full`)
	// An LMTP delivery that PERMANENTLY failed (over-quota bounce). Only `bounced`
	// (5xx, logged once) — NOT `deferred`, which qmgr retries and would re-count.
	lmtpFailRe = regexp.MustCompile(`^(\w+): to=<([^>]+)>,.*dovecot-lmtp.*\bstatus=bounced\b`)
	// The recipient on a reject line, for attributing an over-quota RCPT reject.
	toAddrRe = regexp.MustCompile(`\bto=<([^>]+)>`)
	// A dovecot imap/pop3 login process reporting a FAILED authentication. Matching
	// "(auth failed" counts each failed session once; "(no auth attempts" (port
	// scans, TLS probes) deliberately does NOT match.
	dovecotAuthFailRe = regexp.MustCompile(`^(?:imap|pop3)-login: .*\(auth failed`)
	// The targeted account on a dovecot login line: user=<addr>. ATTACKER-SUPPLIED
	// (whatever username they tried); an empty value falls back to the host-wide bucket.
	loginUserRe = regexp.MustCompile(`\buser=<([^>]*)>`)
	// A postfix submission/smtps SASL failure with no username on the line →
	// counted host-wide. A failed submission auth does not also emit a dovecot
	// *-login line, so the two never double-count.
	saslFailRe = regexp.MustCompile(`^warning: [^:]+: SASL \S+ authentication failed`)
)
