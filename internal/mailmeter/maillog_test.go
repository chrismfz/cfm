package mailmeter

import "testing"

// Lines copied verbatim from a real Postfix 3.8.5 / AlmaLinux maillog (via NGM's
// validated corpus) plus Dovecot login summaries.
func TestParseMaillogLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Event
	}{
		{
			"submission records authenticated sender for QID",
			`Jul 23 13:46:09 ngm postfix/submission/smtpd[61073]: 91B101FBCFA: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=test@nac.gr`,
			Event{Kind: AuthSender, ID: "91B101FBCFA", Addr: "test@nac.gr"},
		},
		{
			"relay client delivered the QID (status=sent) — Addr resolved later",
			`Jul 23 13:46:16 ngm postfix/smtp[61101]: 91B101FBCFA: to=<chris@myip.gr>, relay=mymail.myip.gr[2a14:4280:1:1:151:78d:5112:d3c6]:25, delay=6.4, delays=0.02/0.06/4.1/2.2, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 2C03762234A)`,
			Event{Kind: OutboundSent, ID: "91B101FBCFA"},
		},
		{
			"smtps submission also carries sasl_username",
			`Jul 23 13:57:55 ngm postfix/submission/smtpd[68220]: 8E0E81FBCEF: client=unknown[84.54.49.38], sasl_method=PLAIN, sasl_username=Test@NAC.gr`,
			Event{Kind: AuthSender, ID: "8E0E81FBCEF", Addr: "test@nac.gr"},
		},
		{
			"LMTP delivered into a local mailbox",
			`Jul 23 19:38:16 ngm postfix/lmtp[105198]: CFDA41FBCEF: to=<test@nac.gr>, relay=ngm.myip.gr[private/dovecot-lmtp], delay=0.08, delays=0.03/0.02/0.02/0.01, dsn=2.0.0, status=sent (250 2.0.0 <test@nac.gr> fF52NXhDYmrvmgEA6PiUog Saved)`,
			Event{Kind: InboundLocal, ID: "CFDA41FBCEF", Addr: "test@nac.gr"},
		},
		{
			"aliased inbound — final to= is what counts",
			`Jul 23 19:38:27 ngm postfix/lmtp[105198]: 92B661FBCEF: to=<test@nac.gr>, orig_to=<nobody@nac.gr>, relay=ngm.myip.gr[private/dovecot-lmtp], delay=0.02, delays=0.01/0/0/0.01, dsn=2.0.0, status=sent (250 2.0.0 <test@nac.gr> iLkwJINDYmrvmgEA6PiUog Saved)`,
			Event{Kind: InboundLocal, ID: "92B661FBCEF", Addr: "test@nac.gr"},
		},
		{
			"qmgr removed frees the QID",
			`Jul 23 13:46:16 ngm postfix/qmgr[59717]: 91B101FBCFA: removed`,
			Event{Kind: QueueDone, ID: "91B101FBCFA"},
		},
		{
			"rspamd ratelimit soft-reject (NOQUEUE, inline sasl_username)",
			`Jul 24 10:15:02 ngm postfix/submission/smtpd[61073]: NOQUEUE: milter-reject: END-OF-MESSAGE from unknown[84.54.49.38]: 4.7.1 Rate limit exceeded; from=<spammer@nac.gr> to=<victim@example.com> proto=ESMTP helo=<x> sasl_username=spammer@nac.gr`,
			Event{Kind: Throttled, Addr: "spammer@nac.gr"},
		},
		{
			"spam milter-reject (5.7.1) is NOT a throttle",
			`Jul 24 10:16:00 ngm postfix/submission/smtpd[61073]: NOQUEUE: milter-reject: END-OF-MESSAGE from unknown[1.2.3.4]: 5.7.1 Gtube pattern; from=<x@nac.gr> to=<y@example.com> proto=ESMTP helo=<x> sasl_username=x@nac.gr`,
			Event{Kind: None},
		},
		{
			"LMTP deferred (internal error) is not a delivery",
			`Jul 23 13:16:53 ngm postfix/lmtp[41980]: EABD81FBCFA: to=<test@nac.gr>, relay=ngm.myip.gr[private/dovecot-lmtp], delay=0.16, delays=0.04/0.02/0.03/0.06, dsn=4.3.0, status=deferred (host ngm.myip.gr[private/dovecot-lmtp] said: 451 4.3.0 <test@nac.gr> Temporary internal error (in reply to RCPT TO command))`,
			Event{Kind: None},
		},
		{
			"outbound that bounced is not a successful send",
			`Jul 23 20:27:28 ngm postfix/smtp[134875]: A2FD41FBCEE: to=<someone@gmail.com>, relay=gmail-smtp-in.l.google.com[2a00:1450:4001:c21::1a]:25, delay=0.63, delays=0.01/0.05/0.5/0.06, dsn=5.2.1, status=bounced (host gmail-smtp-in.l.google.com said: 550 5.2.1 inactive)`,
			Event{Kind: None},
		},
		{
			"4xx temp RCPT reject does not count as Rejected",
			`Jul 23 19:21:23 ngm postfix/smtpd[96001]: NOQUEUE: reject: RCPT from unknown[158.94.211.145]: 454 4.7.1 <spameri@tiscali.it>: Relay access denied; from=<spameri@tiscali.it> to=<spameri@tiscali.it> proto=ESMTP helo=<WIN-7N1FIECL6IC>`,
			Event{Kind: None},
		},
		{
			"permanent 5xx inbound RCPT reject — host-wide",
			`Jul 23 19:22:00 ngm postfix/smtpd[96002]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 550 5.1.1 <nobody@nac.gr>: Recipient address rejected: User unknown; from=<s@x> to=<nobody@nac.gr> proto=ESMTP helo=<x>`,
			Event{Kind: Rejected},
		},
		{
			"over-quota RCPT reject attributed to the recipient",
			`Jul 31 09:10:00 ngm postfix/smtpd[123]: NOQUEUE: reject: RCPT from mx[1.1.1.1]: 552 5.2.2 <full@nac.gr>: Recipient address rejected: Mailbox is full (over quota); from=<s@x> to=<full@nac.gr> proto=ESMTP helo=<mx>`,
			Event{Kind: OverQuota, Addr: "full@nac.gr"},
		},
		{
			"over-quota LMTP bounce attributed to the recipient",
			`Jul 31 09:11:00 ngm postfix/lmtp[124]: E1: to=<box@nac.gr>, relay=ngm[private/dovecot-lmtp], dsn=5.2.2, status=bounced (host ngm said: 552 5.2.2 Mailbox is full (over quota))`,
			Event{Kind: OverQuota, Addr: "box@nac.gr"},
		},
		{
			"bare submission connect (no auth yet)",
			`Jul 23 13:46:06 ngm postfix/submission/smtpd[61073]: connect from localhost[127.0.0.1]`,
			Event{Kind: None},
		},
		{
			"dovecot noise",
			`Jul 23 22:50:47 ngm dovecot[152215]: lmtp(200487): Connect from local`,
			Event{Kind: None},
		},
		{
			"dovecot imap-login auth failed, named account",
			`Aug  2 21:00:00 ngm dovecot[900]: imap-login: Disconnected: Connection closed (auth failed, 3 attempts in 12 secs): user=<test@nac.gr>, method=PLAIN, rip=203.0.113.9, lip=10.0.0.1, TLS`,
			Event{Kind: AuthFailed, Addr: "test@nac.gr"},
		},
		{
			"dovecot pop3-login auth failed, bare username lowercased",
			`Aug  2 21:00:05 ngm dovecot[900]: pop3-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<ADMIN>, method=PLAIN, rip=203.0.113.9, lip=10.0.0.1`,
			Event{Kind: AuthFailed, Addr: "admin"},
		},
		{
			"dovecot auth failed, empty user → host-wide",
			`Aug  2 21:00:06 ngm dovecot[900]: imap-login: Aborted login (auth failed, 1 attempts in 2 secs): user=<>, method=PLAIN, rip=203.0.113.9`,
			Event{Kind: AuthFailed},
		},
		{
			"TLS probe / port scan (no auth attempts) is not a failure",
			`Aug  2 21:00:07 ngm dovecot[900]: imap-login: Disconnected: Connection closed (no auth attempts in 2 secs): user=<>, rip=203.0.113.9`,
			Event{Kind: None},
		},
		{
			"dovecot auth-worker detail line must not double-count",
			`Aug  2 21:00:08 ngm dovecot[901]: auth-worker(902): sql(test@nac.gr,203.0.113.9): Password mismatch`,
			Event{Kind: None},
		},
		{
			"postfix submission SASL failure — host-wide",
			`Aug  2 21:00:10 ngm postfix/submission/smtpd[901]: warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`,
			Event{Kind: AuthFailed},
		},
		{
			"same SASL warning on inbound :25 smtpd is NOT counted",
			`Aug  2 21:00:11 ngm postfix/smtpd[902]: warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`,
			Event{Kind: None},
		},
	}
	for _, c := range cases {
		if got := ParseMaillogLine(c.line); got != c.want {
			t.Errorf("%s:\n  ParseMaillogLine(%.70q…)\n  got  %+v\n  want %+v", c.name, c.line, got, c.want)
		}
	}
}
