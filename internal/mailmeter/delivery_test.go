package mailmeter

import "testing"

// Exim lines follow the real titan mainlog shapes captured in the field.
func TestParseEximDelivery(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantOK  bool
		outcome Outcome
		prov    string
		code    string
		reason  string
	}{
		{
			"remote delivered (=>) → provider by registrable domain, 250/ok",
			`2026-08-11 01:30:13 1wtYVW-0000000GFxD-3Ryp => logs@myip.gr R=dkim_lookuphost T=dkim_remote_smtp H=mymail.myip.gr [84.54.49.25] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes C="250 2.0.0 Ok: queued as 5E5A4621BA2"`,
			true, Delivered, "myip.gr", "250", "ok",
		},
		{
			"local mailbox delivery (dovecot) is NOT a remote delivery",
			`2026-08-11 01:30:03 1wtYVO-0000000GF3J-36ma => evafeiadis <evafeiadis@titan.myip.gr> R=localuser T=dovecot_delivery C="250 2.0.0 <evafeiadis@titan.myip.gr> Saved"`,
			false, OutcomeNone, "", "", "",
		},
		{
			"local virtual delivery is not remote",
			`2026-08-11 01:30:06 1wtYVS-0000000GFXp-0ZB0 => contractsfeedback <contractsfeedback@ordermusic.gr> R=virtual_user T=dovecot_virtual_delivery C="250 2.0.0 Saved"`,
			false, OutcomeNone, "", "", "",
		},
		{
			"pipe delivery (autorespond) is not remote",
			`2026-08-11 01:35:09 1wtYaK-0000000GRSy-2tQh => sales+spam |/usr/local/cpanel/bin/autorespond sales@armos.eu /home2/armoseu/.autorespond (sales@armos.eu) <sales@armos.eu> R=virtual_aliases_nostar T=cagefs_virtual_address_pipe`,
			false, OutcomeNone, "", "", "",
		},
		{
			"bounce (**) to gmail — 550 unsolicited-blocked",
			`2026-08-11 05:44:36 1wtcTj-00000008OnA-0eY6 ** danishop.team@gmail.com R=dkim_lookuphost T=dkim_remote_smtp H=alt1.gmail-smtp-in.l.google.com [142.250.147.27] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes : SMTP error from remote mail server after end of data: 550-5.7.1 [84.54.49.200 12] Gmail has detected that this message is likely unsolicited mail. To reduce the amount of spam sent to Gmail, this message has been blocked.`,
			true, Bounced, "google", "550", "unsolicited-blocked",
		},
		{
			"defer (==) to gmail with host — 421 unsolicited-rate-limited",
			`2026-08-11 00:30:18 1wtMbN-00000004FD2-1H7i == fishingnetcruise@gmail.com (info@fishingnet.gr) <info@fishingnet.gr> R=dkim_lookuphost T=dkim_remote_forwarded_smtp defer (-46) H=alt3.gmail-smtp-in.l.google.com [192.178.211.26]: SMTP error from remote mail server after end of data: 421-4.7.28 Gmail has detected an unusual rate of unsolicited mail.`,
			true, Deferred, "google", "421", "unsolicited-rate-limited",
		},
		{
			"defer (==) 'retry time not reached' is the queue run waiting, not an attempt",
			`2026-08-11 00:30:50 1wtLQP-00000001GcB-3Fx5 == info5@mk.xyrike.top R=dkim_lookuphost T=dkim_remote_smtp defer (-54): retry time not reached for any host for 'mk.xyrike.top'`,
			false, OutcomeNone, "", "", "",
		},
		{
			"routing defer with no router/transport, retry time not reached: not an attempt",
			`2026-11-27 16:00:00 1xWwab-0000000Cabc-1abc == someone@example.com routing defer (-51): retry time not reached`,
			false, OutcomeNone, "", "", "",
		},
		{
			"** 'retry time not reached … after a long failure period' is the final give-up: a bounce",
			`2026-11-27 16:00:01 1xWwac-0000000Cabd-1abd ** x@gmail.com R=dkim_lookuphost T=dkim_remote_smtp: retry time not reached for any host after a long failure period`,
			true, Bounced, "google", "", "gave-up-after-retries",
		},
		{
			"** retry timeout exceeded, no host: a bounce, provider from the recipient's domain",
			`2026-11-27 16:46:27 1xWxDQ-0000000EFG1-3ykS ** someone@gmail.com <all@example.gr>: retry timeout exceeded`,
			true, Bounced, "google", "", "gave-up-after-retries",
		},
		{
			"== connection refused with no host: a deferral to the recipient's domain",
			`2026-11-27 16:00:02 1xWwad-0000000Cabe-1abe == login@mx.spam.example R=dkim_lookuphost T=dkim_remote_smtp defer (Connection refused)`,
			true, Deferred, "spam.example", "", "connection-refused",
		},
		{
			"cPanel's hourly limit (router only) is not a delivery",
			`2026-11-27 15:59:49 1xWwUR-0000000CMKj-0Cd0 ** a@yahoo.com (all@example.gr) <info@example.gr> R=enforce_mail_permissions : Domain example.gr has exceeded the max defers and failures per hour (50/50 (100%)) allowed. Message discarded.`,
			false, OutcomeNone, "", "", "",
		},
		{
			"an outgoing mail hold (router only) is not a delivery",
			`2026-11-27 12:00:05 1xWvAE-0000000AAAE-1AAE == d@gmail.com R=enforce_mail_permissions defer: "Sender wordpress@example.gr has an outgoing mail hold.  Message will be reattempted later"`,
			false, OutcomeNone, "", "", "",
		},
		{
			"a forward refused as spam (router only) is not a delivery",
			`2026-11-26 10:52:15 1xWVDB-00000004gDs-0BJ4 ** n@gmail.com (info@example.gr) <info@example.gr> R=reject_forwarded_mail_marked_as_spam : This mail cannot be forwarded because it was detected as spam.`,
			false, OutcomeNone, "", "", "",
		},
		{
			"a local mailbox over quota (** on a dovecot transport) is not a remote bounce",
			`2026-11-27 12:00:00 1xWvAA-0000000AAAA-1AAA ** info@example.gr R=virtual_user T=dovecot_virtual_delivery: LMTP error after RCPT TO:<info@example.gr>: 552 5.2.2 <info@example.gr> Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			false, OutcomeNone, "", "", "",
		},
		{
			"an alias :fail: (router only) is not a delivery",
			`2026-11-27 12:00:06 1xWvAF-0000000AAAF-1AAF ** old@example.gr R=virtual_aliases: No Such User Here`,
			false, OutcomeNone, "", "", "",
		},
		{
			"a remote router's failure with no transport (typo'd domain) stays an outbound bounce",
			`2026-11-27 12:00:07 1xWvAG-0000000AAAG-1AAG ** someone@gmail.cim R=dkim_lookuphost: Unrouteable address`,
			true, Bounced, "gmail.cim", "", "other",
		},
		{
			"a give-up through cPanel's forwarding transport (no host) is still a bounce",
			`2026-11-27 12:00:08 1xWvAI-0000000AAAI-1AAI ** x@gmail.com (info@example.gr) <info@example.gr> R=dkim_lookuphost T=dkim_remote_forwarded_smtp: retry time not reached for any host after a long failure period`,
			true, Bounced, "google", "", "gave-up-after-retries",
		},
		{
			"a refused connection through the forwarding transport is still a deferral",
			`2026-11-27 12:00:09 1xWvAJ-0000000AAAJ-1AAJ == x@remote.example (info@example.gr) <info@example.gr> R=dkim_lookuphost T=dkim_remote_forwarded_smtp defer (Connection refused)`,
			true, Deferred, "remote.example", "", "connection-refused",
		},
		{
			"Debian's dnslookup router failing with no transport stays an outbound bounce",
			`2026-11-27 12:00:10 1xWvAK-0000000AAAK-1AAK ** x@gmail.cim R=dnslookup: Unrouteable address`,
			true, Bounced, "gmail.cim", "", "other",
		},
		{
			"an unknown router (a smarthost) defers: kept",
			`2026-11-27 12:00:11 1xWvAL-0000000AAAL-1AAL == x@example.com R=smarthost defer (-1): host lookup did not complete`,
			true, Deferred, "example.com", "", "other",
		},
		{
			"an angle-bracketed recipient with a trailing colon gives a clean domain",
			`2026-11-27 12:00:12 1xWvAM-0000000AAAM-1AAM ** <x@gmail.com>: retry timeout exceeded`,
			true, Bounced, "google", "", "gave-up-after-retries",
		},
		{
			"an alias router variant (_nostar) is local policy",
			`2026-11-27 12:00:13 1xWvAN-0000000AAAN-1AAN ** old@example.gr R=virtual_aliases_nostar: No Such User Here`,
			false, OutcomeNone, "", "", "",
		},
		{
			"an arrival (<=) line is not a delivery",
			`2026-08-11 00:05:05 1wtXBC-0000000CnX4-1EyU <= info@axidwear.com H=(axidwear.com) [84.54.49.200] P=esmtpsa A=dovecot_login:info@axidwear.com S=27356`,
			false, OutcomeNone, "", "", "",
		},
		{
			// F1: an arrival with a logged subject containing " => " must NOT be
			// booked as a delivery — the flag field ("<=") is matched positionally.
			"arrival with '=>' inside the logged subject is still an arrival",
			`2026-08-11 00:05:05 1wtXBD-0000000CnX5-2Fy6 <= promo@shop.gr H=(shop.gr) [1.2.3.4] P=esmtpa A=dovecot_login:promo@shop.gr S=900 T="Big Sale => 50% off => today"`,
			false, OutcomeNone, "", "", "",
		},
	}
	for _, c := range cases {
		d, ok := ParseEximDelivery(c.line)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v want %v", c.name, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if d.Outcome != c.outcome || d.Provider != c.prov || d.Code != c.code || d.Reason != c.reason {
			t.Errorf("%s:\n got  outcome=%s prov=%q code=%q reason=%q\n want outcome=%s prov=%q code=%q reason=%q",
				c.name, d.Outcome, d.Provider, d.Code, d.Reason, c.outcome, c.prov, c.code, c.reason)
		}
	}
}

// Postfix lines follow the real Postfix 3.8.5 shapes (NGM corpus).
func TestParsePostfixDelivery(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantOK  bool
		outcome Outcome
		prov    string
		code    string
		reason  string
	}{
		{
			"status=sent → delivered, provider from relay, 250/ok",
			`Jul 23 13:46:16 ngm postfix/smtp[61101]: 91B101FBCFA: to=<chris@myip.gr>, relay=mymail.myip.gr[1.2.3.4]:25, delay=6.4, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 2C03762234A)`,
			true, Delivered, "myip.gr", "250", "ok",
		},
		{
			"status=bounced to gmail → 550 no-such-user",
			`Jul 23 20:27:28 ngm postfix/smtp[134875]: A2FD41FBCEE: to=<someone@gmail.com>, relay=gmail-smtp-in.l.google.com[2a00:1450:4001:c21::1a]:25, delay=0.63, dsn=5.1.1, status=bounced (host gmail-smtp-in.l.google.com said: 550 5.1.1 The email account does not exist)`,
			true, Bounced, "google", "550", "no-such-user",
		},
		{
			"status=deferred → temporary",
			`Jul 23 13:16:53 ngm postfix/smtp[41980]: EABD81FBCFA: to=<x@rem>, relay=mx.remote.example[9.9.9.9]:25, dsn=4.3.0, status=deferred (host mx.remote.example said: 451 4.3.0 Try again later)`,
			true, Deferred, "remote.example", "451", "greylisted",
		},
		{
			"local LMTP delivery (postfix/lmtp) is not a remote delivery",
			`Jul 23 19:38:16 ngm postfix/lmtp[105198]: CFDA41FBCEF: to=<test@nac.gr>, relay=ngm.myip.gr[private/dovecot-lmtp], dsn=2.0.0, status=sent (250 2.0.0 Saved)`,
			false, OutcomeNone, "", "", "",
		},
		{
			// F2: a handoff to a loopback content filter (amavis/rspamd) is an
			// internal hop, not a remote delivery.
			"content-filter reinjection to 127.0.0.1 is not a remote delivery",
			`Jul 23 19:40:00 ngm postfix/smtp[105300]: D1: to=<u@rem.example>, relay=127.0.0.1[127.0.0.1]:10025, delay=0.1, dsn=2.0.0, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10026): 250 Ok)`,
			false, OutcomeNone, "", "", "",
		},
	}
	for _, c := range cases {
		d, ok := ParsePostfixDelivery(c.line)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v want %v", c.name, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if d.Outcome != c.outcome || d.Provider != c.prov || d.Code != c.code || d.Reason != c.reason {
			t.Errorf("%s:\n got  outcome=%s prov=%q code=%q reason=%q\n want outcome=%s prov=%q code=%q reason=%q",
				c.name, d.Outcome, d.Provider, d.Code, d.Reason, c.outcome, c.prov, c.code, c.reason)
		}
	}
}

func TestClassifyProvider(t *testing.T) {
	cases := map[string]string{
		"alt1.gmail-smtp-in.l.google.com": "google",
		"gmail-smtp-in.l.google.com":      "google",
		"mx.protection.outlook.com":       "microsoft",
		"eur.olc.protection.outlook.com":  "microsoft",
		"mta5.am0.yahoodns.net":           "yahoo",
		"mx1.mail.icloud.com":             "apple",
		"mymail.myip.gr":                  "myip.gr",
		"mail.example.co":                 "example.co",
		"example.com":                     "example.com",
		"120.48.27.74":                    "120.48.27.74", // bare IP kept, not chopped
		"":                                "",
		// F3: label-boundary match — these must NOT be mislabeled apple/google.
		"acme.com":                   "acme.com",
		"readme.com":                 "readme.com",
		"pineapple.com":              "pineapple.com",
		"notgoogle.com.attacker.net": "attacker.net",
		"mail.me.com":                "apple", // a real apple subdomain still matches
	}
	for host, want := range cases {
		if got := classifyProvider(host); got != want {
			t.Errorf("classifyProvider(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestNormalizeDeliveryReason(t *testing.T) {
	cases := map[string]string{
		"421-4.7.27 Your email has been rate limited because SPF authentication didn't pass": "spf-not-passed",
		"421-4.7.28 Gmail has detected an unusual rate of unsolicited mail":                  "unsolicited-rate-limited",
		"550-5.7.1 Gmail has detected that this message is likely unsolicited mail":          "unsolicited-blocked",
		"retry time not reached for any host for 'x'":                                        "retry-backoff",
		"Connection refused": "connection-refused",
		"host said: 550 5.1.1 Recipient address rejected: Address does not exist": "no-such-user",
		"550 Mailbox is full / Blocks limit exceeded":                             "over-quota",
		"554 5.7.1 Relay access denied":                                           "relay-denied",
		"250 2.0.0 Ok: queued as ABC":                                             "ok",
		"":                                                                        "",
	}
	for raw, want := range cases {
		if got := normalizeDeliveryReason(raw); got != want {
			t.Errorf("normalizeDeliveryReason(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestCPanelFailureLimit(t *testing.T) {
	for line, want := range map[string]bool{
		`2026-11-27 15:59:49 1xWwUR-0000000CMKj-0Cd0 ** a@yahoo.com R=enforce_mail_permissions : Domain example.gr has exceeded the max defers and failures per hour (50/50 (100%)) allowed. Message discarded.`:                       true,
		`2026-11-25 03:56:44 1xW2FV-0000000Dnbe-3gxC ** b@gmail.com R=enforce_mail_permissions : Domain example.gr has exceeded the max emails per hour (125/100 (125%)) allowed.  Message discarded.`:                                 false,
		`2026-11-27 15:59:49 1xWwUR-0000000CMKj-0Cd0 == a@yahoo.com R=enforce_mail_permissions defer: "Domain example.gr has exceeded the max defers and failures per hour (50/50 (100%)) allowed. Message will be reattempted later"`: false,
	} {
		if got := CPanelFailureLimit(line); got != want {
			t.Errorf("CPanelFailureLimit(%.80q…) = %v, want %v", line, got, want)
		}
	}
	for tr, want := range map[string]bool{"dkim_remote_smtp": true, "dkim_remote_forwarded_smtp": true, "remote_smtp": true, "dovecot_virtual_delivery": false, "cagefs_virtual_address_pipe": false, "address_directory": false} {
		if RemoteTransport(tr) != want {
			t.Errorf("RemoteTransport(%q) != %v", tr, want)
		}
	}
}
