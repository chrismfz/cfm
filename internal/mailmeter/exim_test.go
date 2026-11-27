package mailmeter

import "testing"

// Lines follow the real Exim mainlog `<=` shapes documented in CFM's
// exim/relays detector (the authenticated-submission A=dovecot_login:<user> form
// is the one seen in the field for compromised-account outbound bursts).
func TestParseEximLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Event
	}{
		{
			"authenticated submission (esmtpa) → outbound, keyed on the A= user",
			`2026-08-07 12:00:01 1uKq9r-0002Ab-7H <= support@ordermusic.gr H=(mail.example.gr) [10.0.0.5]:52134 P=esmtpa A=dovecot_login:support@ordermusic.gr S=3421 id=abc@ordermusic.gr T="Order confirmation"`,
			Event{Kind: OutboundSent, ID: "1uKq9r-0002Ab-7H", Addr: "support@ordermusic.gr"},
		},
		{
			"esmtpsa authenticated sender, mixed case lowercased",
			`2026-08-07 12:00:02 1uKq9s-0002Ac-8J <= Info@AxidWear.com H=(host) [1.2.3.4]:40000 P=esmtpsa A=dovecot_login:Info@AxidWear.com S=1200`,
			Event{Kind: OutboundSent, ID: "1uKq9s-0002Ac-8J", Addr: "info@axidwear.com"},
		},
		{
			"log_selector +pid prefix — msgid is still the field before <=",
			`2026-08-07 12:00:07 [12345] 1uKq9w-0002Ag-2N <= sales@shop.gr H=(h) [10.0.0.9]:5000 P=esmtpa A=dovecot_login:sales@shop.gr S=900`,
			Event{Kind: OutboundSent, ID: "1uKq9w-0002Ag-2N", Addr: "sales@shop.gr"},
		},
		{
			"unauthenticated remote arrival (esmtp, no A=) is not counted in 1a",
			`2026-08-07 12:00:03 1uKq9t-0002Ad-9K <= newsletter@remote.example H=mail.remote.example [203.0.113.50]:33210 P=esmtp S=8000`,
			Event{Kind: None},
		},
		{
			"local sendmail submission (cron/PHP, P=local) keyed on the unix user",
			`2026-08-07 12:00:04 1uKq9u-0002Ae-0L <= root@server.example U=evafeiadis P=local S=512`,
			Event{Kind: LocalSubmit, ID: "1uKq9u-0002Ae-0L", Addr: "evafeiadis"},
		},
		{
			"a remote delivery (=>) line is neither an arrival nor a local delivery",
			`2026-08-07 12:00:05 1uKq9r-0002Ab-7H => chris@gmail.com R=dkim_lookuphost T=remote_smtp H=gmail-smtp-in.l.google.com [142.250.1.27]:25`,
			Event{Kind: None},
		},
		{
			"esmtpa without a parseable A= user is skipped (defensive)",
			`2026-08-07 12:00:06 1uKq9v-0002Af-1M <= weird@x H=(h) [1.1.1.1]:1 P=esmtpa S=1`,
			Event{Kind: None},
		},
		{
			"a completely unrelated exim line",
			`2026-08-07 12:00:08 1uKq9r-0002Ab-7H Completed`,
			Event{Kind: None},
		},
	}
	for _, c := range cases {
		if got := ParseEximLine(c.line); got != c.want {
			t.Errorf("%s:\n  ParseEximLine(%.70q…)\n  got  %+v\n  want %+v", c.name, c.line, got, c.want)
		}
	}
}

// Shapes measured on the fleet's cPanel mainlogs (2026-11-27), with the
// addresses, hosts and ids replaced. See ParseEximLine for what each maps to.
func TestParseEximLine_FleetShapes(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Event
	}{
		// ---- Received: local mailbox deliveries ----
		{
			"=> into a domain mailbox: keyed on the LMTP-accepted address, +spam folded",
			`2026-11-27 16:16:00 1xWwk3-0000000Czb5-3gF2 => nikos+spam <nikos@example.gr> R=virtual_user T=dovecot_virtual_delivery C="250 2.0.0 <nikos+spam@example.gr> 3SBTCKCQCWvmVS8AL3MpMA Saved"`,
			Event{Kind: InboundLocal, ID: "1xWwk3-0000000Czb5-3gF2", Addr: "nikos@example.gr"},
		},
		{
			"-> second recipient of the same message",
			`2026-11-27 16:10:37 1xWwes-0000000CnsZ-3CfT -> thomas <thomas@example.com> R=virtual_user T=dovecot_virtual_delivery C="250 2.0.0 <thomas@example.com> V9WYLF2PCWsOkS4AL3MpMA:R3 Saved"`,
			Event{Kind: InboundLocal, ID: "1xWwes-0000000CnsZ-3CfT", Addr: "thomas@example.com"},
		},
		{
			"an alias: the mailbox Dovecot saved into, not the alias",
			`2026-11-26 11:14:49 1xWVYx-0000000Beim-2TXw -> info (info@example.net) <info@example.net> R=virtual_user T=dovecot_virtual_delivery C="250 2.0.0 <info@example.com> FuYVKIn4B2sXdyoAyQsudw:R2 Saved"`,
			Event{Kind: InboundLocal, ID: "1xWVYx-0000000Beim-2TXw", Addr: "info@example.com"},
		},
		{
			"=> into a cPanel account's own mailbox (dovecot_delivery)",
			`2026-11-27 15:46:06 1xWwH9-0000000Bozv-3LAS => acct <acct@host.example.gr> R=localuser T=dovecot_delivery C="250 2.0.0 <acct@host.example.gr> wv45KJ6JCWuk/ioAL3MpMA Saved"`,
			Event{Kind: InboundLocal, ID: "1xWwH9-0000000Bozv-3LAS", Addr: "acct@host.example.gr"},
		},
		{
			"an upper-case mailbox is lowercased",
			`2026-11-26 10:51:36 1xWVCU-00000004ev7-10PX => info <INFO@EXAMPLE.GR> R=virtual_user T=dovecot_virtual_delivery C="250 2.0.0 <INFO@EXAMPLE.GR> OM3OLBjzB2s3CBEAO5TXtA Saved"`,
			Event{Kind: InboundLocal, ID: "1xWVCU-00000004ev7-10PX", Addr: "info@example.gr"},
		},
		{
			"a remote delivery is not Received",
			`2026-11-27 16:00:00 1xWwaa-0000000Caaa-0aaa => someone@gmail.com R=dkim_lookuphost T=dkim_remote_smtp H=gmail-smtp-in.l.google.com [142.250.1.27] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes C="250 2.0.0 OK 1764252000 abc.1 - gsmtp"`,
			Event{},
		},
		{
			"an autoresponder pipe is not Received",
			`2026-11-27 16:14:16 1xWwiL-0000000CvF7-3X93 => |/usr/local/cpanel/bin/autorespond sales@example.eu /home2/acct/.autorespond (sales@example.eu) <sales@example.eu> R=virtual_aliases_nostar T=cagefs_virtual_address_pipe`,
			Event{},
		},
		{
			"a filter-to-folder delivery is not counted",
			`2026-11-27 14:38:32 1xWvDf-000000094b8-0Rze => /home2/acct/mail/example.eu/user/ <user@example.eu> R=virtual_user_filter T=address_directory`,
			Event{},
		},

		// ---- Over quota ----
		{
			"** LMTP 552 after RCPT on a domain mailbox",
			`2026-11-27 12:00:00 1xWvAA-0000000AAAA-1AAA ** info@example.gr R=virtual_user T=dovecot_virtual_delivery: LMTP error after RCPT TO:<info@example.gr>: 552 5.2.2 <info@example.gr> Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{Kind: OverQuota, Addr: "info@example.gr"},
		},
		{
			"** LMTP 552 after end of data on an account mailbox",
			`2026-11-27 12:00:01 1xWvAB-0000000AAAB-1AAB ** acct@host.example.gr R=localuser T=dovecot_delivery: LMTP error after end of data: 552 5.2.2 <acct@host.example.gr> Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{Kind: OverQuota, Addr: "acct@host.example.gr"},
		},
		{
			"** over quota on the +spam folder counts for the mailbox",
			`2026-11-26 13:52:42 1xWY1n-0000000A93f-08It ** info+spam@example.gr (info@example.gr) <info@example.gr> R=virtual_user T=dovecot_virtual_delivery : LMTP error after RCPT TO:<info+spam@example.gr>: 552 5.2.2 <info+spam@example.gr> Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{Kind: OverQuota, Addr: "info@example.gr"},
		},
		{
			"== 452 over quota is a defer (retried): not counted",
			`2026-11-27 12:00:02 1xWvAC-0000000AAAC-1AAC == info@example.gr R=virtual_user T=dovecot_virtual_delivery defer (-44): LMTP error after RCPT TO:<info@example.gr>: 452 4.2.2 <info@example.gr> Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{},
		},
		{
			"SMTP-time RCPT reject for a full local mailbox",
			`2026-11-27 15:08:42 H=mail-wm1-f50.google.com [209.85.128.50]:48520 X=TLS1.3:TLS_AES_128_GCM_SHA256:128:x25519 F=<someone@gmail.com> rejected RCPT <Info@Example.gr>: Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{Kind: OverQuota, Addr: "info@example.gr"},
		},
		{
			"an authenticated local sender hitting a full local mailbox: still over quota",
			`2026-11-27 12:00:03 H=(pc) [10.0.0.1]:51952 X=TLS1.3:TLS_AES_256_GCM_SHA384:256:x25519 F=<a@example.gr> A=dovecot_plain:a@example.gr rejected RCPT <b@example.gr>: Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{Kind: OverQuota, Addr: "b@example.gr"},
		},
		{
			"a REMOTE mailbox full (gmail) is the recipient's problem, not ours",
			`2026-11-27 12:00:04 1xWvAD-0000000AAAD-1AAD ** x@gmail.com R=dkim_lookuphost T=dkim_remote_smtp H=gmail-smtp-in.l.google.com [142.250.1.27] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes: SMTP error from remote mail server after RCPT TO:<x@gmail.com>: 552-5.2.2 The recipient's inbox is out of storage space.`,
			Event{},
		},

		// ---- Rate-limited: cPanel's per-domain hourly limits ----
		{
			"max defers and failures per hour, discarded",
			`2026-11-27 15:59:49 1xWwUR-0000000CMKj-0Cd0 ** a@yahoo.com (all@Example.gr, all@example.gr) <info@example.gr> R=enforce_mail_permissions : Domain Example.gr has exceeded the max defers and failures per hour (50/50 (100%)) allowed. Message discarded.`,
			Event{Kind: Throttled, Addr: "*@example.gr"},
		},
		{
			"max emails per hour, discarded",
			`2026-11-25 03:56:44 1xW2FV-0000000Dnbe-3gxC ** b@gmail.com (info@example.gr) <info@example.gr> R=enforce_mail_permissions : Domain example.gr has exceeded the max emails per hour (125/100 (125%)) allowed.  Message discarded.`,
			Event{Kind: Throttled, Addr: "*@example.gr"},
		},
		{
			"max emails per hour, deferred (retried): not counted",
			`2026-11-25 03:56:43 1xW2FU-0000000DnXe-0rHc == c@yahoo.gr (info@example.gr) <info@example.gr> R=enforce_mail_permissions defer: "Domain example.gr has exceeded the max emails per hour (124/100 (124%)) allowed.  Message will be reattempted later"`,
			Event{},
		},
		{
			"an outgoing mail hold is an operator hold, not a rate limit",
			`2026-11-27 12:00:05 1xWvAE-0000000AAAE-1AAE == d@gmail.com R=enforce_mail_permissions defer: "Sender wordpress@example.gr has an outgoing mail hold.  Message will be reattempted later"`,
			Event{},
		},

		// ---- Rejected: inbound, permanent, unauthenticated ----
		{
			"no such user",
			`2026-11-27 16:14:12 H=mail-ej1-f52.google.com [209.85.218.52]:55766 X=TLS1.3:TLS_AES_128_GCM_SHA256:128:x25519 F=<someone@gmail.com> rejected RCPT <nobody@example.gr>: No Such User Here`,
			Event{Kind: Rejected},
		},
		{
			"relay attempt",
			`2026-11-27 16:12:45 H=(mail.spam.example) [172.98.14.149]:58948 F=<x@spam.example> rejected RCPT <valid@victim.example>: Rejected relay attempt: '172.98.14.149' From: 'x@spam.example' To: 'valid@victim.example'`,
			Event{Kind: Rejected},
		},
		{
			"spam rejected after DATA",
			`2026-11-27 16:06:32 1xWwat-00000005ask-2beK H=spam.example [135.125.225.103]:42705 X=TLS1.2:ECDHE-RSA-AES256-GCM-SHA384:256 F=<a@spam.example> rejected after DATA: "The mail server detected your message as spam and has prevented delivery (300)."`,
			Event{Kind: Rejected},
		},
		{
			"a null-sender spam rejected after DATA (the line carries a message-id, no flag)",
			`2026-11-26 10:57:48 1xWVIZ-00000004qhp-2uM9 H=219.88.158.34.bc.googleusercontent.com ([10.88.0.3]) [34.158.88.219]:47682 F=<> rejected after DATA: "The mail server detected your message as spam and has prevented delivery (300)."`,
			Event{Kind: Rejected},
		},
		{
			"cPanel's OUTGOING spam verdict is our own mail: not an inbound reject",
			`2026-11-27 12:00:06 1xWvAF-0000000AAAF-1AAF H=(localhost) [10.0.0.2]:60620 F=<shop@example.gr> rejected after DATA: "SpamAssassin as acct detected OUTGOING smtp message as spam (12.0/10)"`,
			Event{},
		},
		{
			"an AUTHENTICATED RCPT reject is our user's mail to a bad address",
			`2026-11-27 16:16:14 H=(example.gr) [10.0.0.3]:51196 X=TLS1.3:TLS_AES_256_GCM_SHA384:256:x25519 F=<info@example.gr> A=dovecot_login:info@example.gr rejected RCPT <someone@gmail.cim>: The mail server could not deliver mail to someone@gmail.cim.  The account or domain may not exist, they may be blacklisted, or missing the proper dns entries.`,
			Event{},
		},
		{
			"a temporary (4xx) reject is not a reject",
			`2026-11-27 14:59:45 H=ec2.example [32.198.5.54]:40032 X=TLS1.3:TLS_AES_256_GCM_SHA384:256 F=<sales@remote.example> temporarily rejected RCPT <info@example.gr>: host lookup did not complete`,
			Event{},
		},
		{
			"the connect ACL's host rate limit (temporary) is not a reject",
			`2026-11-27 12:00:07 H=(helo) [1.2.3.4]:1234 temporarily rejected connection in "connect" ACL: "Host is ratelimited (1.4/1h max:1.2)"`,
			Event{},
		},
		{
			"a remote server's text containing 'rejected RCPT' on a ** line is not our reject",
			`2026-11-27 12:00:08 1xWvAG-0000000AAAG-1AAG ** x@remote.example R=dkim_lookuphost T=dkim_remote_smtp H=mx.remote.example [192.0.2.1]: SMTP error from remote mail server after RCPT TO:<x@remote.example>: 550 rejected RCPT <x@remote.example>: no such user`,
			Event{},
		},

		// ---- text the remote side chose (sender, HELO, echoed addresses) ----
		{
			"quota words in the forged sender, echoed by a relay reject: a reject, not over quota",
			`2026-11-27 12:00:09 H=(x) [192.0.2.5]:5 F=<"over quota"@evil.example> rejected RCPT <a@remote.example>: Rejected relay attempt: '192.0.2.5' From: '"over quota"@evil.example' To: 'a@remote.example'`,
			Event{Kind: Rejected},
		},
		{
			"a forged reject inside the sender cannot write an over-quota row for a tenant",
			`2026-11-27 12:00:10 H=(x) [192.0.2.5]:5 F=<"rejected RCPT <victim@tenant.example>: Mailbox is full"@evil.example> rejected RCPT <nobody@tenant.example>: No Such User Here`,
			Event{},
		},
		{
			"a forged A= inside the sender does not make the reject look authenticated",
			`2026-11-27 12:00:11 H=(x) [192.0.2.5]:5 F=<"a A=b:c"@evil.example> rejected RCPT <nobody@tenant.example>: No Such User Here`,
			Event{Kind: Rejected},
		},
		{
			"an over-quota reject for a quoted local part is not attributed",
			`2026-11-27 12:00:12 H=(x) [192.0.2.5]:5 F=<a@remote.example> rejected RCPT <"x y"@example.gr>: Mailbox is full / Blocks limit exceeded / Inode limit exceeded`,
			Event{},
		},
		{
			"=> into a mailbox with no C= falls back to the recipient before R=",
			`2026-11-27 12:00:13 1xWvAH-0000000AAAH-1AAH => info <Info@Example.gr> R=virtual_user T=dovecot_virtual_delivery`,
			Event{Kind: InboundLocal, ID: "1xWvAH-0000000AAAH-1AAH", Addr: "info@example.gr"},
		},
	}
	for _, c := range cases {
		if got := ParseEximLine(c.line); got != c.want {
			t.Errorf("%s:\n  ParseEximLine(%.90q…)\n  got  %+v\n  want %+v", c.name, c.line, got, c.want)
		}
	}
}

func TestEximMsgID(t *testing.T) {
	cases := []struct{ line, want string }{
		{`2026-08-07 12:00:01 1uKq9r-0002Ab-7H <= a@b P=esmtpa A=x:a@b`, "1uKq9r-0002Ab-7H"},
		{`2026-08-07 12:00:07 [12345] 1uKq9w-0002Ag-2N <= a@b P=esmtpa A=x:a@b`, "1uKq9w-0002Ag-2N"},
		{`no arrow here`, ""},
	}
	for _, c := range cases {
		if got := eximMsgID(c.line); got != c.want {
			t.Errorf("eximMsgID(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}
