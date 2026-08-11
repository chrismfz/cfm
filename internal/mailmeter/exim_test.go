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
			"local submission (cron/PHP, P=local) is not attributed to a mailbox in 1a",
			`2026-08-07 12:00:04 1uKq9u-0002Ae-0L <= root@server.example U=root P=local S=512`,
			Event{Kind: None},
		},
		{
			"a delivery (=>) line is not an arrival — deferred to the collector stage",
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
