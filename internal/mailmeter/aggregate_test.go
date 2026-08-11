package mailmeter

import (
	"reflect"
	"testing"
)

// TestAggregatePostfixCorrelation walks a real Postfix send sequence end to end:
// the sender is recorded on the submission line, resolved on the relay line, and
// the QID is freed by qmgr.
func TestAggregatePostfixCorrelation(t *testing.T) {
	lines := []string{
		`Jul 23 22:24:24 ngm postfix/submission/smtpd[189625]: 325D61FBCED: client=ngm.myip.gr[84.54.49.38], sasl_method=PLAIN, sasl_username=test@nac.gr`,
		`Jul 23 22:24:30 ngm postfix/smtp[189657]: 325D61FBCED: to=<chris@myip.gr>, relay=mymail.myip.gr[84.54.49.25]:25, delay=6.1, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as BA120621D63)`,
		`Jul 23 22:24:30 ngm postfix/qmgr[189153]: 325D61FBCED: removed`,
	}
	var evs []Event
	for _, ln := range lines {
		evs = append(evs, ParseMaillogLine(ln))
	}
	r := Aggregate(evs)
	if r.OutboundTotal != 1 || r.OutboundBySender["test@nac.gr"] != 1 {
		t.Fatalf("postfix outbound not correlated: total=%d bysender=%v", r.OutboundTotal, r.OutboundBySender)
	}
}

// An OutboundSent whose QID was never introduced (submission line rotated away)
// must not be miscounted under an empty address.
func TestAggregateOrphanOutbound(t *testing.T) {
	r := Aggregate([]Event{{Kind: OutboundSent, ID: "GONEQID"}})
	if r.OutboundTotal != 0 || len(r.OutboundBySender) != 0 {
		t.Fatalf("orphan outbound leaked: total=%d bysender=%v", r.OutboundTotal, r.OutboundBySender)
	}
}

// Exim's authenticated `<=` carries its own Addr, so it counts with no
// correlation line — and both MTAs fold into one Report.
func TestAggregateEximAndMixed(t *testing.T) {
	evs := []Event{
		ParseEximLine(`2026-08-07 12:00:01 1a-b-c <= support@ordermusic.gr H=(h) [10.0.0.5]:5 P=esmtpa A=dovecot_login:support@ordermusic.gr S=1`),
		ParseEximLine(`2026-08-07 12:00:02 1a-b-d <= support@ordermusic.gr H=(h) [10.0.0.5]:5 P=esmtpa A=dovecot_login:support@ordermusic.gr S=1`),
		ParseMaillogLine(`Jul 23 13:46:09 ngm postfix/submission/smtpd[1]: Q1: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=test@nac.gr`),
		ParseMaillogLine(`Jul 23 13:46:16 ngm postfix/smtp[1]: Q1: to=<x@y>, status=sent (250 ok)`),
		ParseMaillogLine(`Aug  2 21:00:00 ngm dovecot[9]: imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<victim@nac.gr>, rip=203.0.113.9`),
	}
	r := Aggregate(evs)
	if r.OutboundBySender["support@ordermusic.gr"] != 2 {
		t.Fatalf("exim self-carried outbound miscounted: %v", r.OutboundBySender)
	}
	if r.OutboundBySender["test@nac.gr"] != 1 {
		t.Fatalf("postfix outbound not correlated in mixed batch: %v", r.OutboundBySender)
	}
	if r.OutboundTotal != 3 {
		t.Fatalf("OutboundTotal = %d, want 3", r.OutboundTotal)
	}
	if r.AuthFailByMailbox["victim@nac.gr"] != 1 {
		t.Fatalf("dovecot auth-fail not counted: %v", r.AuthFailByMailbox)
	}
}

// A password spray with distinct attacker-chosen non-mailbox usernames must
// fold into the host-wide bucket, not spawn a row per guess. A real mailbox
// (has "@") keeps its own row.
func TestAggregateAuthFailFoldsJunk(t *testing.T) {
	evs := []Event{
		{Kind: AuthFailed, Addr: "victim@nac.gr"},
		{Kind: AuthFailed, Addr: "victim@nac.gr"},
		{Kind: AuthFailed, Addr: "admin"},  // bare login guess → host-wide
		{Kind: AuthFailed, Addr: "x8f3zz"}, // random guess → host-wide
		{Kind: AuthFailed, Addr: ""},       // already host-wide
	}
	r := Aggregate(evs)
	if r.AuthFailByMailbox["victim@nac.gr"] != 2 {
		t.Fatalf("real mailbox miscounted: %v", r.AuthFailByMailbox)
	}
	if r.AuthFailByMailbox[HostWide] != 3 {
		t.Fatalf("junk/empty usernames not folded host-wide: %v", r.AuthFailByMailbox)
	}
	if _, ok := r.AuthFailByMailbox["admin"]; ok {
		t.Fatalf("non-mailbox guess leaked its own row: %v", r.AuthFailByMailbox)
	}
}

// Exim local sendmail (PHP/cron) submissions tally per unix user, separate from
// the SMTP-authenticated senders.
func TestAggregateLocalSubmit(t *testing.T) {
	evs := []Event{
		ParseEximLine(`2026-08-07 12:00:01 1a-b-c <= x@y U=evafeiadis P=local S=1`),
		ParseEximLine(`2026-08-07 12:00:02 1a-b-d <= x@y U=evafeiadis P=local S=1`),
		ParseEximLine(`2026-08-07 12:00:03 1a-b-e <= s@d H=(h) [10.0.0.5]:5 P=esmtpa A=dovecot_login:s@d S=1`),
	}
	r := Aggregate(evs)
	if r.LocalSubmitByUser["evafeiadis"] != 2 || r.LocalSubmitTotal != 2 {
		t.Fatalf("local submit miscounted: byuser=%v total=%d", r.LocalSubmitByUser, r.LocalSubmitTotal)
	}
	if r.OutboundBySender["s@d"] != 1 || r.OutboundTotal != 1 {
		t.Fatalf("SMTP sender should not mix with local submitters: %v", r.OutboundBySender)
	}
}

// A streaming collector feeds one Correlator across many polls: an AuthSender
// seen in an early poll must still resolve an OutboundSent seen in a later poll,
// even though each poll uses a fresh Report for its deltas.
func TestCorrelatorAcrossPolls(t *testing.T) {
	c := NewCorrelator()

	// Poll 1: only the submission line (records the sender for QID Q9).
	p1 := NewReport()
	c.Feed(ParseMaillogLine(`Jul 23 13:46:09 ngm postfix/submission/smtpd[1]: Q9: client=localhost[127.0.0.1], sasl_method=PLAIN, sasl_username=late@nac.gr`), &p1)
	if p1.OutboundTotal != 0 {
		t.Fatalf("poll 1 should have no completed send yet: %+v", p1.OutboundBySender)
	}

	// Poll 2 (later): the relay status=sent line resolves against the carried QID.
	p2 := NewReport()
	c.Feed(ParseMaillogLine(`Jul 23 13:46:16 ngm postfix/smtp[1]: Q9: to=<x@y>, status=sent (250 ok)`), &p2)
	if p2.OutboundBySender["late@nac.gr"] != 1 || p2.OutboundTotal != 1 {
		t.Fatalf("cross-poll correlation lost: %+v", p2.OutboundBySender)
	}
}

func TestTopNDeterministicOrder(t *testing.T) {
	m := map[string]int{"a@x": 5, "b@x": 5, "c@x": 9, "d@x": 1}
	got := TopN(m, 3)
	want := []AddrCount{{"c@x", 9}, {"a@x", 5}, {"b@x", 5}} // count desc, addr asc tiebreak
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TopN order = %v, want %v", got, want)
	}
	// n<=0 returns everything, still sorted.
	if all := TopN(m, 0); len(all) != 4 || all[len(all)-1].Addr != "d@x" {
		t.Fatalf("TopN(0) = %v", all)
	}
	// empty map → empty slice, never nil-panic on range.
	if e := TopN(map[string]int{}, 5); len(e) != 0 {
		t.Fatalf("TopN(empty) = %v", e)
	}
}
