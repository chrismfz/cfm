package mailtraffic

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"cfm/internal/mailqueue"
)

func eximArrival(ts, id, user, rcpt string) string {
	return fmt.Sprintf("%s %s <= %s@titan.example U=%s P=local S=900 T=\"Offer\" for %s", ts, id, user, user, rcpt)
}

func eximBounce(ts, id, rcpt string) string {
	return fmt.Sprintf("%s %s ** %s R=dkim_lookuphost T=dkim_remote_smtp H=gmail-smtp-in.l.google.com [142.250.1.1] X=TLS: SMTP error from remote mail server after RCPT TO:<%s>: 550-5.1.1 The email account that you tried to reach does not exist.", ts, id, rcpt, rcpt)
}

func eximDelivered(ts, id, rcpt string) string {
	return fmt.Sprintf("%s %s => %s R=dkim_lookuphost T=dkim_remote_smtp H=mta5.am0.yahoodns.net [67.195.1.1] X=TLS C=\"250 ok dirdel\"", ts, id, rcpt)
}

// A form writing to made-up addresses: most of its mail bounces. A normal
// sender with a couple of stale addresses does not.
func TestBounceSpikePerSender(t *testing.T) {
	T := time.Unix(1_700_000_000, 0)
	ts := T.Add(-20 * time.Minute).Format("2006-01-02 15:04:05")
	tr := newTracker()
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("1tXyZa-%06d-AB", i)
		rcpt := fmt.Sprintf("x%d@gmail.com", i)
		tr.observeExim(eximArrival(ts, id, "hotellito", rcpt), T)
		if i < 25 {
			tr.observeExim(eximBounce(ts, id, rcpt), T)
		} else {
			tr.observeExim(eximDelivered(ts, id, rcpt), T)
		}
		id2 := fmt.Sprintf("1tXyZb-%06d-AB", i)
		tr.observeExim(eximArrival(ts, id2, "shop", rcpt), T)
		if i < 2 {
			tr.observeExim(eximBounce(ts, id2, rcpt), T)
		} else {
			tr.observeExim(eximDelivered(ts, id2, rcpt), T)
		}
	}
	fs, _, ok := tr.evaluate(openTemp(t), T)
	if !ok || len(fs) != 1 {
		t.Fatalf("want one bounce finding: %+v", fs)
	}
	f := fs[0]
	if f.Type != TypeBounceSpike || f.Key != "mail:bounce:local:hotellito" || f.Severity != "warning" ||
		!strings.Contains(f.Message, "25 of 30 deliveries bounced") || !strings.Contains(f.Message, "mostly no-such-user") {
		t.Fatalf("bad bounce finding: %+v", f)
	}
	// a fading wave stays open on the lower threshold, then closes
	open := map[string]bool{"mail:bounce:local:hotellito": true}
	tr2 := newTracker()
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("1tXyZc-%06d-AB", i)
		tr2.observeExim(eximArrival(ts, id, "hotellito", "a@b.c"), T)
		if i < 12 {
			tr2.observeExim(eximBounce(ts, id, "a@b.c"), T)
		} else {
			tr2.observeExim(eximDelivered(ts, id, "a@b.c"), T)
		}
	}
	if fs, _, _, _ := tr2.evaluateWith(openTemp(t), T, open, nil); len(fs) != 1 {
		t.Fatalf("12 bounces keep an open finding open: %+v", fs)
	}
	if fs, _, _, _ := tr2.evaluateWith(openTemp(t), T, nil, nil); len(fs) != 0 {
		t.Fatalf("12 bounces do not open one: %+v", fs)
	}
	if fs, _, _ := tr2.evaluate(openTemp(t), T.Add(3*time.Hour)); len(fs) != 0 {
		t.Fatalf("old outcomes age out: %+v", fs)
	}
}

func TestPostfixBouncesAreAttributedToTheMailbox(t *testing.T) {
	tr := newTracker()
	T := time.Now()
	for i := 0; i < 25; i++ {
		qid := fmt.Sprintf("4AB%04X", i)
		tr.observeMaillog("Oct  8 10:00:00 mx postfix/submission/smtpd[1]: "+qid+": client=unknown[5.6.7.8], sasl_method=PLAIN, sasl_username=info@shop.gr", T)
		tr.observeMaillog("Oct  8 10:00:01 mx postfix/smtp[2]: "+qid+": to=<x@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.1.1]:25, delay=1, dsn=5.1.1, status=bounced (host said: 550 5.1.1 user unknown)", T)
	}
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if len(fs) != 1 || fs[0].Key != "mail:bounce:auth:info@shop.gr" {
		t.Fatalf("want the mailbox's bounces: %+v", fs)
	}
}

// IMAP/POP3 logins (dovecot) count towards a hijack like SMTP AUTH; webmail
// (loopback) does not.
func TestDovecotLoginsCountForHijack(t *testing.T) {
	orig := geoOf
	geoOf = func(ip string) (string, uint) {
		return map[string]string{"1.1.1.1": "GR", "2.2.2.2": "VN", "3.3.3.3": "BR"}[ip], 0
	}
	t.Cleanup(func() { geoOf = orig })
	tr := newTracker()
	T := time.Now()
	for _, l := range []string{
		"Oct  8 10:00:00 titan dovecot[1]: imap-login: Login: user=<info@shop.gr>, method=PLAIN, rip=1.1.1.1, lip=9.9.9.9, mpid=1, TLS, session=<a>",
		"Oct  8 10:00:01 titan dovecot[1]: pop3-login: Login: user=<info@shop.gr>, method=PLAIN, rip=2.2.2.2, lip=9.9.9.9, mpid=2, TLS, session=<b>",
		"Oct  8 10:00:02 titan dovecot[1]: imap-login: Logged in: user=<info@shop.gr>, method=PLAIN, rip=3.3.3.3, lip=9.9.9.9, mpid=3, TLS, session=<c>",
		"Oct  8 10:00:03 titan dovecot[1]: imap-login: Login: user=<me@shop.gr>, method=PLAIN, rip=127.0.0.1, lip=127.0.0.1, mpid=4, secured, session=<d>",
		"Oct  8 10:00:04 titan dovecot[1]: imap-login: Login: user=<me@shop.gr>, method=PLAIN, rip=::1, lip=::1, mpid=5, secured, session=<e>",
		"Oct  8 10:00:05 titan dovecot[1]: imap-login: Login: user=<me@shop.gr>, method=PLAIN, rip=1.1.1.1, lip=9.9.9.9, mpid=6, TLS, session=<f>",
	} {
		tr.observeMaillog(l, T)
	}
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if len(fs) != 1 || fs[0].Key != "mail:hijack:info@shop.gr" || !strings.Contains(fs[0].Message, "logged in (imap/pop3) from 3 IPs in 3 countries") {
		t.Fatalf("want one IMAP/POP3 hijack: %+v", fs)
	}
}

// Gmail fetching a mailbox over POP3 logs in from dozens of Google addresses;
// with the owner's phone in another country that is still not a hijack.
func TestMailProviderFetchingIsOneSource(t *testing.T) {
	orig := geoOf
	geoOf = func(ip string) (string, uint) {
		if strings.HasPrefix(ip, "209.85.") {
			return "US", 15169
		}
		return "GR", 6799
	}
	t.Cleanup(func() { geoOf = orig })
	tr := newTracker()
	T := time.Now()
	for i := 0; i < 30; i++ {
		tr.observeMaillog(fmt.Sprintf("Oct  8 10:00:00 titan dovecot[1]: pop3-login: Login: user=<info@shop.gr>, method=PLAIN, rip=209.85.220.%d, lip=9.9.9.9, mpid=1, TLS, session=<a>", i), T)
	}
	for i := 0; i < 12; i++ {
		tr.observeMaillog(fmt.Sprintf("Oct  8 10:00:00 titan dovecot[1]: imap-login: Login: user=<info@shop.gr>, method=PLAIN, rip=62.1.1.%d, lip=9.9.9.9, mpid=1, TLS, session=<a>", i), T)
	}
	if fs, _, _ := tr.evaluate(openTemp(t), T); len(fs) != 0 {
		t.Fatalf("a provider fetching mail is not a hijack: %+v", fs)
	}
}

func stubQueue(t *testing.T, rep mailqueue.Report, ok bool) {
	t.Helper()
	orig := queueReport
	queueReport = func() (mailqueue.Report, bool) { return rep, ok }
	t.Cleanup(func() { queueReport = orig })
}

func TestQueueHog(t *testing.T) {
	T := time.Now()
	rep := mailqueue.Report{MeasuredAt: T, Total: 950, Parsed: 950, TopSenders: []mailqueue.SenderQueueStat{
		{Sender: "webhostingcosmoteam@gmail.com", Total: 812, Frozen: 300, Deferred: 400},
		{Sender: "info@shop.gr", Total: 60},
	}}
	// a campaign going out fine: most of the queue, nothing stuck
	stubQueue(t, mailqueue.Report{MeasuredAt: T, Total: 950, Parsed: 950, TopSenders: []mailqueue.SenderQueueStat{{Sender: "news@shop.gr", Total: 900, Deferred: 10}}}, true)
	if fs, _, _ := newTracker().evaluate(openTemp(t), T); len(fs) != 0 {
		t.Fatalf("a campaign in flight is not a hog: %+v", fs)
	}
	stubQueue(t, rep, true)
	tr := newTracker()
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if len(fs) != 1 || fs[0].Type != TypeQueueHog || fs[0].Key != "mail:queue:webhostingcosmoteam@gmail.com" ||
		fs[0].Severity != "warning" || !strings.Contains(fs[0].Message, "812 of 950 queued messages (85%), 300 frozen, 400 stuck over 1h") {
		t.Fatalf("want one queue hog: %+v", fs)
	}

	// draining: 60 of 150 (40%) keeps it open, would not open it
	stubQueue(t, mailqueue.Report{MeasuredAt: T, Total: 150, Parsed: 150, TopSenders: []mailqueue.SenderQueueStat{{Sender: "webhostingcosmoteam@gmail.com", Total: 60}}}, true)
	open := map[string]bool{"mail:queue:webhostingcosmoteam@gmail.com": true}
	if fs, _, _, _ := tr.evaluateWith(openTemp(t), T, open, nil); len(fs) != 1 {
		t.Fatalf("a draining hog stays open: %+v", fs)
	}
	if fs, _, _, _ := tr.evaluateWith(openTemp(t), T, nil, nil); len(fs) != 0 {
		t.Fatalf("60 of 150 does not open one: %+v", fs)
	}

	// no fresh reading: the open finding is held, not resolved
	stubQueue(t, mailqueue.Report{MeasuredAt: T.Add(-time.Hour)}, true)
	fs, _, held, _ := tr.evaluateWith(openTemp(t), T, open, nil)
	if len(fs) != 0 || !held["mail:queue:webhostingcosmoteam@gmail.com"] {
		t.Fatalf("a stale queue reading must hold the finding: %+v %v", fs, held)
	}
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func stubRBL(t *testing.T, ips []string, answers map[string][]string, fail map[string]bool) {
	t.Helper()
	oi, ol := rblIPs, rblLookup
	rblIPs = func() []string { return ips }
	rblLookup = func(_ context.Context, name string) ([]string, error) {
		name = strings.TrimSuffix(name, ".")
		if fail[name] {
			return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
		}
		if a, ok := answers[name]; ok {
			return a, nil
		}
		return nil, notFound(name)
	}
	t.Cleanup(func() { rblIPs, rblLookup = oi, ol })
}

func TestRBLListing(t *testing.T) {
	T := time.Now()
	stubRBL(t, []string{"84.54.49.4", "84.54.49.5", "84.54.49.6"}, map[string][]string{
		"4.49.54.84.zen.spamhaus.org":       {"127.0.0.2"},
		"5.49.54.84.bl.spamcop.net":         {"127.0.0.2"},
		"6.49.54.84.zen.spamhaus.org":       {"127.255.255.254"}, // public resolver refused
		"5.49.54.84.psbl.surriel.com":       nil,
		"4.49.54.84.b.barracudacentral.org": {"127.0.0.2"},
	}, nil)
	r := &rblChecker{}
	r.check(context.Background(), T)
	open := map[string]bool{"mail:rbl:84.54.49.6": true}
	fs, _, held, _ := newTracker().evaluateWith(openTemp(t), T, open, r)
	if len(fs) != 2 {
		t.Fatalf("want two listed IPs: %+v", fs)
	}
	if fs[0].Key != "mail:rbl:84.54.49.4" || fs[0].Severity != "critical" ||
		!strings.Contains(fs[0].Message, "b.barracudacentral.org, zen.spamhaus.org (SBL)") {
		t.Fatalf("bad SBL finding: %+v", fs[0])
	}
	if fs[1].Key != "mail:rbl:84.54.49.5" || fs[1].Severity != "warning" || !strings.Contains(fs[1].Message, "bl.spamcop.net") {
		t.Fatalf("bad SpamCop finding: %+v", fs[1])
	}
	if len(held) != 0 {
		t.Fatalf("a list refusing the resolver holds nothing (it never listed 84.54.49.6): %v", held)
	}

	// delisted: a clean answer closes it
	stubRBL(t, []string{"84.54.49.4"}, nil, nil)
	r.check(context.Background(), T)
	if fs, _, held, _ := newTracker().evaluateWith(openTemp(t), T, map[string]bool{"mail:rbl:84.54.49.4": true}, r); len(fs) != 0 || len(held) != 0 {
		t.Fatalf("a delisted IP is over: %+v %v", fs, held)
	}

	// a timeout after a clean answer does not list it again
	stubRBL(t, []string{"84.54.49.4"}, nil, map[string]bool{"4.49.54.84.zen.spamhaus.org": true})
	r.check(context.Background(), T)
	if fs, _, _, _ := newTracker().evaluateWith(openTemp(t), T, nil, r); len(fs) != 0 {
		t.Fatalf("a timeout keeps the last (clean) verdict: %+v", fs)
	}
}

func TestHeldFindingsAreNotResolved(t *testing.T) {
	got := recordAbuse(t)
	p := &publisher{}
	T := time.Now()
	f := []abuseFinding{{Type: TypeRBLListed, Severity: "warning", Key: "mail:rbl:1.2.3.4", Message: "1.2.3.4 is on bl.spamcop.net"}}
	p.apply(f, nil, T)
	p.applyHeld(nil, nil, map[string]bool{"mail:rbl:1.2.3.4": true}, T)
	if len(*got) != 1 {
		t.Fatalf("a held finding must not resolve: %+v", *got)
	}
	p.applyHeld(nil, nil, nil, T)
	if len(*got) != 2 || (*got)[1].typ != TypeRecovered || !strings.HasPrefix((*got)[1].msg, "no longer listed") {
		t.Fatalf("want the delisting: %+v", *got)
	}
}

// A phone rotating IPv6 privacy addresses plus a laptop on a VPN: many
// addresses, two places. Proxies in a second country: a hijack.
func TestManySourcesNeedSeveralAbroad(t *testing.T) {
	orig := geoOf
	geoOf = func(ip string) (string, uint) {
		if strings.HasPrefix(ip, "185.") {
			return "NL", 1
		}
		if strings.HasPrefix(ip, "45.") {
			return "VN", 2
		}
		return "GR", 3
	}
	t.Cleanup(func() { geoOf = orig })
	login := func(tr *tracker, user, ip string) {
		tr.observeMaillog("Oct  8 10:00:00 titan dovecot[1]: imap-login: Logged in: user=<"+user+">, method=PLAIN, rip="+ip+", lip=9.9.9.9, mpid=1, TLS, session=<a>", time.Now())
	}
	tr := newTracker()
	for i := 0; i < 15; i++ {
		login(tr, "me@shop.gr", fmt.Sprintf("2a02:587:1234:5678::%x", i+1)) // one /64
		login(tr, "me@shop.gr", fmt.Sprintf("62.1.1.%d", i))                // home + mobile, GR
	}
	login(tr, "me@shop.gr", "185.1.1.1") // the VPN
	login(tr, "me@shop.gr", "185.1.1.2")
	for i := 0; i < 8; i++ {
		login(tr, "info@shop.gr", fmt.Sprintf("62.1.2.%d", i))
		login(tr, "info@shop.gr", fmt.Sprintf("45.1.1.%d", i))
	}
	fs, _, _ := tr.evaluate(openTemp(t), time.Now())
	if len(fs) != 1 || fs[0].Key != "mail:hijack:info@shop.gr" {
		t.Fatalf("want only the proxies abroad: %+v", fs)
	}
}

// Review findings (PR #1557): each one a scenario that used to page wrongly.

// A list that refuses this resolver (Spamhaus behind a public resolver) or does
// not answer must not keep a delisted address open forever.
func TestRBLDelistingWithARefusingList(t *testing.T) {
	T := time.Now()
	stubRBL(t, []string{"84.54.49.5"}, map[string][]string{
		"5.49.54.84.zen.spamhaus.org": {"127.255.255.254"},
		"5.49.54.84.bl.spamcop.net":   {"127.0.0.2"},
	}, map[string]bool{"5.49.54.84.b.barracudacentral.org": true})
	r := &rblChecker{}
	r.check(context.Background(), T)
	fs, _, _, _ := newTracker().evaluateWith(openTemp(t), T, nil, r)
	if len(fs) != 1 || fs[0].Severity != "warning" {
		t.Fatalf("want the SpamCop listing: %+v", fs)
	}
	// SpamCop delists; Spamhaus still refuses, Barracuda still times out
	stubRBL(t, []string{"84.54.49.5"}, map[string][]string{"5.49.54.84.zen.spamhaus.org": {"127.255.255.254"}},
		map[string]bool{"5.49.54.84.b.barracudacentral.org": true})
	r.check(context.Background(), T)
	fs, _, held, _ := newTracker().evaluateWith(openTemp(t), T, map[string]bool{"mail:rbl:84.54.49.5": true}, r)
	if len(fs) != 0 || len(held) != 0 {
		t.Fatalf("delisted on SpamCop is over, whatever the other lists do: %+v %v", fs, held)
	}
	// a list that times out keeps its own last verdict
	stubRBL(t, []string{"84.54.49.5"}, map[string][]string{"5.49.54.84.bl.spamcop.net": {"127.0.0.2"}}, nil)
	r.check(context.Background(), T)
	stubRBL(t, []string{"84.54.49.5"}, nil, map[string]bool{"5.49.54.84.bl.spamcop.net": true})
	r.check(context.Background(), T)
	if fs, _, _, _ := newTracker().evaluateWith(openTemp(t), T, nil, r); len(fs) != 1 {
		t.Fatalf("a timeout must keep the listing: %+v", fs)
	}
}

// After a restart the bounce window is empty: an open finding is held until it
// has filled, not resolved and re-paged.
func TestBounceFindingSurvivesARestart(t *testing.T) {
	tr := newTracker()
	open := map[string]bool{"mail:bounce:local:hotellito": true}
	_, _, held, _ := tr.evaluateWith(openTemp(t), time.Now(), open, nil)
	if !held["mail:bounce:local:hotellito"] {
		t.Fatalf("a fresh tracker must hold open bounce findings: %v", held)
	}
	_, _, held, _ = tr.evaluateWith(openTemp(t), time.Now().Add(3*time.Hour), open, nil)
	if held["mail:bounce:local:hotellito"] {
		t.Fatalf("once the window has filled it is judged: %v", held)
	}
}

// A failed `exim -bp` (count fine, listing empty) holds an open hog.
func TestQueueListingFailureHolds(t *testing.T) {
	T := time.Now()
	open := map[string]bool{"mail:queue:spam@gmail.com": true}
	stubQueue(t, mailqueue.Report{MeasuredAt: T, Total: 900}, true)
	if _, _, held, _ := newTracker().evaluateWith(openTemp(t), T, open, nil); !held["mail:queue:spam@gmail.com"] {
		t.Fatalf("a failed listing must hold: %v", held)
	}
	// the detector switched off long ago: no longer held
	stubQueue(t, mailqueue.Report{MeasuredAt: T.Add(-2 * time.Hour), Total: 900, Parsed: 900}, true)
	if _, _, held, _ := newTracker().evaluateWith(openTemp(t), T, open, nil); held["mail:queue:spam@gmail.com"] {
		t.Fatalf("a reading hours old must not hold forever: %v", held)
	}
}

// A cron mailing a full local mailbox is not a bounce spike: local deliveries
// are not counted, so their failures are not either.
func TestLocalMailboxFailuresAreNotBounces(t *testing.T) {
	T := time.Unix(1_700_000_000, 0)
	ts := T.Add(-20 * time.Minute).Format("2006-01-02 15:04:05")
	tr := newTracker()
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("1tXyZd-%06d-AB", i)
		tr.observeExim(eximArrival(ts, id, "bob", "info@bob.gr"), T)
		tr.observeExim(ts+" "+id+" ** info@bob.gr R=virtual_user T=virtual_userdelivery: Mailbox quota exceeded", T)
	}
	if fs, _, _ := tr.evaluate(openTemp(t), T); len(fs) != 0 {
		t.Fatalf("local mailbox failures are not bounces: %+v", fs)
	}
	// a remote give-up with no transport still counts
	tr2 := newTracker()
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("1tXyZe-%06d-AB", i)
		tr2.observeExim(eximArrival(ts, id, "bob", "x@gmail.com"), T)
		tr2.observeExim(ts+" "+id+" ** x@gmail.com: retry timeout exceeded", T)
	}
	if fs, _, _ := tr2.evaluate(openTemp(t), T); len(fs) != 1 {
		t.Fatalf("a retry timeout is a bounce: %+v", fs)
	}
}

func TestMappedIPv4IsTheSameSource(t *testing.T) {
	orig := geoOf
	geoOf = func(string) (string, uint) { return "GR", 1 }
	t.Cleanup(func() { geoOf = orig })
	if a, _ := authSource("::ffff:84.54.49.4"); a != "84.54.49.4" {
		t.Fatalf("mapped IPv4: %q", a)
	}
	if a, _ := authSource("2a02:587:1:2:3:4:5:6"); a != "2a02:587:1:2::/64" {
		t.Fatalf("IPv6 /64: %q", a)
	}
}

// orion, 8 Oct 2026: info@ read from the office (GR), the Mail.ru / VK
// collector (rimap37.m.smailru.net, RU) and a mail app on Google Cloud (US)
// within an hour — one owner, not a hijack.
func TestMailCollectorsAreNotAHijack(t *testing.T) {
	orig := geoOf
	geoOf = func(ip string) (string, uint) {
		switch {
		case ip == "176.112.169.196":
			return "RU", 47764
		case strings.HasPrefix(ip, "34.27."):
			return "US", 396982
		}
		return "GR", 6799
	}
	t.Cleanup(func() { geoOf = orig })
	tr := newTracker()
	for _, ip := range []string{"5.203.22.73", "176.112.169.196", "34.27.14.24", "34.27.195.226"} {
		tr.observeMaillog("Oct  8 18:03:05 orion dovecot[1]: imap-login: Logged in: user=<info@socialpower.gr>, method=PLAIN, rip="+ip+", lip=157.90.128.246, mpid=1, TLS, session=<a>", time.Now())
	}
	if fs, _, _ := tr.evaluate(openTemp(t), time.Now()); len(fs) != 0 {
		t.Fatalf("office + mail collectors is not a hijack: %+v", fs)
	}
}

// A volume spike pages only from abuseAlertFloor messages; an open one stays
// judged below it so it does not flap.
func TestSpikeAlertFloor(t *testing.T) {
	st := openTemp(t)
	T := time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)
	for d := 1; d <= 5; d++ {
		for h := 0; h < 3; h++ {
			if err := st.AddReport(T.Add(-time.Duration(d)*24*time.Hour+time.Duration(h)*time.Hour), localReport("shop", 4)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := st.AddReport(T.Add(-time.Hour), localReport("shop", 37)); err != nil {
		t.Fatal(err)
	}
	tr := newTracker()
	if fs, _, _, _ := tr.evaluateWith(st, T, nil, nil); len(fs) != 0 {
		t.Fatalf("37 messages at ~9× is not an alert: %+v", fs)
	}
	if fs, _, _, _ := tr.evaluateWith(st, T, map[string]bool{"mail:script:shop": true}, nil); len(fs) != 1 {
		t.Fatalf("an open spike is still judged below the floor: %+v", fs)
	}
	if err := st.AddReport(T.Add(-30*time.Minute), localReport("shop", 30)); err != nil {
		t.Fatal(err)
	}
	if fs, _, _, _ := tr.evaluateWith(st, T, nil, nil); len(fs) != 1 {
		t.Fatalf("67 messages is an alert: %+v", fs)
	}
}
