package mailtraffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"cfm/internal/mailmeter"
)

type pubRec struct{ typ, sev, key, msg string }

func recordAbuse(t *testing.T) *[]pubRec {
	t.Helper()
	var got []pubRec
	SetFaultSink(func(typ, sev, key, msg string, _ time.Time) bool {
		got = append(got, pubRec{typ, sev, key, msg})
		return true
	})
	t.Cleanup(func() { SetFaultSink(nil) })
	return &got
}

func localReport(user string, n int) mailmeter.Report {
	r := mailmeter.NewReport()
	r.LocalSubmitByUser[user] = n
	r.LocalSubmitTotal = n
	return r
}

func withLocalDomains(t *testing.T, doms ...string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "localdomains")
	if err := os.WriteFile(p, []byte(strings.Join(doms, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := localDomainFiles
	localDomainFiles = []string{p}
	localDomMu.Lock()
	localDoms = nil
	localDomMu.Unlock()
	t.Cleanup(func() {
		localDomainFiles = orig
		localDomMu.Lock()
		localDoms = nil
		localDomMu.Unlock()
	})
}

// titan, 6 Oct 2026: a Joomla contact form on hotellito sent ~43 messages an
// hour, each to the site owner and one new outside address, "from" a gmail
// address — while the user normally sends about one a day.
func TestScriptSpikeHotellito(t *testing.T) {
	got := recordAbuse(t)
	withLocalDomains(t, "hotellito.gr", "www.hotellito.gr")
	st := openTemp(t)
	T := time.Date(2026, 10, 6, 12, 0, 0, 0, time.Local)
	for _, d := range []int{1, 2, 3, 4, 5} { // ~1 a day for the week before
		if err := st.AddReport(T.Add(-time.Duration(d)*24*time.Hour), localReport("hotellito", 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.AddReport(T.Add(-time.Hour), localReport("hotellito", 86)); err != nil {
		t.Fatal(err)
	}

	tr := newTracker()
	for i := 0; i < 6; i++ {
		ts := T.Add(-time.Duration(30-i) * time.Minute).Format("2006-01-02 15:04:05")
		tr.observeExim(ts+" cwd=/home/hotellito/public_html 4 args: /usr/sbin/sendmail -t -i -fwebhostingcosmoteam@gmail.com", T)
		// the real subject, as exim logged (and cut) it on titan
		tr.observeExim(ts+" 1xEL5B-0000000G4kX-2ged <= webhostingcosmoteam@gmail.com U=hotellito P=local S=1390 id=x@hotellito.gr T=\"=?utf-8?B?0JvQsNC30LXRgNC90YvQtSDRgdC60LDQvdC10YDRiyB8IHBhd3ViYWxlODky?=  =?utf-8?B?QGdtYWlsLmNvbSB8\" for litohotel@outlook.com victim"+string(rune('a'+i))+"@gmail.com", T)
	}
	fs, recent, ok := tr.evaluate(st, T)
	if !ok || len(fs) != 1 {
		t.Fatalf("want one finding, got ok=%v %+v", ok, fs)
	}
	f := fs[0]
	if f.Type != TypeScriptSpike || f.Severity != "critical" || f.Key != "mail:script:hotellito" {
		t.Fatalf("unexpected finding %+v", f)
	}
	for _, want := range []string{"86 messages sent by scripts", "/home/hotellito/public_html", "webhostingcosmoteam@gmail.com (not a domain here)", "contact-form pattern: litohotel@outlook.com + a new address each"} {
		if !strings.Contains(f.Message, want) {
			t.Fatalf("message %q lacks %q", f.Message, want)
		}
	}
	if n := utf8.RuneCountInString(f.Message); n > 250 { // cfm-web keeps 250 characters
		t.Fatalf("message too long for cfm-web: %d characters", n)
	}

	if len(tr.last) != 1 || tr.last[0].Context == nil || tr.last[0].Context.Recipients != 7 ||
		len(tr.last[0].Context.Subjects) != 1 || !strings.HasPrefix(tr.last[0].Context.Subjects[0], "Лазерные сканеры") ||
		tr.last[0].Context.RcptDomains[0] != "gmail.com×6" {
		t.Fatalf("the view must carry the decoded subject and recipients: %+v", tr.last)
	}

	p := &publisher{path: filepath.Join(t.TempDir(), "state.json")}
	p.apply(fs, recent, T)
	p.apply(fs, recent, T.Add(5*time.Minute))
	if len(*got) != 1 || (*got)[0].typ != TypeScriptSpike {
		t.Fatalf("published once: %+v", *got)
	}
}

func TestSystemUsersAreNotScriptSpikes(t *testing.T) {
	st := openTemp(t)
	T := time.Unix(1_700_000_000, 0)
	if err := st.AddReport(T.Add(-time.Hour), localReport("root", 500)); err != nil {
		t.Fatal(err)
	}
	if fs, _, _ := newTracker().evaluate(st, T); len(fs) != 0 {
		t.Fatalf("root's cron mail is not a hacked site: %+v", fs)
	}
}

// A long incident becomes its own baseline: the ratio falls back under the
// threshold while the volume does not. It must stay open until the volume is
// back near what it was before.
func TestSpikeClosesOnlyWhenVolumeIsBackToItsOldLevel(t *testing.T) {
	got := recordAbuse(t)
	p := &publisher{}
	T := time.Unix(1_700_000_000, 0)
	open := []abuseFinding{{Type: TypeScriptSpike, Severity: "critical", Key: "mail:script:u", Message: "m", Expected: 2}}
	p.apply(open, map[string]int64{"mail:script:u": 86}, T)

	p.apply(nil, map[string]int64{"mail:script:u": 80}, T.Add(48*time.Hour)) // ratio gone, volume not
	if len(*got) != 1 {
		t.Fatalf("must stay open while the volume stays high: %+v", *got)
	}
	p.apply(nil, map[string]int64{"mail:script:u": 2}, T.Add(72*time.Hour))
	if len(*got) != 2 || (*got)[1].typ != TypeRecovered || (*got)[1].key != "mail:script:u" || (*got)[1].sev != "info" {
		t.Fatalf("want one recovery under the same key: %+v", *got)
	}
}

func TestSeverityRiseIsRepublished(t *testing.T) {
	got := recordAbuse(t)
	p := &publisher{}
	T := time.Unix(1_700_000_000, 0)
	w := abuseFinding{Type: TypeOutboundSpike, Severity: "warning", Key: "mail:out:a@x.gr", Message: "m"}
	p.apply([]abuseFinding{w}, nil, T)
	c := w
	c.Severity = "critical"
	p.apply([]abuseFinding{c}, nil, T)
	p.apply([]abuseFinding{w}, nil, T) // calmer: no news
	if len(*got) != 2 || (*got)[1].sev != "critical" {
		t.Fatalf("want warning then critical: %+v", *got)
	}
}

func TestNoSinkKeepsTheFindingForTheNextCheck(t *testing.T) {
	SetFaultSink(nil)
	p := &publisher{}
	T := time.Unix(1_700_000_000, 0)
	f := []abuseFinding{{Type: TypeHijack, Severity: "critical", Key: "mail:hijack:a@x.gr", Message: "m"}}
	p.apply(f, nil, T)
	got := recordAbuse(t)
	p.apply(f, nil, T)
	if len(*got) != 1 {
		t.Fatalf("undelivered finding must be retried: %+v", *got)
	}
}

func TestHijackFromManyCountries(t *testing.T) {
	orig := geoOf
	geoOf = func(ip string) (string, uint) {
		return map[string]string{"1.1.1.1": "GR", "2.2.2.2": "VN", "3.3.3.3": "BR", "4.4.4.4": "GR"}[ip], 0
	}
	t.Cleanup(func() { geoOf = orig })
	st := openTemp(t)
	T := time.Unix(1_700_000_000, 0)
	tr := newTracker()
	ts := T.Add(-10 * time.Minute).Format("2006-01-02 15:04:05")
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		tr.observeExim(ts+" 1abc <= info@shop.gr H=(x) ["+ip+"]:5555 P=esmtpsa X=TLS1.3 A=dovecot_login:info@shop.gr S=900 for a@b.c", T)
	}
	// a normal mailbox: two IPs, one country
	for _, ip := range []string{"1.1.1.1", "4.4.4.4"} {
		tr.observeExim(ts+" 1abd <= me@shop.gr H=(x) ["+ip+"]:5555 P=esmtpsa X=TLS1.3 A=dovecot_login:me@shop.gr S=900 for a@b.c", T)
	}
	fs, _, ok := tr.evaluate(st, T)
	if !ok || len(fs) != 1 || fs[0].Type != TypeHijack || fs[0].Key != "mail:hijack:info@shop.gr" || !strings.Contains(fs[0].Message, "3 countries (BR, GR, VN)") {
		t.Fatalf("want one hijack for info@shop.gr: %+v", fs)
	}
	// an hour later the logins aged out: nothing
	if fs, _, _ := tr.evaluate(st, T.Add(2*time.Hour)); len(fs) != 0 {
		t.Fatalf("old logins must age out: %+v", fs)
	}
}

// A mailbox used as "send mail as" in Gmail logs in from many Google IPs,
// all in one country: not a hijack.
func TestManyIPsInOneCountryAreNotAHijack(t *testing.T) {
	orig := geoOf
	geoOf = func(string) (string, uint) { return "US", 0 }
	t.Cleanup(func() { geoOf = orig })
	tr := newTracker()
	T := time.Unix(1_700_000_000, 0)
	ts := T.Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	for i := 0; i < 30; i++ {
		ip := "209.85.220." + string(rune('0'+i%10)) + string(rune('0'+i/10))
		tr.observeExim(ts+" 1x <= info@shop.gr H=(mail-gmail) ["+ip+"]:1 P=esmtpsa A=dovecot_login:info@shop.gr S=1 for a@b.c", T)
	}
	if fs, _, _ := tr.evaluate(openTemp(t), T); len(fs) != 0 {
		t.Fatalf("one country, many IPs is not a hijack: %+v", fs)
	}
}

func TestPostfixAuthIPsAreTracked(t *testing.T) {
	tr := newTracker()
	tr.observeMaillog("Oct  8 10:00:00 mx postfix/submission/smtpd[1]: 4AB: client=unknown[5.6.7.8], sasl_method=PLAIN, sasl_username=info@shop.gr", time.Now())
	if _, ok := tr.authIPs["info@shop.gr"]["5.6.7.8"]; !ok {
		t.Fatalf("postfix sasl login not tracked: %+v", tr.authIPs)
	}
}

func TestDecodeSubject(t *testing.T) {
	for raw, want := range map[string]string{
		"Order #123 confirmed":                 "Order #123 confirmed",
		"=?utf-8?B?zpXPhc+HzrHPgc65z4PPhM+O?=": "Ευχαριστώ",
		// exim cut the second encoded word: keep what decodes, drop the stub
		"=?utf-8?B?zpXPhc+HzrHPgc65z4PPhM+O?=  =?utf-8?B?QGdtYW": "Ευχαριστώ",
		`say \"hi\"`: `say "hi"`,
	} {
		if got := decodeSubject(raw); got != want {
			t.Fatalf("decodeSubject(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A mailbox sending as someone else is worth saying; a newsletter from its own
// address to many domains is not a contact-form pattern.
func TestMailboxContext(t *testing.T) {
	withLocalDomains(t, "shop.gr")
	tr := newTracker()
	T := time.Unix(1_700_000_000, 0)
	ts := T.Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	for i := 0; i < 10; i++ {
		r := "c" + string(rune('a'+i)) + "@d" + string(rune('a'+i%3)) + ".com"
		tr.observeExim(ts+" 1x <= news@shop.gr H=(x) [1.1.1.1]:1 P=esmtpsa A=dovecot_login:news@shop.gr S=1 T=\"Autumn sale\" for "+r, T)
		tr.observeExim(ts+" 1y <= ceo@bank.example H=(x) [1.1.1.1]:1 P=esmtpsa A=dovecot_login:info@shop.gr S=1 T=\"Invoice\" for "+r, T)
	}
	news := tr.context("auth:news@shop.gr", "news@shop.gr")
	if news.OtherFrom || news.ForeignFrom || news.CopiedTo != "" || news.Recipients != 10 || news.Subjects[0] != "Autumn sale" {
		t.Fatalf("a newsletter: %+v", news)
	}
	hij := tr.context("auth:info@shop.gr", "info@shop.gr")
	if !hij.ForeignFrom || !strings.Contains(hij.describe("x"), "ceo@bank.example (not a domain here)") {
		t.Fatalf("sending as a foreign address must be said: %+v", hij)
	}
}

// Review of #1556: the cwd line belongs to whoever's directory it is.
func TestCwdIsOnlyTakenForItsOwnUser(t *testing.T) {
	tr := newTracker()
	T := time.Now()
	ts := T.Format("2006-01-02 15:04:05")
	tr.observeExim(ts+" cwd=/home/alice/public_html 4 args: /usr/sbin/sendmail -t -i", T)
	tr.observeExim(ts+" 1xEL5B-0000000G4kX-2aaa <= bob@x.gr U=bob P=local S=1 for a@b.c", T)
	tr.observeExim(ts+" 1xEL5B-0000000G4kX-2bbb <= alice@x.gr U=alice P=local S=1 for a@b.c", T)
	tr.observeExim(ts+" 1xEL5B-0000000G4kX-2ccc <= alice@x.gr U=alice P=local S=1 for a@b.c", T)
	if c := tr.context("local:bob", ""); c.Cwd != "" {
		t.Fatalf("bob must not get alice's directory: %q", c.Cwd)
	}
	ss := tr.samples["local:alice"]
	if len(ss) != 2 || ss[0].cwd != "/home/alice/public_html" || ss[1].cwd != "" {
		t.Fatalf("alice's cwd goes to her next message, once: %+v", ss)
	}
}

// A site mailing only its owner is not a contact form spamming strangers.
func TestCwdOwnedByIsAnchored(t *testing.T) {
	for _, c := range []struct {
		cwd, user string
		want      bool
	}{
		{"/home/alice/public_html", "alice", true},
		{"/home2/alice/public_html/x", "alice", true},
		{"/home/alice", "alice", true},
		{"/home/alice/public_html", "public_html", false},
		{"/home/alice/public_html", "home", false},
		{"/home/bob/www/alice/x", "alice", false},
		{"/usr/local/cpanel", "alice", false},
	} {
		if got := cwdOwnedBy(c.cwd, c.user); got != c.want {
			t.Errorf("cwdOwnedBy(%q, %q) = %v", c.cwd, c.user, got)
		}
	}
}

func TestOneRecipientIsNotTheContactFormPattern(t *testing.T) {
	tr := newTracker()
	T := time.Now()
	ts := T.Format("2006-01-02 15:04:05")
	for i := 0; i < 10; i++ {
		tr.observeExim(ts+" 1xEL5B-0000000G4kX-2ddd <= shop@shop.gr U=shop P=local S=1 for owner@shop.gr", T)
	}
	if c := tr.context("local:shop", ""); c.CopiedTo != "" || c.Recipients != 1 {
		t.Fatalf("one recipient: no pattern, one recipient counted: %+v", c)
	}
}

func TestDecodeSubjectCharsets(t *testing.T) {
	for raw, want := range map[string]string{
		"=?windows-1251?B?z/Do4uXy?=":            "Привет",
		"=?iso-8859-7?B?xvbv7Q==?=":              "Ζφον",
		"=?koi8-r?B?8NLJ18XU?= =?utf-8?Q?plus?=": "Приветplus",
	} {
		if got := decodeSubject(raw); got != want {
			t.Errorf("decodeSubject(%q) = %q, want %q", raw, got, want)
		}
	}
	// an unknown charset loses only its own word
	if got := decodeSubject("=?x-nope?B?AAAA?= =?utf-8?Q?kept?="); !strings.Contains(got, "kept") {
		t.Errorf("a bad word must not cost the others: %q", got)
	}
}

// A new sender (a migrated account, a new shop) is a warning at 50, critical
// only at 200; with no baseline from before, it settles after a while.
func TestNewSenderSeverityAndSettling(t *testing.T) {
	if s := spikeSeverity(Anomaly{Kind: "new-sender", Recent: 120}); s != "warning" {
		t.Fatalf("120 from a new sender: %s", s)
	}
	if s := spikeSeverity(Anomaly{Kind: "new-sender", Recent: 250}); s != "critical" {
		t.Fatalf("250 from a new sender: %s", s)
	}
	T := time.Now()
	busy := func(key string) map[string]int64 { return map[string]int64{key: 120} }

	// a new MAILBOX that opened as a warning settles after a quiet day
	got := recordAbuse(t)
	p := &publisher{}
	p.apply([]abuseFinding{{Type: TypeOutboundSpike, Severity: "warning", Key: "mail:out:new@shop.gr", Message: "new@shop.gr: 120"}}, nil, T)
	p.apply(nil, busy("mail:out:new@shop.gr"), T.Add(time.Hour))
	p.apply(nil, busy("mail:out:new@shop.gr"), T.Add(20*time.Hour))
	if len(*got) != 1 {
		t.Fatalf("still busy, not settled yet: %+v", *got)
	}
	p.apply(nil, busy("mail:out:new@shop.gr"), T.Add(26*time.Hour))
	if len(*got) != 2 || (*got)[1].typ != TypeRecovered || !strings.Contains((*got)[1].msg, "now its usual volume") {
		t.Fatalf("a new mailbox settles: %+v", *got)
	}

	// a SCRIPT spike never settles: a hacked quiet site opens exactly like this
	got = recordAbuse(t)
	p = &publisher{}
	p.apply([]abuseFinding{{Type: TypeScriptSpike, Severity: "warning", Key: "mail:script:shop", Message: "shop: 120"}}, nil, T)
	p.apply(nil, busy("mail:script:shop"), T.Add(time.Hour))
	p.apply(nil, busy("mail:script:shop"), T.Add(72*time.Hour))
	if len(*got) != 1 {
		t.Fatalf("a script spike stays open while the volume does: %+v", *got)
	}

	// nor does one that opened critical
	got = recordAbuse(t)
	p = &publisher{}
	p.apply([]abuseFinding{{Type: TypeOutboundSpike, Severity: "critical", Key: "mail:out:x@shop.gr", Message: "x: 2000"}}, nil, T)
	p.apply(nil, busy("mail:out:x@shop.gr"), T.Add(time.Hour))
	p.apply(nil, busy("mail:out:x@shop.gr"), T.Add(72*time.Hour))
	if len(*got) != 1 {
		t.Fatalf("a critical spike never settles: %+v", *got)
	}

	// an old sender with a real baseline does not settle while still high
	got2 := recordAbuse(t)
	p2 := &publisher{}
	p2.apply([]abuseFinding{{Type: TypeScriptSpike, Severity: "warning", Key: "mail:script:old", Message: "old", Expected: 2}}, nil, T)
	p2.apply(nil, map[string]int64{"mail:script:old": 120}, T.Add(24*time.Hour))
	if len(*got2) != 1 {
		t.Fatalf("a spike over its real baseline stays open: %+v", *got2)
	}
}
