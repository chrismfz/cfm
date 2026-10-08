package mailtraffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	for i := 0; i < 3; i++ {
		ts := T.Add(-time.Duration(30-i) * time.Minute).Format("2006-01-02 15:04:05")
		tr.observeExim(ts+" cwd=/home/hotellito/public_html 4 args: /usr/sbin/sendmail -t -i -fwebhostingcosmoteam@gmail.com", T)
		tr.observeExim(ts+" 1xEL5B-0000000G4kX-2ged <= webhostingcosmoteam@gmail.com U=hotellito P=local S=1390 id=x@hotellito.gr T=\"offer for you\" for litohotel@outlook.com victim"+string(rune('a'+i))+"@gmail.com", T)
	}
	fs, recent, ok := tr.evaluate(st, T)
	if !ok || len(fs) != 1 {
		t.Fatalf("want one finding, got ok=%v %+v", ok, fs)
	}
	f := fs[0]
	if f.Type != TypeScriptSpike || f.Severity != "critical" || f.Key != "mail:script:hotellito" {
		t.Fatalf("unexpected finding %+v", f)
	}
	for _, want := range []string{"86 messages sent by scripts", "/home/hotellito/public_html", "webhostingcosmoteam@gmail.com (not a domain on this server)", "4 different recipients"} {
		if !strings.Contains(f.Message, want) {
			t.Fatalf("message %q lacks %q", f.Message, want)
		}
	}
	if len(f.Message) > 255 {
		t.Fatalf("message too long for cfm-web: %d", len(f.Message))
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
	orig := countryOf
	countryOf = func(ip string) string {
		return map[string]string{"1.1.1.1": "GR", "2.2.2.2": "VN", "3.3.3.3": "BR", "4.4.4.4": "GR"}[ip]
	}
	t.Cleanup(func() { countryOf = orig })
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

func TestPostfixAuthIPsAreTracked(t *testing.T) {
	tr := newTracker()
	tr.observeMaillog("Oct  8 10:00:00 mx postfix/submission/smtpd[1]: 4AB: client=unknown[5.6.7.8], sasl_method=PLAIN, sasl_username=info@shop.gr", time.Now())
	if _, ok := tr.authIPs["info@shop.gr"]["5.6.7.8"]; !ok {
		t.Fatalf("postfix sasl login not tracked: %+v", tr.authIPs)
	}
}
