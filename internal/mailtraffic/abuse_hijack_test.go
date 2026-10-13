package mailtraffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/panelmap"
)

func stubGeo(t *testing.T, fn func(ip string) (string, uint)) {
	t.Helper()
	orig := geoOf
	geoOf = fn
	t.Cleanup(func() { geoOf = orig })
}

func dovecotLogin(tr *tracker, user, proto, ip string, at time.Time) {
	tr.observeMaillog("Oct 13 10:00:00 orion dovecot[1]: "+proto+"-login: Logged in: user=<"+user+">, method=PLAIN, rip="+ip+", lip=9.9.9.9, mpid=1, TLS, session=<a>", at)
}

func smtpLogin(tr *tracker, user, ip string, at time.Time) {
	tr.observeExim(at.Format("2006-01-02 15:04:05")+" 1abc-000000-AB <= "+user+" H=(x) ["+ip+"]:5555 P=esmtpsa X=TLS1.3 A=dovecot_login:"+user+" S=900 for a@b.c", at)
}

func onlyHijack(t *testing.T, fs []abuseFinding) abuseFinding {
	t.Helper()
	var out []abuseFinding
	for _, f := range fs {
		if f.Type == TypeHijack {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("want one hijack: %+v", fs)
	}
	return out[0]
}

var threeCountries = func(ip string) (string, uint) {
	return map[string]string{"1.1.1.1": "GR", "1.1.1.2": "GR", "2.2.2.2": "MK", "3.3.3.3": "RS"}[ip], 0
}

// earth, Oct 2026: sekesa@sekesa.mk read over IMAP from GR, MK and RS every
// day, paged as a critical hijack six times in a week. Reading alone is a
// warning; it never asks to change the password once it stops.
func TestHijackReadingOnlyIsAWarning(t *testing.T) {
	stubGeo(t, threeCountries)
	got := recordAbuse(t)
	T := time.Now()
	tr := newTracker()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		dovecotLogin(tr, "sekesa@sekesa.mk", "imap", ip, T)
	}
	st := openTemp(t)
	fs, _, _ := tr.evaluate(st, T)
	f := onlyHijack(t, fs)
	if f.Severity != "warning" || !strings.Contains(f.Message, "3 countries (GR, MK, RS)") || !strings.Contains(f.Message, "reading only") {
		t.Fatalf("want a reading-only warning: %+v", f)
	}
	p := &publisher{}
	p.apply(fs, nil, T)
	p.apply(nil, nil, T.Add(2*time.Hour))
	if len(*got) != 2 || (*got)[0].sev != "warning" || (*got)[1].typ != TypeRecovered || strings.Contains((*got)[1].msg, "change the password") {
		t.Fatalf("want a warning, then a recovery without the password advice: %+v", *got)
	}
}

// Sending mail from a country other than the mailbox's home is the stolen
// password in use: critical, and it names where from.
func TestHijackSendingFromAbroadIsCritical(t *testing.T) {
	stubGeo(t, func(ip string) (string, uint) {
		return map[string]string{"1.1.1.1": "GR", "1.1.1.2": "GR", "2.2.2.2": "MK", "3.3.3.3": "VN"}[ip], 0
	})
	T := time.Now()
	tr := newTracker()
	dovecotLogin(tr, "info@shop.gr", "imap", "1.1.1.1", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "1.1.1.2", T)
	smtpLogin(tr, "info@shop.gr", "1.1.1.1", T) // the owner sends from home
	dovecotLogin(tr, "info@shop.gr", "imap", "2.2.2.2", T)
	smtpLogin(tr, "info@shop.gr", "3.3.3.3", T)
	fs, _, _ := tr.evaluate(openTemp(t), T)
	f := onlyHijack(t, fs)
	if f.Severity != "critical" || !strings.Contains(f.Message, "and sent mail from VN — ") {
		t.Fatalf("want critical, sent from VN only: %+v", f)
	}
}

// The owner sending from where the mailbox is also read is not a thief
// sending: a warning that says where the mail went out from.
func TestHijackSendingOnlyWhereItIsReadIsAWarning(t *testing.T) {
	stubGeo(t, threeCountries)
	T := time.Now()
	tr := newTracker()
	dovecotLogin(tr, "info@shop.gr", "imap", "1.1.1.1", T)
	smtpLogin(tr, "info@shop.gr", "1.1.1.2", T) // the office desktop, the phone reads: both GR
	dovecotLogin(tr, "info@shop.gr", "imap", "2.2.2.2", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "3.3.3.3", T)
	fs, _, _ := tr.evaluate(openTemp(t), T)
	f := onlyHijack(t, fs)
	if f.Severity != "warning" || !strings.Contains(f.Message, "sent mail only from GR, where it is also read") || !strings.Contains(f.Message, "(imap/smtp)") {
		t.Fatalf("want a warning: %+v", f)
	}
}

// One address per country (the common shape): mail sent from a country the
// mailbox is not read from is the thief's, whatever the counts.
func TestHijackSentFromAnUnreadCountry(t *testing.T) {
	stubGeo(t, threeCountries)
	T := time.Now()
	tr := newTracker()
	dovecotLogin(tr, "info@shop.gr", "imap", "1.1.1.1", T)
	smtpLogin(tr, "info@shop.gr", "2.2.2.2", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "3.3.3.3", T)
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if f := onlyHijack(t, fs); f.Severity != "critical" || !strings.Contains(f.Message, "sent mail from MK") {
		t.Fatalf("want critical: %+v", f)
	}
}

// A thief behind a proxy pool has more addresses than the owner: no
// majority vote decides where "home" is (review of PR #1597).
func TestHijackThiefWithMoreAddressesThanTheOwner(t *testing.T) {
	stubGeo(t, func(ip string) (string, uint) {
		switch {
		case strings.HasPrefix(ip, "41."):
			return "NG", 1
		case ip == "9.9.9.9":
			return "US", 2
		}
		return "GR", 3
	})
	T := time.Now()
	tr := newTracker()
	for _, ip := range []string{"41.0.0.1", "41.0.0.2", "41.0.0.3", "41.0.0.4"} {
		smtpLogin(tr, "info@shop.gr", ip, T)
	}
	dovecotLogin(tr, "info@shop.gr", "imap", "62.1.1.1", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "62.1.1.2", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "9.9.9.9", T)
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if f := onlyHijack(t, fs); f.Severity != "critical" || !strings.Contains(f.Message, "sent mail from NG") {
		t.Fatalf("want critical: %+v", f)
	}
}

// A thief with a full mail client reads and sends from one address; the
// owner sends too, from home: mail from two countries in the hour.
func TestHijackSentFromTwoCountries(t *testing.T) {
	stubGeo(t, func(ip string) (string, uint) {
		return map[string]string{"1.1.1.1": "GR", "2.2.2.2": "VN", "3.3.3.3": "RS"}[ip], 0
	})
	T := time.Now()
	tr := newTracker()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		dovecotLogin(tr, "info@shop.gr", "imap", ip, T)
		smtpLogin(tr, "info@shop.gr", ip, T)
	}
	dovecotLogin(tr, "info@shop.gr", "imap", "3.3.3.3", T)
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if f := onlyHijack(t, fs); f.Severity != "critical" || !strings.Contains(f.Message, "sent mail from GR, VN") {
		t.Fatalf("want critical: %+v", f)
	}
}

// An address that sent mail more than an hour ago and only reads now has not
// sent mail within the window.
func TestHijackOldSMTPDoesNotCount(t *testing.T) {
	stubGeo(t, threeCountries)
	T := time.Now()
	tr := newTracker()
	dovecotLogin(tr, "info@shop.gr", "imap", "1.1.1.1", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "1.1.1.2", T)
	smtpLogin(tr, "info@shop.gr", "2.2.2.2", T.Add(-90*time.Minute))
	dovecotLogin(tr, "info@shop.gr", "imap", "2.2.2.2", T)
	dovecotLogin(tr, "info@shop.gr", "imap", "3.3.3.3", T)
	fs, _, _ := tr.evaluate(openTemp(t), T)
	if f := onlyHijack(t, fs); f.Severity != "warning" || !strings.Contains(f.Message, "(imap)") {
		t.Fatalf("an old SMTP login must not confirm it: %+v", f)
	}
}

// A spike or bounce FINDING of the same mailbox this check confirms the
// hijack; one only held open on volume does not (review of PR #1597).
func TestHijackConfirmedByItsOwnSpikeOrBounces(t *testing.T) {
	h := hijackCand{user: "a@x.gr", sources: 3, countries: []string{"GR", "MK", "RS"}, vias: []string{"imap"}}
	if f := h.finding(nil, nil); f.Severity != "warning" {
		t.Fatalf("nothing else: a warning: %+v", f)
	}
	for k, want := range map[string]string{
		"mail:out:a@x.gr":         "is sending far above its usual",
		"mail:bounce:auth:a@x.gr": "its mail bounces in bulk",
	} {
		if f := h.finding(map[string]bool{k: true}, nil); f.Severity != "critical" || !strings.Contains(f.Message, want) {
			t.Fatalf("want critical %q: %+v", want, f)
		}
	}
	if f := h.finding(map[string]bool{"mail:out:b@x.gr": true}, nil); f.Severity != "warning" {
		t.Fatalf("another mailbox's spike confirms nothing: %+v", f)
	}
}

// A forwarder or a mail filter set on the mailbox within a day confirms it;
// one changed long ago, or another address's forwarder, does not. The answer
// is reused for hijackRulesRecheck.
func TestHijackConfirmedByChangedForwarderOrFilter(t *testing.T) {
	etc, home := t.TempDir(), t.TempDir()
	origEtc, origHome, origUD := cpanelEtc, mailboxHome, panelmap.UserDomainsPath
	cpanelEtc, mailboxHome = etc, func(u string) string {
		if u == "shopuser" {
			return home
		}
		return ""
	}
	panelmap.UserDomainsPath = filepath.Join(etc, "userdomains")
	t.Cleanup(func() { cpanelEtc, mailboxHome, panelmap.UserDomainsPath = origEtc, origHome, origUD })
	write := func(p, body string, age time.Duration) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write(panelmap.UserDomainsPath, "other.gr: someone\nshop.gr: shopuser\n", 30*24*time.Hour)
	valiases := filepath.Join(etc, "valiases", "shop.gr")
	filter := filepath.Join(home, "etc", "shop.gr", "info", "filter")
	T := time.Now()
	rules := func(addr string) string {
		return rulesFor(addr, panelmap.HostOwners([]string{"shop.gr"}), T)
	}

	write(valiases, "sales@shop.gr: boss@gmail.com\n", time.Hour)
	if r := rules("info@shop.gr"); r != "" {
		t.Fatalf("another address's forwarder: %q", r)
	}
	write(valiases, "Info@shop.gr: thief@gmail.com\n", time.Hour)
	if r := rules("info@shop.gr"); r != "its forwarder" {
		t.Fatalf("want its forwarder: %q", r)
	}
	write(valiases, "info@shop.gr: owner@gmail.com\n", 3*24*time.Hour)
	write(filter, "# Exim filter\n", 2*time.Hour)
	if r := rules("info@shop.gr"); r != "its mail filter" {
		t.Fatalf("want its mail filter: %q", r)
	}

	tr := newTracker()
	got := tr.rulesChanged([]string{"info@shop.gr"}, T)
	h := hijackCand{user: "info@shop.gr", sources: 3, countries: []string{"BR", "GR", "VN"}, vias: []string{"imap"}}
	if f := h.finding(nil, got); f.Severity != "critical" || !strings.Contains(f.Message, "its mail filter changed in the last 24 h") {
		t.Fatalf("want critical: %+v", f)
	}
	write(filter, "# Exim filter\n", 3*24*time.Hour)
	if r := rules("info@shop.gr"); r != "" {
		t.Fatalf("old changes confirm nothing: %q", r)
	}
	if got := tr.rulesChanged([]string{"info@shop.gr"}, T.Add(5*time.Minute)); got["info@shop.gr"] != "its mail filter" {
		t.Fatalf("the answer is reused within hijackRulesRecheck: %+v", got)
	}
	if got := tr.rulesChanged([]string{"info@shop.gr"}, T.Add(hijackRulesRecheck)); got["info@shop.gr"] != "" {
		t.Fatalf("then asked again: %+v", got)
	}
	for _, bad := range []string{"../../x@shop.gr", "info@../etc", "info@", "@shop.gr", "a/b@shop.gr"} {
		if r := rules(bad); r != "" {
			t.Fatalf("%q: %q", bad, r)
		}
	}
}

// orion, Oct 2026: larrynail@ and sonia@aspirephysiciansolutions.com read
// from a US phone (AT&T), the French office (Orange) and Netskope exits in IN
// and UG — one company behind its security gateway, not a hijack.
func TestCorporateProxyIsOneSourceWithNoCountry(t *testing.T) {
	stubGeo(t, func(ip string) (string, uint) {
		switch {
		case strings.HasPrefix(ip, "163.116.205."):
			return "IN", 55256
		case strings.HasPrefix(ip, "163.116.213."):
			return "UG", 55256
		case strings.HasPrefix(ip, "166.205."):
			return "US", 7018
		}
		return "FR", 3215
	})
	T := time.Now()
	tr := newTracker()
	for _, ip := range []string{"166.205.208.97", "163.116.205.144", "163.116.213.145", "212.234.15.113"} {
		dovecotLogin(tr, "larrynail@aspirephysiciansolutions.com", "imap", ip, T)
	}
	if fs, _, _ := tr.evaluate(openTemp(t), T); len(fs) != 0 {
		t.Fatalf("a corporate gateway is not a hijack: %+v", fs)
	}
}

// A hijack resolved within hijackQuiet that comes back from the same
// countries, no worse, is not published again; a new country, a rise to
// critical, or a week later is. Survives a restart.
func TestHijackIsNotRepagedForTheSameCountries(t *testing.T) {
	got := recordAbuse(t)
	path := filepath.Join(t.TempDir(), "mail_abuse_published.json")
	T := time.Unix(1_700_000_000, 0)
	w := func(cs ...string) abuseFinding {
		return abuseFinding{Type: TypeHijack, Severity: "warning", Key: "mail:hijack:a@x.gr", Message: "m " + strings.Join(cs, ","), Countries: cs}
	}
	p := &publisher{path: path}
	p.apply([]abuseFinding{w("GR", "MK", "RS")}, nil, T)
	p.apply(nil, nil, T.Add(time.Hour)) // resolved
	if len(*got) != 2 {
		t.Fatalf("want published and resolved: %+v", *got)
	}

	p = &publisher{path: path} // a restart
	p.apply([]abuseFinding{w("GR", "MK")}, nil, T.Add(24*time.Hour))
	p.apply([]abuseFinding{w("GR", "MK", "RS")}, nil, T.Add(25*time.Hour))
	if len(*got) != 2 {
		t.Fatalf("same countries again: nothing new: %+v", *got)
	}
	p.apply(nil, nil, T.Add(26*time.Hour)) // nothing was open: no recovery
	if len(*got) != 2 {
		t.Fatalf("a quiet hijack is never resolved: %+v", *got)
	}

	p.apply([]abuseFinding{w("GR", "MK", "TR")}, nil, T.Add(27*time.Hour))
	if len(*got) != 3 || (*got)[2].typ != TypeHijack {
		t.Fatalf("a new country is news: %+v", *got)
	}
	p.apply(nil, nil, T.Add(28*time.Hour))

	c := w("GR", "MK")
	c.Severity = "critical"
	p.apply([]abuseFinding{c}, nil, T.Add(29*time.Hour))
	if len(*got) != 5 || (*got)[4].sev != "critical" {
		t.Fatalf("a rise to critical is news: %+v", *got)
	}
	p.apply(nil, nil, T.Add(30*time.Hour))
	if !strings.Contains((*got)[5].msg, "still change the password") {
		t.Fatalf("a critical one asks for the password change: %+v", (*got)[5])
	}

	// after a critical one nothing is quiet: that password was in use
	p.apply([]abuseFinding{w("GR", "MK")}, nil, T.Add(31*time.Hour))
	if len(*got) != 7 || (*got)[6].sev != "warning" {
		t.Fatalf("a warning after a critical is news: %+v", *got)
	}
	p.apply(nil, nil, T.Add(32*time.Hour))
	p.apply([]abuseFinding{c}, nil, T.Add(33*time.Hour))
	if len(*got) != 9 || (*got)[8].sev != "critical" {
		t.Fatalf("a critical one back is always news: %+v", *got)
	}
}

// A quiet sighting renews the memory: the same pattern every day is not
// paged again every week. Countries met while it is open are remembered.
func TestHijackQuietRenewsAndRemembersEveryCountry(t *testing.T) {
	got := recordAbuse(t)
	T := time.Unix(1_700_000_000, 0)
	w := func(cs ...string) abuseFinding {
		return abuseFinding{Type: TypeHijack, Severity: "warning", Key: "mail:hijack:a@x.gr", Message: "m", Countries: cs}
	}
	p := &publisher{}
	p.apply([]abuseFinding{w("GR", "MK", "RS")}, nil, T)
	p.apply([]abuseFinding{w("GR", "MK", "TR")}, nil, T.Add(10*time.Minute)) // still open, a new country: no news, remembered
	p.apply(nil, nil, T.Add(time.Hour))
	if len(*got) != 2 {
		t.Fatalf("want published and resolved: %+v", *got)
	}
	for d := 1; d <= 20; d++ {
		p.apply([]abuseFinding{w("GR", "MK", "TR")}, nil, T.Add(time.Duration(d)*24*time.Hour))
	}
	if len(*got) != 2 {
		t.Fatalf("the same pattern every day stays quiet: %+v", *got)
	}
}

// An alert paged critical and re-judged a warning this hour (the SMTP login
// left the window) is shown as what the team was told: publishing never
// downgrades it (review of PR #1597).
func TestCurrentAbuseKeepsThePublishedSeverity(t *testing.T) {
	c := newCollector(openTemp(t), "")
	c.ab.last = []AbuseView{{Type: TypeHijack, Severity: "warning", Key: "mail:hijack:a@x.gr", Message: "now"}}
	c.ab.lastCheck = time.Now()
	c.pub.load()
	c.pub.open["mail:hijack:a@x.gr"] = openFinding{Type: TypeHijack, Severity: "critical", Message: "paged"}
	sharedMu.Lock()
	prev := coll
	coll = c
	sharedMu.Unlock()
	t.Cleanup(func() {
		sharedMu.Lock()
		coll = prev
		sharedMu.Unlock()
	})
	views, _ := CurrentAbuse()
	if len(views) != 1 || views[0].Severity != "critical" || views[0].Message != "paged" {
		t.Fatalf("want the published critical: %+v", views)
	}
}
