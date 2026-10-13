package mailtraffic

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var spikeT = time.Date(2026, 10, 13, 12, 0, 0, 0, time.Local)

// spikeStore: a mailbox that sends 4 an hour, 3 hours a day, for 5 days.
func spikeStore(t *testing.T, addr string) *Store {
	t.Helper()
	st := openTemp(t)
	for d := 1; d <= 5; d++ {
		for h := 0; h < 3; h++ {
			if err := st.AddReport(spikeT.Add(-time.Duration(d)*24*time.Hour+time.Duration(h)*time.Hour), outboundReport(addr, 4)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return st
}

func addOut(t *testing.T, st *Store, addr string, at time.Time, n int) {
	t.Helper()
	if err := st.AddReport(at, outboundReport(addr, n)); err != nil {
		t.Fatal(err)
	}
}

// sendAs logs n authenticated messages of mailbox, sent "as" from.
func sendAs(tr *tracker, mailbox, from string, n int) {
	ts := spikeT.Add(-30 * time.Minute).Format("2006-01-02 15:04:05")
	for i := 0; i < n; i++ {
		tr.observeExim(fmt.Sprintf("%s 1abc <= %s H=(x) [1.1.1.1]:1 P=esmtpsa A=dovecot_login:%s S=1 T=\"Order %d\" for c%d@gmail.com", ts, from, mailbox, i, i), spikeT)
	}
}

func outFinding(t *testing.T, fs []abuseFinding) *abuseFinding {
	t.Helper()
	var got *abuseFinding
	for i := range fs {
		if fs[i].Type == TypeOutboundSpike {
			if got != nil {
				t.Fatalf("want at most one spike: %+v", fs)
			}
			got = &fs[i]
		}
	}
	return got
}

// The peak is the largest sum over two consecutive hourly buckets, before the
// recent window.
func TestPeakWindows(t *testing.T) {
	st := openTemp(t)
	day := spikeT.Add(-3 * 24 * time.Hour)
	for h, n := range []int{5, 100, 70, 0, 60, 1} {
		if n > 0 {
			addOut(t, st, "a@x.gr", day.Add(time.Duration(h)*time.Hour), n)
		}
	}
	addOut(t, st, "a@x.gr", spikeT.Add(-time.Hour), 999) // the recent window itself
	addOut(t, st, "a@x.gr", spikeT.Add(-40*24*time.Hour), 999)
	got, err := st.peakWindows("outbound", []string{"a@x.gr", "none@x.gr"}, spikeT)
	if err != nil {
		t.Fatal(err)
	}
	if got["a@x.gr"] != 170 || got["none@x.gr"] != 0 {
		t.Fatalf("want 100+70, ignoring the recent window and >28 days: %+v", got)
	}
}

// titan, Oct 2026: itadmin@pantelos.gr sent its "Order production start" run
// of 177 one morning and 176 the next, paged at 3× its usual both days. A
// burst no larger than its own peak is not an alert; past it, it is.
func TestSpikeDoneBeforeIsNotAnAlert(t *testing.T) {
	st := spikeStore(t, "itadmin@x.gr")
	addOut(t, st, "itadmin@x.gr", spikeT.Add(-24*time.Hour+time.Hour), 177)
	addOut(t, st, "itadmin@x.gr", spikeT.Add(-time.Hour), 176)
	tr := newTracker()
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f != nil {
		t.Fatalf("176 after 177 the day before is its usual run: %+v", f)
	}
	if fs, _, _, _ := tr.evaluateWith(st, spikeT, map[string]bool{"mail:out:itadmin@x.gr": true}, nil); outFinding(t, fs) == nil {
		t.Fatal("an open spike is judged as before (its own incident is in the peak)")
	}
	addOut(t, st, "itadmin@x.gr", spikeT.Add(-30*time.Minute), 60)
	fs, _, _, _ = tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil || !strings.Contains(f.Message, "236 authenticated") {
		t.Fatalf("past its peak it is a finding again: %+v", fs)
	}
}

// A spike with no tell of abuse is info (listed, never paged); a foreign
// sender, another domain, or bounces of its own keep it a warning. Another
// address of its own domain is the same owner, not a tell.
func TestSpikeNeedsATellOfAbuse(t *testing.T) {
	withLocalDomains(t, "shop.gr", "pantelos.gr")
	for _, tc := range []struct {
		name, mailbox, from, sev, has, not string
	}{
		{"volume only", "info@shop.gr", "info@shop.gr", "info", "· volume only", ""},
		{"own domain alias", "mail@pantelos.gr", "claim@pantelos.gr", "info", "· as claim@pantelos.gr", "(another domain)"},
		{"another domain", "info@shop.gr", "info@pantelos.gr", "warning", "(another domain)", "volume only"},
		{"foreign sender", "info@shop.gr", "x@gmail.com", "warning", "(not a domain here)", "volume only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := spikeStore(t, tc.mailbox)
			addOut(t, st, tc.mailbox, spikeT.Add(-time.Hour), 60)
			tr := newTracker()
			sendAs(tr, tc.mailbox, tc.from, 10)
			fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
			f := outFinding(t, fs)
			if f == nil || f.Severity != tc.sev || !strings.Contains(f.Message, tc.has) || (tc.not != "" && strings.Contains(f.Message, tc.not)) {
				t.Fatalf("want %s with %q: %+v", tc.sev, tc.has, f)
			}
		})
	}
}

// A small spike of a mailbox sending as another address of its own domain is
// no longer kept as an alert below the floor (it was the spoofing tell):
// titan's mail@pantelos.gr at 20–23 in 2 h, paged twice a day.
func TestOwnDomainAliasIsNotKeptBelowTheFloor(t *testing.T) {
	withLocalDomains(t, "pantelos.gr")
	st := spikeStore(t, "mail@pantelos.gr")
	addOut(t, st, "mail@pantelos.gr", spikeT.Add(-time.Hour), 25)
	tr := newTracker()
	sendAs(tr, "mail@pantelos.gr", "claim@pantelos.gr", 10)
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f != nil {
		t.Fatalf("25 at 3× as its own claim@ is not an alert: %+v", f)
	}
}

// An extreme spike stays a warning on volume alone (one step down from
// critical); bounces of its own, or logins from many countries, make a
// volume spike a warning again.
func TestVolumeOnlyStepsDownOneLevel(t *testing.T) {
	st := spikeStore(t, "payroll@x.gr")
	addOut(t, st, "payroll@x.gr", spikeT.Add(-time.Hour), 136)
	tr := newTracker()
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil || f.Severity != "warning" || !strings.Contains(f.Message, "volume only") {
		t.Fatalf("an extreme volume-only spike is a warning: %+v", f)
	}

	stubGeo(t, threeCountries)
	st = spikeStore(t, "info@shop.gr")
	addOut(t, st, "info@shop.gr", spikeT.Add(-time.Hour), 60)
	tr = newTracker()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		dovecotLogin(tr, "info@shop.gr", "imap", ip, spikeT)
	}
	fs, _, _, _ = tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil || f.Severity != "warning" || strings.Contains(f.Message, "volume only") {
		t.Fatalf("a spike of a mailbox logged in from many countries is a warning: %+v", fs)
	}
	if h := onlyHijack(t, fs); h.Severity != "critical" {
		t.Fatalf("and the hijack is confirmed by it: %+v", h)
	}
}

// Review of the change: a tell of abuse is judged before "done before" — the
// peak can be the same thief's earlier run.
func TestATellBeatsDoneBefore(t *testing.T) {
	withLocalDomains(t, "shop.gr")
	st := spikeStore(t, "info@shop.gr")
	addOut(t, st, "info@shop.gr", spikeT.Add(-10*24*time.Hour), 300) // the first run, long resolved
	addOut(t, st, "info@shop.gr", spikeT.Add(-time.Hour), 150)
	tr := newTracker()
	sendAs(tr, "info@shop.gr", "x@gmail.com", 10)
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil || f.Severity != "critical" {
		t.Fatalf("back under its old peak but as a foreign sender: still paged: %+v", fs)
	}
}

// Review of PR #1598: at the top of an hour the current bucket is empty, and
// a steady sender's last two hours EQUAL a two-hour peak: equal is not
// "done before". The hours just before the recent window are not in the
// peak, so a falling incident cannot hide behind its own first hours.
func TestSteadyOrFallingRateIsNotDoneBefore(t *testing.T) {
	st := openTemp(t)
	for h := 30; h >= 1; h-- {
		addOut(t, st, "a@x.gr", spikeT.Add(-time.Duration(h)*time.Hour), 100)
	}
	peaks, err := st.peakWindows("outbound", []string{"a@x.gr"}, spikeT)
	if err != nil || peaks["a@x.gr"] != 200 {
		t.Fatalf("peak: %+v %v", peaks, err)
	}
	tr := newTracker()
	if tr.doneBefore(Anomaly{Addr: "a@x.gr", Kind: "spike", Recent: 200, Peak: 200}, "mail:out:a@x.gr", false) {
		t.Fatal("equal to its peak is not done before")
	}

	st = openTemp(t) // never opened: 150, 100, 50 in the three hours before now
	for i, n := range []int{150, 100, 50} {
		addOut(t, st, "b@x.gr", spikeT.Add(-time.Duration(3-i)*time.Hour), n)
	}
	if peaks, _ := st.peakWindows("outbound", []string{"b@x.gr"}, spikeT); peaks["b@x.gr"] != 0 {
		t.Fatalf("the incident's own first hours are not its peak: %+v", peaks)
	}
}

// Review of PR #1598: a sender alerted on (warning or critical) within the
// peak's days is never "done before" — its peak may be the thief's first
// wave. An info spike is not remembered.
func TestAlertedSpikeIsNeverDoneBefore(t *testing.T) {
	recordAbuse(t)
	T := spikeT
	p := &publisher{}
	w := abuseFinding{Type: TypeOutboundSpike, Severity: "warning", Key: "mail:out:a@x.gr", Message: "m", Expected: 8}
	i := abuseFinding{Type: TypeOutboundSpike, Severity: "info", Key: "mail:out:b@x.gr", Message: "m", Expected: 8}
	p.apply([]abuseFinding{w, i}, nil, T)
	if got := p.alertedSpikes(T); !got["mail:out:a@x.gr"] || got["mail:out:b@x.gr"] {
		t.Fatalf("an open warning is alerted, an info is not: %+v", got)
	}
	p.apply(nil, nil, T.Add(time.Hour)) // both resolved
	if got := p.alertedSpikes(T.Add(10 * 24 * time.Hour)); !got["mail:out:a@x.gr"] || got["mail:out:b@x.gr"] {
		t.Fatalf("remembered after it closed: %+v", got)
	}
	if got := p.alertedSpikes(T.Add(time.Hour + anomalyPeakDays*24*time.Hour)); got["mail:out:a@x.gr"] {
		t.Fatalf("forgotten after anomalyPeakDays: %+v", got)
	}

	tr := newTracker()
	tr.setAlerted(map[string]bool{"mail:out:a@x.gr": true})
	a := Anomaly{Addr: "a@x.gr", Kind: "spike", Recent: 100, Peak: 300}
	if tr.doneBefore(a, "mail:out:a@x.gr", false) || !tr.doneBefore(a, "mail:out:c@x.gr", false) {
		t.Fatal("only the alerted sender loses done-before")
	}
}

// Review of PR #1598: a spike sent from many addresses at once (a botnet with
// the password) is not volume only, and a hijack candidate's small spike is
// still a finding: it confirms the hijack.
func TestManyIPsAndHijackAreTells(t *testing.T) {
	stubGeo(t, func(string) (string, uint) { return "GR", 3 })
	st := spikeStore(t, "info@shop.gr")
	addOut(t, st, "info@shop.gr", spikeT.Add(-time.Hour), 60)
	tr := newTracker()
	for i := 0; i < spikeManyIPs; i++ {
		dovecotLogin(tr, "info@shop.gr", "imap", fmt.Sprintf("62.1.1.%d", i), spikeT)
	}
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil || f.Severity != "warning" || strings.Contains(f.Message, "volume only") {
		t.Fatalf("from %d addresses: a warning: %+v", spikeManyIPs, fs)
	}

	stubGeo(t, threeCountries)
	st = spikeStore(t, "info@shop.gr")
	addOut(t, st, "info@shop.gr", spikeT.Add(-time.Hour), 30) // under the floor
	tr = newTracker()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		dovecotLogin(tr, "info@shop.gr", "imap", ip, spikeT)
	}
	fs, _, _, _ = tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil {
		t.Fatalf("a hijack candidate's small spike is a finding: %+v", fs)
	}
	if h := onlyHijack(t, fs); h.Severity != "critical" {
		t.Fatalf("and it confirms the hijack: %+v", h)
	}
}

// Review of PR #1598: findings keep their order — spikes, then bounces /
// queue / blocklists, then hijacks.
func TestFindingOrder(t *testing.T) {
	stubGeo(t, threeCountries)
	st := spikeStore(t, "info@shop.gr")
	addOut(t, st, "info@shop.gr", spikeT.Add(-time.Hour), 60)
	tr := newTracker()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		dovecotLogin(tr, "info@shop.gr", "imap", ip, spikeT)
	}
	for i := 0; i < 40; i++ {
		tr.outcomes["auth:info@shop.gr"] = append(tr.outcomes["auth:info@shop.gr"], outcome{at: spikeT, bounced: true})
	}
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	var types []string
	for _, f := range fs {
		types = append(types, f.Type)
	}
	if strings.Join(types, ",") != TypeOutboundSpike+","+TypeBounceSpike+","+TypeHijack {
		t.Fatalf("order: %v", types)
	}
}

// A sender with no history is not stepped down: a dormant mailbox blasting
// is the strongest signal there is.
func TestNewSenderIsNotSteppedDown(t *testing.T) {
	st := openTemp(t)
	addOut(t, st, "old@shop.gr", spikeT.Add(-time.Hour), 120)
	tr := newTracker()
	fs, _, _, _ := tr.evaluateWith(st, spikeT, nil, nil)
	if f := outFinding(t, fs); f == nil || f.Severity != "warning" || strings.Contains(f.Message, "volume only") {
		t.Fatalf("a new sender at 120 is a warning: %+v", fs)
	}
}
