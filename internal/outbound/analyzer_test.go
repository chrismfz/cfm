package outbound

import (
	"testing"
	"time"
)

func newTestRuntime() Runtime {
	return Runtime{
		Window:             60 * time.Second,
		SMTPPerWindow:      3,
		UniqueDstPerWindow: 4,
		HTTPPerWindow:      5,
		DNSPerWindow:       5,
		DedupCooldown:      30 * time.Second,
		QueueSampleLimit:   3,
		NotifySeverity:     "warning",
		DNSUniqDstMin:      2,
		DNSSeverityMode:    "volume+dispersion",
		SMTPPorts:          map[uint16]struct{}{25: {}, 465: {}, 587: {}},
		ScanPorts:          map[uint16]struct{}{22: {}, 23: {}, 3389: {}},
		HTTPPorts:          map[uint16]struct{}{80: {}, 443: {}},
		AllowUIDs:          map[uint32]struct{}{},
		AllowGIDs:          map[uint32]struct{}{},
	}
}

func mkEvent(t time.Time, uid uint32, sig Signal, dport uint16, dstByte byte) Event {
	var dst [16]byte
	dst[12] = 10
	dst[13] = 0
	dst[14] = 0
	dst[15] = dstByte
	return Event{
		When:   t,
		UID:    uid,
		GID:    1000,
		IPVer:  4,
		DstIP:  dst,
		SPort:  40000,
		DPort:  dport,
		Signal: sig,
	}
}

func TestAnalyzer_TripsOnThreshold(t *testing.T) {
	a := NewAnalyzer(newTestRuntime())
	now := time.Now()

	// 2 hits below threshold (3) — no verdict.
	for i := 0; i < 2; i++ {
		if v := a.Observe(mkEvent(now.Add(time.Duration(i)*time.Second), 1001, SignalSMTP, 25, byte(i))); v != nil {
			t.Fatalf("unexpected verdict at i=%d: %+v", i, v)
		}
	}
	// 3rd hit trips.
	v := a.Observe(mkEvent(now.Add(2*time.Second), 1001, SignalSMTP, 25, 3))
	if v == nil {
		t.Fatal("expected verdict on 3rd SMTP hit")
	}
	if v.Signal != SignalSMTP || v.Count != 3 || v.Threshold != 3 {
		t.Fatalf("bad verdict: %+v", v)
	}
}

func TestAnalyzer_Dedup(t *testing.T) {
	rt := newTestRuntime()
	a := NewAnalyzer(rt)
	now := time.Now()

	// Trip
	for i := 0; i < 3; i++ {
		a.Observe(mkEvent(now.Add(time.Duration(i)*time.Second), 1002, SignalSMTP, 25, byte(i)))
	}
	// Within dedup cooldown — must not re-emit.
	if v := a.Observe(mkEvent(now.Add(4*time.Second), 1002, SignalSMTP, 25, 4)); v != nil {
		t.Fatalf("dedup violated: %+v", v)
	}
	// Past dedup cooldown — must re-emit.
	later := now.Add(rt.DedupCooldown).Add(2 * time.Second)
	if v := a.Observe(mkEvent(later, 1002, SignalSMTP, 25, 5)); v == nil {
		t.Fatal("expected re-emit after dedup cooldown")
	}
}

func TestAnalyzer_WindowSlides(t *testing.T) {
	rt := newTestRuntime()
	a := NewAnalyzer(rt)
	t0 := time.Now()

	// 2 hits well in the past.
	for i := 0; i < 2; i++ {
		a.Observe(mkEvent(t0, 1003, SignalSMTP, 25, byte(i)))
	}
	// 1 hit far in the future — should slide window so old hits expire.
	v := a.Observe(mkEvent(t0.Add(2*rt.Window), 1003, SignalSMTP, 25, 9))
	if v != nil {
		t.Fatalf("window did not slide; got verdict: %+v", v)
	}
}

func TestAnalyzer_AllowList(t *testing.T) {
	rt := newTestRuntime()
	rt.AllowUIDs = map[uint32]struct{}{99: {}}
	a := NewAnalyzer(rt)

	if !a.IsAllowed(0, 0) {
		t.Fatal("uid 0 must always be allowed")
	}
	if !a.IsAllowed(99, 0) {
		t.Fatal("explicit allow uid not honored")
	}
	if a.IsAllowed(1234, 0) {
		t.Fatal("unrelated uid should not be allowed")
	}
}

func TestAnalyzer_UniqDstSideChannel(t *testing.T) {
	// Even if SMTP threshold isn't met, hitting many distinct dst IPs should
	// trip UNIQDST (horizontal scanner pattern).
	rt := newTestRuntime()
	rt.SMTPPerWindow = 100 // can't trip via count
	rt.UniqueDstPerWindow = 3
	a := NewAnalyzer(rt)
	now := time.Now()

	a.Observe(mkEvent(now, 1004, SignalSMTP, 25, 1))
	a.Observe(mkEvent(now.Add(time.Second), 1004, SignalSMTP, 25, 2))
	v := a.Observe(mkEvent(now.Add(2*time.Second), 1004, SignalSMTP, 25, 3))
	if v == nil {
		t.Fatal("expected uniq-dst verdict")
	}
	if v.Signal != SignalUNIQDST {
		t.Fatalf("expected UNIQDST signal, got %s", v.Signal)
	}
	if v.UniqueDsts < 3 {
		t.Fatalf("uniq_dst count low: %+v", v)
	}
}

func TestAnalyzer_DNSLowDispersionDemotesSeverity(t *testing.T) {
	rt := newTestRuntime()
	rt.DNSPerWindow = 3
	rt.NotifySeverity = "warning"
	rt.DNSUniqDstMin = 2
	rt.DNSSeverityMode = "volume+dispersion"
	a := NewAnalyzer(rt)
	now := time.Now()

	// All DNS hits go to the same resolver -> low dispersion.
	for i := 0; i < 2; i++ {
		if v := a.Observe(mkEvent(now.Add(time.Duration(i)*time.Second), 2001, SignalDNS, 53, 9)); v != nil {
			t.Fatalf("unexpected early verdict: %+v", v)
		}
	}
	v := a.Observe(mkEvent(now.Add(3*time.Second), 2001, SignalDNS, 53, 9))
	if v == nil {
		t.Fatal("expected dns verdict")
	}
	if v.Severity != "info" {
		t.Fatalf("expected demoted severity, got %q", v.Severity)
	}
}

func TestAnalyzer_DNSDispersionKeepsConfiguredSeverity(t *testing.T) {
	rt := newTestRuntime()
	rt.DNSPerWindow = 3
	rt.NotifySeverity = "warning"
	rt.DNSUniqDstMin = 2
	rt.DNSSeverityMode = "volume+dispersion"
	a := NewAnalyzer(rt)
	now := time.Now()

	for i := 0; i < 2; i++ {
		a.Observe(mkEvent(now.Add(time.Duration(i)*time.Second), 2002, SignalDNS, 53, byte(i+1)))
	}
	v := a.Observe(mkEvent(now.Add(3*time.Second), 2002, SignalDNS, 53, 9))
	if v == nil {
		t.Fatal("expected dns verdict")
	}
	if v.Severity != "warning" {
		t.Fatalf("expected configured severity, got %q", v.Severity)
	}
	if v.DNS.UniqueResolvers < 2 {
		t.Fatalf("expected resolver dispersion in verdict: %+v", v.DNS)
	}
}
