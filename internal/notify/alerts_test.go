package notify

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/alerts"
)

// recordingChannel accepts every event except WAF/SQLI, which it fails like a
// broken SMTP server would.
type recordingChannel struct{ sent int }

func (c *recordingChannel) Name() string { return "rec" }
func (c *recordingChannel) Send(ev Event, _ string, _ string) error {
	c.sent++
	if ev.Kind == "WAF/SQLI" {
		return errors.New("smtp down")
	}
	return nil
}

// installTestConfig swaps the package notifier state for one test.
func installTestConfig(t *testing.T, c *config) {
	t.Helper()
	cfgMu.Lock()
	prevCfg := cfg
	cfg = c
	cfgMu.Unlock()
	prevDedup := dedup
	dedup = newDeduper(time.Minute)
	t.Cleanup(func() {
		cfgMu.Lock()
		cfg = prevCfg
		cfgMu.Unlock()
		dedup = prevDedup
	})
}

func installTestStore(t *testing.T) *alerts.Store {
	t.Helper()
	s, err := alerts.Open(filepath.Join(t.TempDir(), "alerts.db"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	prev := alerts.SetDefault(s)
	t.Cleanup(func() { alerts.SetDefault(prev); s.Close() })
	return s
}

// Every event lands in the alert store with what the notifier did about it,
// including the ones it never sent: the store must not depend on mail being set up.
func TestEmitRecordsEveryOutcome(t *testing.T) {
	s := installTestStore(t)
	ch := &recordingChannel{}
	installTestConfig(t, &config{
		Enabled:   true,
		DedupeKey: "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}",
		DedupeTTL: time.Minute,
		Channels:  []Channel{ch},
		Detectors: map[string]detectorOverride{
			"mysql/governor": {Notify: false},
			"clam/down":      {Notify: true, MinSeverity: "critical"},
			"clam/up":        {Notify: true, MinSeverity: "info"},
			"ssh/authfail":   {Notify: true, Channels: []string{"nonexistent"}},
		},
	})

	ev := Event{Host: "orion.example", Kind: "WAF/SQLI", SrcIP: "31.217.169.106", Reason: "WAF/SQLI", Severity: "warn",
		TTL: 15 * time.Minute, Samples: []string{"[waf] reason=WAF_SQLI host=shop.example.gr uri=/"}, Extra: map[string]string{"mode": "ttl"}}
	if err := Emit(ev); err == nil {
		t.Fatal("channel error not returned")
	}
	_ = Emit(ev) // same dedupe key
	_ = Emit(Event{Kind: "MYSQL/GOVERNOR", Reason: "long query"})
	_ = Emit(Event{Kind: "CLAM/DOWN", Reason: "clamd unreachable", Severity: "warning"})
	_ = Emit(Event{Kind: "SSH/AUTHFAIL", SrcIP: "198.51.100.4", Reason: "authfail"})
	if err := Emit(Event{Kind: "WEB/MALPATH", SrcIP: "34.156.121.46", Reason: "WEB/MALPATH"}); err != nil {
		t.Fatal(err)
	}
	// no severity at all ranks as info, so a min_severity=info override still sends it
	_ = Emit(Event{Kind: "CLAM/UP", Reason: "clamd recovered"})

	installTestConfig(t, &config{Enabled: false})
	_ = Emit(Event{Kind: "PORTSCAN", SrcIP: "203.0.113.5", Reason: "portscan 8 ports"})

	s.Flush()
	page, err := s.List(alerts.Filter{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, r := range page.Rows {
		got[r.Kind] = append(got[r.Kind], r.Delivery)
	}
	want := map[string][]string{
		"WAF/SQLI":       {alerts.DeliveryDeduped, alerts.DeliverySendFailed},
		"WEB/MALPATH":    {alerts.DeliveryNotified},
		"CLAM/UP":        {alerts.DeliveryNotified},
		"MYSQL/GOVERNOR": {alerts.DeliveryMuted},
		"CLAM/DOWN":      {alerts.DeliveryBelowSeverity},
		"SSH/AUTHFAIL":   {alerts.DeliveryNoChannels},
		"PORTSCAN":       {alerts.DeliveryNotifierOff},
	}
	for kind, w := range want {
		g := got[kind]
		if len(g) != len(w) {
			t.Fatalf("%s: deliveries %v, want %v (all: %v)", kind, g, w, got)
		}
		for _, d := range w {
			found := false
			for _, x := range g {
				found = found || x == d
			}
			if !found {
				t.Fatalf("%s: deliveries %v, want %v", kind, g, w)
			}
		}
	}
	if ch.sent != 3 {
		t.Fatalf("channel sent %d times, want 3", ch.sent)
	}

	waf, _ := s.List(alerts.Filter{Kinds: []string{"WAF/SQLI"}, Deliveries: []string{alerts.DeliverySendFailed}}, 1)
	r := waf.Rows[0]
	if r.Host != "orion.example" || r.IP != "31.217.169.106" || r.TTLSec != 900 || r.Mode != "ttl" ||
		r.Vhost != "shop.example.gr" || r.EventID == "" || r.Severity != "warning" {
		t.Fatalf("recorded row: %+v", r)
	}
}

// With no store open (tests, a node whose store failed) Emit behaves as before.
func TestEmitWithoutStore(t *testing.T) {
	prev := alerts.SetDefault(nil)
	defer alerts.SetDefault(prev)
	installTestConfig(t, &config{Enabled: false})
	if err := Emit(Event{Kind: "WAF/SQLI"}); err != nil {
		t.Fatal(err)
	}
}

// Events recorded on Enqueue's own paths (here: the notifier never started)
// carry the configured hostname_override, like the ones Emit records.
func TestEnqueuePathUsesHostnameOverride(t *testing.T) {
	s := installTestStore(t)
	cfgMu.Lock()
	prevQ, prevHost := queueCh, hostname
	queueCh, hostname = nil, "orion.override"
	cfgMu.Unlock()
	defer func() {
		cfgMu.Lock()
		queueCh, hostname = prevQ, prevHost
		cfgMu.Unlock()
	}()
	Enqueue(Event{Kind: "PORTSCAN", SrcIP: "203.0.113.5", Reason: "portscan"})
	s.Flush()
	page, _ := s.List(alerts.Filter{}, 5)
	if len(page.Rows) != 1 || page.Rows[0].Host != "orion.override" || page.Rows[0].Delivery != alerts.DeliveryNotifierOff {
		t.Fatalf("rows: %+v", page.Rows)
	}
}
