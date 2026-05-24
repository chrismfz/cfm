package webdetector

import (
	"testing"
	"time"
)

func TestUATop_AggregatesAcrossVhosts(t *testing.T) {
	e := NewEngine(Config{
		Every:                 5 * time.Second,
		Window:                2 * time.Minute,
		UAEmergencyStorePath:  t.TempDir() + "/r.json",
		UAEmergencyAuditLog:   t.TempDir() + "/a.log",
		TrafficRulesStorePath: t.TempDir() + "/tr.json",
	})

	// UA aggregation is gated on UAEmergency().HasActive() — the lazy-
	// activation design means an idle box pays zero ingest cost. Install
	// a no-op rule to enable aggregation for this test.
	if _, err := e.UAEmergency().Set("_test_enable_aggregation",
		UAActionThrottle, "test", "", 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	now := float64(time.Now().Unix())

	// facebookexternalhit hits 3 vhosts from 2 IPs.
	for i, vh := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		for _, ip := range []string{"57.141.20.1", "57.141.20.2"} {
			e.ingest(LogRec{
				TS:     now + float64(i),
				IP:     ip,
				Host:   vh,
				Method: "get",
				URI:    "/og",
				Status: 200,
				UA:     "facebookexternalhit/1.1",
			}, "raw")
		}
	}
	// semrushbot hits 1 vhost from 1 IP, fewer requests.
	for i := 0; i < 4; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "85.208.96.200",
			Host:   "a.example.com",
			Method: "get",
			URI:    "/",
			Status: 200,
			UA:     "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
		}, "raw")
	}

	rows := e.UATop(10)
	if len(rows) < 2 {
		t.Fatalf("expected at least 2 UA rows, got %d", len(rows))
	}

	// Sorted by reqs desc, so facebookexternalhit should be first.
	if rows[0].UA != "facebookexternalhit" {
		t.Errorf("row[0].UA = %q, want facebookexternalhit", rows[0].UA)
	}
	if rows[0].Vhosts != 3 {
		t.Errorf("row[0].Vhosts = %d, want 3", rows[0].Vhosts)
	}
	if rows[0].UniqueIPs != 2 {
		t.Errorf("row[0].UniqueIPs = %d, want 2", rows[0].UniqueIPs)
	}
	if rows[0].Reqs != 6 {
		t.Errorf("row[0].Reqs = %d, want 6", rows[0].Reqs)
	}

	// Find semrushbot row.
	var sem *UATopRow
	for i := range rows {
		if rows[i].UA == "semrushbot" {
			sem = &rows[i]
			break
		}
	}
	if sem == nil {
		t.Fatal("semrushbot row missing")
	}
	if sem.Vhosts != 1 || sem.UniqueIPs != 1 || sem.Reqs != 4 {
		t.Errorf("semrushbot row = %+v", *sem)
	}
}

func TestUATop_IgnoresEmptyUA(t *testing.T) {
	e := NewEngine(Config{
		Every:                 5 * time.Second,
		Window:                2 * time.Minute,
		UAEmergencyStorePath:  t.TempDir() + "/r.json",
		UAEmergencyAuditLog:   t.TempDir() + "/a.log",
		TrafficRulesStorePath: t.TempDir() + "/tr.json",
	})
	now := float64(time.Now().Unix())
	e.ingest(LogRec{TS: now, IP: "1.1.1.1", Host: "x.com", Method: "get", URI: "/", Status: 200, UA: ""}, "raw")
	e.ingest(LogRec{TS: now, IP: "1.1.1.1", Host: "x.com", Method: "get", URI: "/", Status: 200, UA: "-"}, "raw")
	rows := e.UATop(10)
	for _, r := range rows {
		if r.UA == "" || r.UA == "-" {
			t.Errorf("empty/dash UA leaked into rows: %+v", r)
		}
	}
}

func TestUADrill_BreakdownsPresent(t *testing.T) {
	e := NewEngine(Config{
		Every:                 5 * time.Second,
		Window:                2 * time.Minute,
		UAEmergencyStorePath:  t.TempDir() + "/r.json",
		UAEmergencyAuditLog:   t.TempDir() + "/a.log",
		TrafficRulesStorePath: t.TempDir() + "/tr.json",
	})
	// UA aggregation is gated on UAEmergency().HasActive() — install a
	// dummy rule so the ingest path populates the per-UA maps.
	if _, err := e.UAEmergency().Set("_test_enable_aggregation",
		UAActionThrottle, "test", "", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	now := float64(time.Now().Unix())
	// Same normalized UA, three raw variants — should be collapsed.
	variants := []string{
		"facebookexternalhit/1.1",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"facebookexternalhit/1.2",
	}
	for i, v := range variants {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "57.141.20.7",
			Host:   "site.example.com",
			Method: "get",
			URI:    "/og",
			Status: 200,
			UA:     v,
		}, "raw")
	}

	d := e.UADrill("facebookexternalhit")
	if d.UA != "facebookexternalhit" {
		t.Errorf("drill UA = %q", d.UA)
	}
	if d.Reqs != 3 {
		t.Errorf("Reqs = %d, want 3", d.Reqs)
	}
	if d.Vhosts != 1 {
		t.Errorf("Vhosts = %d, want 1", d.Vhosts)
	}
	if len(d.TopRawUAs) < 1 {
		t.Errorf("TopRawUAs empty")
	}
	// TopRawUAs should include the lowercased raw variants.
	seen := make(map[string]bool)
	for _, kv := range d.TopRawUAs {
		seen[kv.Key] = true
	}
	if !seen["facebookexternalhit/1.1"] {
		t.Errorf("TopRawUAs missing variant: %+v", d.TopRawUAs)
	}
}

func TestIsGoogleVerifiedBot(t *testing.T) {
	cases := map[string]bool{
		"googlebot":             true,
		"GoogleBot":             true,
		"adsbot-google":         true,
		"mediapartners-google":  true,
		"facebookexternalhit":   false,
		"semrushbot":            false,
		"":                      false,
	}
	for in, want := range cases {
		if got := IsGoogleVerifiedBot(in); got != want {
			t.Errorf("IsGoogleVerifiedBot(%q) = %v, want %v", in, got, want)
		}
	}
}
