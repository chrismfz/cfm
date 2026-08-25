package webdetector

import (
	"testing"
	"time"
)

// costOutlier: enough requests AND a high enough 5xx fraction AND an absolute
// 5xx-rps floor.
func TestCostOutlier_Verdict(t *testing.T) {
	c := costShadowCfg{MinFrac: 0.15, MinReq: 50, MinRPS: 1.0}

	cases := []struct {
		name   string
		total  int
		c5xx   int
		rps5xx float64
		want   bool
	}{
		// Origin collapse: half of a heavy load is 5xx.
		{"origin collapse", 1000, 500, 50, true},
		// Healthy origin: a trickle of 5xx well under the fraction floor.
		{"healthy", 1000, 5, 0.5, false},
		// High fraction but tiny sample — guarded by MinReq.
		{"tiny sample", 10, 8, 0.2, false},
		// High fraction, enough requests, but 5xx-rps below the absolute floor.
		{"below rps floor", 60, 12, 0.5, false},
		// Exactly at the fraction + rps floors is a hit (>=).
		{"at floors", 100, 15, 1.0, true},
		// Zero 5xx never flags.
		{"no 5xx", 1000, 0, 0, false},
	}
	for _, tc := range cases {
		if got := costOutlier(tc.total, tc.c5xx, tc.rps5xx, c); got != tc.want {
			t.Errorf("%s: costOutlier(%d,%d,%.2f)=%v, want %v",
				tc.name, tc.total, tc.c5xx, tc.rps5xx, got, tc.want)
		}
	}
}

func TestCostShadowCfg_Defaults(t *testing.T) {
	e := &Engine{cfg: Config{}}
	c := e.costShadowCfg()
	if c.MinFrac != 0.15 || c.MinReq != 50 || c.MinRPS != 1.0 {
		t.Fatalf("defaults: got frac=%v req=%d rps=%v, want 0.15/50/1.0", c.MinFrac, c.MinReq, c.MinRPS)
	}
	e2 := &Engine{cfg: Config{AbuseShadowCostMinFrac: 0.4, AbuseShadowCostMinReq: 200, AbuseShadowCostMinRPS: 5}}
	c2 := e2.costShadowCfg()
	if c2.MinFrac != 0.4 || c2.MinReq != 200 || c2.MinRPS != 5 {
		t.Fatalf("explicit knobs not honoured: got %v/%d/%v", c2.MinFrac, c2.MinReq, c2.MinRPS)
	}
}

func TestCostMarks_MarkBulkGetExpiry(t *testing.T) {
	m := newCostMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }

	m.markBulk(map[string]int{"Shop.EXAMPLE": 42, "skip.com": 0, "": 1}, time.Minute)
	if got := m.get("shop.example"); got != 42 {
		t.Fatalf("fresh mark: got %d, want 42", got)
	}
	if _, ok := m.hosts["skip.com"]; ok {
		t.Fatal("pct<=0 host should be skipped")
	}
	m.nowFn = func() time.Time { return base.Add(2 * time.Minute) }
	m.markBulk(map[string]int{"fresh.com": 9}, time.Minute)
	if _, ok := m.hosts["shop.example"]; ok {
		t.Fatal("markBulk did not prune the expired entry")
	}
	if n := len(m.hosts); n != 1 {
		t.Fatalf("store has %d entries, want 1", n)
	}
}

// End-to-end: a vhost whose origin is 5xx-collapsing under load gets badged with
// the 5xx percent; a healthy vhost does not. Exercises ingest→emit with the real
// per-bucket 5xx counters (no facet-style ingest state needed).
func TestCost_IngestEmit_Badge(t *testing.T) {
	ResetCostShadowMarks()
	defer ResetCostShadowMarks()
	e := NewEngine(Config{
		Every: 1 * time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowCost: true,
		AbuseShadowCostMinFrac: 0.15, AbuseShadowCostMinReq: 50, AbuseShadowCostMinRPS: 0.1,
	})
	now := float64(time.Now().Unix())
	const bad, good = "collapse.example", "healthy.example"

	// bad: 200 requests, 80 of them 500 (40% 5xx) — origin under pressure.
	for i := 0; i < 200; i++ {
		st := 200
		if i%5 < 2 { // 2 of every 5 → 40%
			st = 500
		}
		e.ingest(LogRec{TS: now + float64(i)*0.001, IP: "9.9.9.9", Host: bad,
			Method: "get", URI: "/p", Status: st}, "raw")
	}
	// good: 200 requests, all 200 OK.
	for i := 0; i < 200; i++ {
		e.ingest(LogRec{TS: now + float64(i)*0.001, IP: "8.8.8.8", Host: good,
			Method: "get", URI: "/p", Status: 200}, "raw")
	}

	e.emitAbuseShadowCostPressure(time.Now())

	if got := CostShadowPressure(bad); got != 40 {
		t.Errorf("bad vhost badge = %d%%, want 40%%", got)
	}
	if got := CostShadowPressure(good); got != 0 {
		t.Errorf("healthy vhost badge = %d, want 0", got)
	}
}

// The API decoration stamps the live percent onto rows (global store path).
func TestDecorateCost_StampsRows(t *testing.T) {
	ResetCostShadowMarks()
	defer ResetCostShadowMarks()
	MarkCostShadowBulk(map[string]int{"shop.example": 37}, time.Minute)

	short := decorateCostShort([]ShortRow{{Host: "shop.example"}, {Host: "quiet.example"}})
	if short[0].CostPressure != 37 || short[1].CostPressure != 0 {
		t.Fatalf("short decorate: got %d/%d, want 37/0", short[0].CostPressure, short[1].CostPressure)
	}
	susp := decorateCostSuspicious([]SuspiciousRow{{Host: "shop.example"}})
	if susp[0].CostPressure != 37 {
		t.Fatalf("suspicious decorate: got %d, want 37", susp[0].CostPressure)
	}
}
