package webdetector

import (
	"testing"
	"time"
)

// dcIPCountsAsDatacenter is the pure per-IP gating rule: count iff the IP is on a
// datacenter/cloud ASN AND is not an FCrDNS-verified good bot. Both inputs are
// booleans the emit computes once, so this is a trivially-testable 2×2 truth table
// with no DNS.
func TestDCIPCountsAsDatacenter(t *testing.T) {
	cases := []struct {
		isDC, verifiedGB, want bool
	}{
		{false, false, false}, // residential → never
		{false, true, false},  // residential + (nonsensical) bot flag → still never
		{true, false, true},   // datacenter, not a verified bot → counts
		{true, true, false},   // datacenter, verified good bot → excluded
	}
	for _, tc := range cases {
		if got := dcIPCountsAsDatacenter(tc.isDC, tc.verifiedGB); got != tc.want {
			t.Errorf("dcIPCountsAsDatacenter(%v,%v)=%v, want %v", tc.isDC, tc.verifiedGB, got, tc.want)
		}
	}
}

// The emit feeds dcIPCountsAsDatacenter with IsDatacenter's verdict; guard the ASN
// values Signal H relies on so a curated-map change can't silently flip the class.
func TestDCFrac_IsDatacenterAnchors(t *testing.T) {
	if !IsDatacenter(16509, "AMAZON-02") { // AWS — must classify as datacenter
		t.Error("AS16509 AMAZON-02 should be datacenter")
	}
	if IsDatacenter(3215, "Orange S.A.") { // a residential/telco org — must not
		t.Error("AS3215 Orange S.A. should NOT be datacenter")
	}
}

func TestDCFracShadowCfg_Defaults(t *testing.T) {
	e := &Engine{cfg: Config{}}
	c := e.dcFracShadowCfg()
	if c.MinFrac != 0.5 || c.MinReq != 50 || c.MinIPs != 5 {
		t.Fatalf("defaults: got %v/%d/%d, want 0.5/50/5", c.MinFrac, c.MinReq, c.MinIPs)
	}
	e2 := &Engine{cfg: Config{AbuseShadowDCFracMinFrac: 0.8, AbuseShadowDCFracMinReq: 100, AbuseShadowDCFracMinIPs: 10}}
	c2 := e2.dcFracShadowCfg()
	if c2.MinFrac != 0.8 || c2.MinReq != 100 || c2.MinIPs != 10 {
		t.Fatalf("explicit knobs not honoured: got %v/%d/%d", c2.MinFrac, c2.MinReq, c2.MinIPs)
	}
}

func TestDCFracMarks_MarkBulkGetExpiry(t *testing.T) {
	m := newDCFracMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }

	m.markBulk(map[string]int{"Shop.EXAMPLE": 73, "skip.com": 0, "": 1}, time.Minute)
	if got := m.get("shop.example"); got != 73 {
		t.Fatalf("fresh mark: got %d, want 73", got)
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

func TestDecorateDCFrac_StampsRows(t *testing.T) {
	ResetDCFracShadowMarks()
	defer ResetDCFracShadowMarks()
	MarkDCFracShadowBulk(map[string]int{"shop.example": 66}, time.Minute)

	short := decorateDCFracShort([]ShortRow{{Host: "shop.example"}, {Host: "quiet.example"}})
	if short[0].DCFraction != 66 || short[1].DCFraction != 0 {
		t.Fatalf("short decorate: got %d/%d, want 66/0", short[0].DCFraction, short[1].DCFraction)
	}
	susp := decorateDCFracSuspicious([]SuspiciousRow{{Host: "shop.example"}})
	if susp[0].DCFraction != 66 {
		t.Fatalf("suspicious decorate: got %d, want 66", susp[0].DCFraction)
	}
}
