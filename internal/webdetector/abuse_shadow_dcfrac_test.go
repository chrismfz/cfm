package webdetector

import (
	"testing"
	"time"
)

// dcIPCountsAsDatacenter is the pure per-IP gating decision: count iff the IP is
// on a datacenter/cloud ASN AND is not an FCrDNS-verified good bot. The good-bot
// verdict is computed once by the emit (via the shared verdict cache) and passed
// in as a boolean, so this stays a trivially-testable rule with no DNS.
func TestDCIPCountsAsDatacenter(t *testing.T) {
	// AS16509 = AMAZON-02 (in the curated cloud map); AS3215 = a telco/residential
	// org name with no cloud keyword.
	const dcASN, dcName = 16509, "AMAZON-02"
	const resASN, resName = 3215, "Orange S.A."

	cases := []struct {
		name       string
		asn        uint
		asnName    string
		verifiedGB bool
		want       bool
	}{
		{"residential never counts", resASN, resName, false, false},
		{"residential is not rescued by a bot flag", resASN, resName, true, false},
		{"datacenter, not a verified bot, counts", dcASN, dcName, false, true},
		{"datacenter, verified good bot, excluded", dcASN, dcName, true, false},
	}
	for _, tc := range cases {
		got := dcIPCountsAsDatacenter(tc.asn, tc.asnName, tc.verifiedGB)
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
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
