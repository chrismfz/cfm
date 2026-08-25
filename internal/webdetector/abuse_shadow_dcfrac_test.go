package webdetector

import (
	"testing"
	"time"
)

// dcIPCountsAsDatacenter is the pure per-IP gating decision. A well-known cloud
// ASN counts; a residential ASN never does; a good-bot PTR is excluded per the
// FCrDNS verifier's verdict; and when the verifier is nil (budget exhausted) a
// good-bot-looking PTR is given the benefit of the doubt (excluded, safe).
func TestDCIPCountsAsDatacenter(t *testing.T) {
	// AS16509 = AMAZON-02 (in the curated cloud map); AS3215 = a telco/residential
	// org name with no cloud keyword.
	const dcASN, dcName = 16509, "AMAZON-02"
	const resASN, resName = 3215, "Orange S.A."

	always := func(string, string) bool { return true } // FCrDNS says "verified good bot"
	never := func(string, string) bool { return false } // FCrDNS says "spoofed / not a bot"

	cases := []struct {
		name    string
		asn     uint
		asnName string
		ptr     string
		verify  func(string, string) bool
		want    bool
	}{
		{"residential never counts", resASN, resName, "", never, false},
		{"datacenter plain counts", dcASN, dcName, "host.compute.amazonaws.com", never, true},
		{"datacenter no ptr counts", dcASN, dcName, "", nil, true},
		// A good-bot-looking PTR on a datacenter IP, verified → excluded.
		{"verified good bot excluded", dcASN, dcName, "crawl-66-x.googlebot.com", always, false},
		// Same, but FCrDNS fails (spoofed PTR) → counted as datacenter.
		{"spoofed good bot counted", dcASN, dcName, "fake.googlebot.com", never, true},
		// Good-bot-looking PTR but no budget to verify (verify==nil) → benefit of
		// the doubt, excluded (false-negative safe direction).
		{"unverifiable good bot excluded", dcASN, dcName, "crawl-66-x.googlebot.com", nil, false},
	}
	for _, tc := range cases {
		got := dcIPCountsAsDatacenter(tc.asn, tc.asnName, tc.ptr, "1.2.3.4", tc.verify)
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
