package abuseshadow

import "testing"

// Verbatim shadow-log line shapes as emitted by logging.LogfABUSESHADOW
// (internal/webdetector/abuse_shadow.go), timestamp-prefixed.
const (
	lineOutlier1  = `2026-08-21 12:00:00 [abuse-shadow] signal=rate_outlier host=www.e-vafeiadis.gr ip=37.6.1.149 rps=0.517 median_rps=0.008 ratio=62.0 skew=62.0 reqs=62 asn=25472 provider=- good_bot=- verdict=would_challenge`
	lineOutlier2  = `2026-08-21 12:00:30 [abuse-shadow] signal=rate_outlier host=www.e-vafeiadis.gr ip=37.6.1.149 rps=0.600 median_rps=0.008 ratio=72.0 skew=70.0 reqs=72 asn=25472 provider=- good_bot=- verdict=would_challenge`
	lineDCOutlier = `2026-08-21 12:01:00 [abuse-shadow] signal=rate_outlier host=shop.example.gr ip=1.2.3.4 rps=2.0 median_rps=0.05 ratio=40.0 skew=30.0 reqs=240 asn=16509 provider=amazon-aws good_bot=- verdict=would_challenge`
	lineGoodbot   = `2026-08-21 12:02:00 [abuse-shadow] signal=rate_outlier host=shop.example.gr ip=66.249.73.237 rps=1.0 median_rps=0.05 ratio=20.0 skew=25.0 reqs=120 asn=15169 provider=google good_bot=googlebot verdict=exempt_goodbot`
	lineNoise     = `2026-08-21 12:03:00 [challenge][vhost] action=auto_on host=x`
)

func TestParse(t *testing.T) {
	e, ok := Parse(lineOutlier1)
	if !ok {
		t.Fatalf("expected a parsed entry")
	}
	if e.Host != "www.e-vafeiadis.gr" || e.IP != "37.6.1.149" || e.Reqs != 62 ||
		e.ASN != 25472 || e.Verdict != "would_challenge" || e.Ratio != 62.0 {
		t.Errorf("bad parse: %+v", e)
	}
	if e.Provider != "" || e.GoodBot != "" { // "-" normalizes to empty
		t.Errorf("dash should normalize to empty: provider=%q good_bot=%q", e.Provider, e.GoodBot)
	}

	dc, _ := Parse(lineDCOutlier)
	if dc.Provider != "amazon-aws" {
		t.Errorf("provider = %q, want amazon-aws", dc.Provider)
	}
	gb, _ := Parse(lineGoodbot)
	if gb.GoodBot != "googlebot" || gb.Verdict != "exempt_goodbot" {
		t.Errorf("good-bot parse: %+v", gb)
	}

	// A non-shadow line is rejected.
	if _, ok := Parse(lineNoise); ok {
		t.Errorf("non-shadow line must not parse")
	}
	if _, ok := Parse(""); ok {
		t.Errorf("empty line must not parse")
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]string{lineOutlier1, lineOutlier2, lineDCOutlier, lineGoodbot, lineNoise})

	if s.Total != 4 { // noise line excluded
		t.Fatalf("total = %d, want 4", s.Total)
	}
	if s.WouldChallenge != 3 || s.ExemptGoodbot != 1 {
		t.Errorf("verdicts: would=%d exempt=%d, want 3/1", s.WouldChallenge, s.ExemptGoodbot)
	}
	if s.UniqueHosts != 2 { // e-vafeiadis + shop.example
		t.Errorf("unique_hosts = %d, want 2", s.UniqueHosts)
	}
	if s.UniqueIPs != 3 { // 37.6.1.149, 1.2.3.4, 66.249.73.237
		t.Errorf("unique_ips = %d, want 3", s.UniqueIPs)
	}

	// The strongest would_challenge outlier ranks first (ratio 72 from the two
	// e-vafeiadis lines collapsed into one entity with hits=2).
	if len(s.TopWouldBlock) == 0 {
		t.Fatalf("no top would_challenge entities")
	}
	top := s.TopWouldBlock[0]
	if top.IP != "37.6.1.149" || top.Hits != 2 || top.MaxRatio != 72.0 || top.MaxReqs != 72 {
		t.Errorf("top entity = %+v, want ip 37.6.1.149 hits2 ratio72 reqs72", top)
	}

	// Provider split counts the datacenter would_challenge (amazon-aws), NOT the
	// exempted googlebot (that's an exemption, not a would_challenge).
	if len(s.ByProvider) != 1 || s.ByProvider[0].Key != "amazon-aws" || s.ByProvider[0].Count != 1 {
		t.Errorf("by_provider = %+v, want [{amazon-aws,1}]", s.ByProvider)
	}
	if len(s.ByGoodbot) != 1 || s.ByGoodbot[0].Key != "googlebot" {
		t.Errorf("by_good_bot = %+v, want [{googlebot,1}]", s.ByGoodbot)
	}
}
