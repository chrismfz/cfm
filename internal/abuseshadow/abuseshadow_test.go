package abuseshadow

import "testing"

// Verbatim shadow-log line shapes as emitted by logging.LogfABUSESHADOW
// (internal/webdetector/abuse_shadow.go), timestamp-prefixed.
const (
	lineOutlier1  = `2026-08-21 12:00:00 [abuse-shadow] signal=rate_outlier host=www.e-vafeiadis.gr ip=37.6.1.149 rps=0.517 median_rps=0.008 ratio=62.0 skew=62.0 reqs=62 asn=25472 cc=GR provider=- good_bot=- verdict=would_challenge`
	lineOutlier2  = `2026-08-21 12:00:30 [abuse-shadow] signal=rate_outlier host=www.e-vafeiadis.gr ip=37.6.1.149 rps=0.600 median_rps=0.008 ratio=72.0 skew=70.0 reqs=72 asn=25472 cc=GR provider=- good_bot=- verdict=would_challenge`
	lineDCOutlier = `2026-08-21 12:01:00 [abuse-shadow] signal=rate_outlier host=shop.example.gr ip=1.2.3.4 rps=2.0 median_rps=0.05 ratio=40.0 skew=30.0 reqs=240 asn=16509 cc=US provider=amazon-aws good_bot=- verdict=would_challenge`
	lineGoodbot   = `2026-08-21 12:02:00 [abuse-shadow] signal=rate_outlier host=shop.example.gr ip=66.249.73.237 rps=1.0 median_rps=0.05 ratio=20.0 skew=25.0 reqs=120 asn=15169 cc=US provider=google good_bot=googlebot verdict=exempt_goodbot`
	lineNoise     = `2026-08-21 12:03:00 [challenge][vhost] action=auto_on host=x`

	// Per-vhost signal lines (facet/cost/dc). Verbatim shapes from
	// abuse_shadow_facet.go / _cost.go / _dcfrac.go — no ip= field, verdict=would_shadow.
	lineFacet1 = `2026-08-21 12:04:00 [abuse-shadow] signal=facet_expansion host=shop.example.gr urls=805 paths=12 expansion=67.1 repeat=1.05 reqs=830 verdict=would_shadow`
	lineFacet2 = `2026-08-21 12:04:30 [abuse-shadow] signal=facet_expansion host=shop.example.gr urls=910 paths=13 expansion=70.5 repeat=1.08 reqs=940 verdict=would_shadow`
	lineCost1  = `2026-08-21 12:05:00 [abuse-shadow] signal=cost_pressure host=slow.example.gr rps5xx=1.200 frac5xx=0.450 rt_avg=2.100 reqs=300 fails=135 verdict=would_shadow`
	lineCost2  = `2026-08-21 12:05:30 [abuse-shadow] signal=cost_pressure host=slow.example.gr rps5xx=1.500 frac5xx=0.600 rt_avg=2.400 reqs=350 fails=210 verdict=would_shadow`
	lineDC1    = `2026-08-21 12:06:00 [abuse-shadow] signal=dc_fraction host=dc.example.gr dc_frac=0.900 dc_reqs=540 dc_ips=18 total_reqs=600 total_ips=20 verdict=would_shadow`
	lineDC2    = `2026-08-21 12:06:30 [abuse-shadow] signal=dc_fraction host=dc.example.gr dc_frac=0.950 dc_reqs=570 dc_ips=19 total_reqs=600 total_ips=20 verdict=would_shadow`

	// dc_fraction ALSO emits two verdict-less OPERATIONAL lines to the same log.
	// They must NOT be counted (they carry no decision): the verified_crawler note
	// even parses a malformed ip=…) with a trailing paren.
	lineDCVerified = `2026-08-21 12:07:00 [abuse-shadow] signal=dc_fraction verified_crawler="googlebot.com" excluded_from_datacenter_count (per-IP FCrDNS; e.g. ip=66.249.73.237)`
	lineDCDeferred = `2026-08-21 12:07:30 [abuse-shadow] signal=dc_fraction deferred_vhosts=4 reason=ip_enrich_budget`

	// Per-IP challenge_score lines. Verbatim shape from emitChallengeScoreShadow
	// (internal/webdetector/challenge_score.go): host-less, own verdict space
	// (would_harden/would_deny), fp="-" when no X-CFM-TLS stamp; plus the store-cap
	// NOTE line (note=store_cap_reached, dropped=N, verdict=would_shadow).
	lineCS_deny1 = `2026-08-21 12:08:00 [abuse-shadow] signal=challenge_score ip=203.0.113.10 fp=c28caa00 score=618.2 solves=40 fast=2 uaimp=0 farm=5 farmfp=30 verdict=would_deny`
	lineCS_deny2 = `2026-08-21 12:08:30 [abuse-shadow] signal=challenge_score ip=203.0.113.10 fp=c28caa00 score=120.0 solves=41 fast=2 uaimp=0 farm=5 farmfp=31 verdict=would_deny`
	lineCS_hard1 = `2026-08-21 12:09:00 [abuse-shadow] signal=challenge_score ip=203.0.113.11 fp=c28caa00 score=55.0 solves=3 fast=0 uaimp=0 farm=0 farmfp=1 verdict=would_harden`
	lineCS_hard2 = `2026-08-21 12:09:30 [abuse-shadow] signal=challenge_score ip=203.0.113.12 fp=- score=52.0 solves=2 fast=0 uaimp=1 farm=0 farmfp=0 verdict=would_harden`
	lineCS_note  = `2026-08-21 12:10:00 [abuse-shadow] signal=challenge_score note=store_cap_reached cap=10000 dropped=7 verdict=would_shadow`
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
	if e.CC != "GR" {
		t.Errorf("cc = %q, want GR", e.CC)
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

	// Country split counts would_challenge only: GR twice (the two e-vafeiadis
	// lines) and US once (the amazon-aws DC). The exempted googlebot (US) is an
	// exemption, not a would_challenge, so it must NOT appear.
	if len(s.ByCountry) != 2 {
		t.Fatalf("by_country = %+v, want 2 entries (GR, US)", s.ByCountry)
	}
	if s.ByCountry[0].Key != "GR" || s.ByCountry[0].Count != 2 {
		t.Errorf("by_country[0] = %+v, want {GR,2}", s.ByCountry[0])
	}
	if s.ByCountry[1].Key != "US" || s.ByCountry[1].Count != 1 {
		t.Errorf("by_country[1] = %+v, want {US,1}", s.ByCountry[1])
	}
	if top.CC != "GR" {
		t.Errorf("top entity cc = %q, want GR", top.CC)
	}
}

// TestParsePerSignal locks the per-vhost signal line shapes: the facet/cost/dc
// keys parse and the ip/ratio/provider keys stay zero (these lines carry none).
func TestParsePerSignal(t *testing.T) {
	f, ok := Parse(lineFacet1)
	if !ok || f.Signal != "facet_expansion" {
		t.Fatalf("facet parse: %+v ok=%v", f, ok)
	}
	if f.Urls != 805 || f.Paths != 12 || f.Expansion != 67.1 || f.Reqs != 830 || f.Verdict != "would_shadow" {
		t.Errorf("facet fields = %+v, want urls805 paths12 expansion67.1 reqs830 would_shadow", f)
	}
	if f.IP != "" || f.Ratio != 0 || f.Provider != "" {
		t.Errorf("facet line must not carry ip/ratio/provider: %+v", f)
	}

	c, _ := Parse(lineCost1)
	if c.Signal != "cost_pressure" || c.Frac5xx != 0.450 || c.Reqs != 300 {
		t.Errorf("cost fields = %+v, want cost_pressure frac5xx0.45 reqs300", c)
	}

	d, _ := Parse(lineDC1)
	if d.Signal != "dc_fraction" || d.DCFrac != 0.900 || d.DCReqs != 540 || d.DCIPs != 18 {
		t.Errorf("dc fields = %+v, want dc_fraction dc_frac0.9 dc_reqs540 dc_ips18", d)
	}
}

// TestSummarizePerSignal locks the per-vhost top lists: each signal groups by
// host and keeps the PEAK metric across the window's firings (two lines each,
// the second stronger).
func TestSummarizePerSignal(t *testing.T) {
	s := Summarize([]string{
		lineFacet1, lineFacet2, lineCost1, lineCost2, lineDC1, lineDC2, lineNoise,
	})

	// would_shadow lines still parse (Total) but are neither would_challenge nor
	// exempt_goodbot, so those counters stay zero.
	if s.Total != 6 {
		t.Fatalf("total = %d, want 6", s.Total)
	}
	if s.WouldChallenge != 0 || s.ExemptGoodbot != 0 {
		t.Errorf("would_shadow lines must not count as challenge/exempt: would=%d exempt=%d", s.WouldChallenge, s.ExemptGoodbot)
	}
	if s.UniqueIPs != 0 {
		t.Errorf("per-signal lines carry no ip=, unique_ips = %d, want 0", s.UniqueIPs)
	}

	if len(s.TopFacet) != 1 {
		t.Fatalf("top_facet = %+v, want 1 host", s.TopFacet)
	}
	if f := s.TopFacet[0]; f.Host != "shop.example.gr" || f.Hits != 2 || f.Expansion != 70.5 || f.Urls != 910 {
		t.Errorf("top_facet[0] = %+v, want shop hits2 expansion70.5 urls910 (peak)", f)
	}

	if len(s.TopCost) != 1 || s.TopCost[0].Frac5xx != 0.600 || s.TopCost[0].Hits != 2 {
		t.Errorf("top_cost = %+v, want slow frac5xx0.6 hits2 (peak)", s.TopCost)
	}

	if len(s.TopDC) != 1 {
		t.Fatalf("top_dc = %+v, want 1 host", s.TopDC)
	}
	if d := s.TopDC[0]; d.DCFrac != 0.950 || d.DCReqs != 570 || d.DCIPs != 19 || d.Hits != 2 {
		t.Errorf("top_dc[0] = %+v, want dc_frac0.95 dc_reqs570 dc_ips19 hits2 (peak)", d)
	}
}

// TestParseChallengeScore locks the per-IP challenge_score line shape: the fp/score/
// tell keys parse, fp="-" normalizes to empty, and the store-cap note line yields
// note/dropped without a decision verdict.
func TestParseChallengeScore(t *testing.T) {
	e, ok := Parse(lineCS_deny1)
	if !ok || e.Signal != "challenge_score" {
		t.Fatalf("challenge_score parse: %+v ok=%v", e, ok)
	}
	if e.IP != "203.0.113.10" || e.FP != "c28caa00" || e.Score != 618.2 ||
		e.Solves != 40 || e.Fast != 2 || e.UAImp != 0 || e.Farm != 5 || e.FarmFP != 30 ||
		e.Verdict != "would_deny" {
		t.Errorf("challenge_score fields = %+v", e)
	}
	// challenge_score lines carry none of the rate-outlier / vhost keys.
	if e.Host != "" || e.Ratio != 0 || e.DCFrac != 0 {
		t.Errorf("challenge_score line must not carry host/ratio/dc keys: %+v", e)
	}
	// fp="-" normalizes to empty (no X-CFM-TLS stamp).
	if h, _ := Parse(lineCS_hard2); h.FP != "" {
		t.Errorf("fp=- must normalize to empty, got %q", h.FP)
	}
	// The store-cap note line carries note + dropped, no decision verdict.
	n, _ := Parse(lineCS_note)
	if n.Note != "store_cap_reached" || n.Dropped != 7 {
		t.Errorf("note line = %+v, want note=store_cap_reached dropped=7", n)
	}
}

// TestSummarizeChallengeScore locks the dedicated challenge_score section: the
// would_harden soft rung is counted (it is invisible to detection_history), the
// per-fp footprint carries the convicted flag + distinct IPs, top offenders keep the
// PEAK-score line per IP, and the store-cap note contributes only `dropped`.
func TestSummarizeChallengeScore(t *testing.T) {
	s := Summarize([]string{
		lineCS_deny1, lineCS_deny2, lineCS_hard1, lineCS_hard2, lineCS_note, lineNoise,
	})

	cs := s.ChallengeScore
	if cs == nil {
		t.Fatalf("challenge_score section missing")
	}
	if cs.Lines != 4 || cs.WouldHarden != 2 || cs.WouldDeny != 2 {
		t.Errorf("counts = lines%d harden%d deny%d, want 4/2/2", cs.Lines, cs.WouldHarden, cs.WouldDeny)
	}
	if cs.Dropped != 7 {
		t.Errorf("dropped = %d, want 7 (from the note line, not a decision)", cs.Dropped)
	}
	if cs.DistinctIPs != 3 { // .10, .11, .12
		t.Errorf("distinct_ips = %d, want 3", cs.DistinctIPs)
	}
	if cs.DistinctFPs != 1 { // c28caa00 only — the "-" fp is excluded
		t.Errorf("distinct_fps = %d, want 1", cs.DistinctFPs)
	}
	if cs.MaxScore != 618.2 {
		t.Errorf("max_score = %v, want 618.2", cs.MaxScore)
	}

	// by_fp: c28caa00 first (3 lines), then (none) (1 line).
	if len(cs.ByFP) != 2 {
		t.Fatalf("by_fp = %+v, want 2", cs.ByFP)
	}
	if f := cs.ByFP[0]; f.FP != "c28caa00" || f.Lines != 3 || f.DistinctIPs != 2 ||
		f.WouldHarden != 1 || f.WouldDeny != 2 || f.MaxScore != 618.2 || !f.Convicted {
		t.Errorf("by_fp[0] = %+v, want c28caa00 lines3 ips2 harden1 deny2 max618.2 convicted", f)
	}
	if f := cs.ByFP[1]; f.FP != "(none)" || f.Lines != 1 || f.WouldHarden != 1 || f.Convicted {
		t.Errorf("by_fp[1] = %+v, want (none) lines1 harden1 not-convicted", f)
	}

	// top offenders: peak score per IP, ranked desc — .10 keeps 618.2, not the 120.0 re-fire.
	if len(cs.Top) != 3 {
		t.Fatalf("top = %+v, want 3", cs.Top)
	}
	if o := cs.Top[0]; o.IP != "203.0.113.10" || o.Score != 618.2 || o.Verdict != "would_deny" ||
		o.FarmFP != 30 || o.Solves != 40 {
		t.Errorf("top[0] = %+v, want .10 score618.2 deny farmfp30 solves40 (peak line)", o)
	}

	// A window with no challenge_score line omits the section entirely, so a quiet
	// node is distinguishable from one that scored but stayed under would_deny.
	if q := Summarize([]string{lineOutlier1, lineNoise}); q.ChallengeScore != nil {
		t.Errorf("challenge_score must be nil when the signal never fired, got %+v", q.ChallengeScore)
	}
}

// TestSummarizeDropsOperationalLines locks the verdict gate: dc_fraction's
// verdict-less operational lines must not inflate Total/unique_ips/by_signal and
// must not leak an empty-key by_verdict row (and the malformed ip=…) must not
// count as a unique IP).
func TestSummarizeDropsOperationalLines(t *testing.T) {
	s := Summarize([]string{lineDCVerified, lineDCDeferred, lineDC1})

	if s.Total != 1 {
		t.Fatalf("total = %d, want 1 (only the real decision line)", s.Total)
	}
	if s.UniqueIPs != 0 {
		t.Errorf("unique_ips = %d, want 0 — the operational ip=…) must not count", s.UniqueIPs)
	}
	for _, kv := range s.ByVerdict {
		if kv.Key == "" {
			t.Errorf("by_verdict leaked an empty-key row: %+v", s.ByVerdict)
		}
	}
	// by_signal counts only the decision line, not the two operational ones.
	for _, kv := range s.BySignal {
		if kv.Key == "dc_fraction" && kv.Count != 1 {
			t.Errorf("by_signal dc_fraction = %d, want 1 (decision only)", kv.Count)
		}
	}
	// The real decision still populates the per-vhost breakdown.
	if len(s.TopDC) != 1 || s.TopDC[0].DCFrac != 0.900 {
		t.Errorf("top_dc = %+v, want the one real dc.example.gr firing", s.TopDC)
	}
}

// TestSummarizePerSignalRanking locks sort DIRECTION (descending by the ranking
// metric) and the tiebreaks — single-host cases can't, since a 1-element slice
// sorts identically under a reversed comparator.
func TestSummarizePerSignalRanking(t *testing.T) {
	const (
		// facet: bbb & ccc tie on expansion=90 (ccc higher urls → ranks first);
		// aaa is weaker (expansion=50) → last. A reversed comparator would flip this.
		fa = `t [abuse-shadow] signal=facet_expansion host=aaa.gr urls=999 paths=99 expansion=50.0 repeat=1.0 reqs=999 verdict=would_shadow`
		fb = `t [abuse-shadow] signal=facet_expansion host=bbb.gr urls=300 paths=3 expansion=90.0 repeat=1.0 reqs=300 verdict=would_shadow`
		fc = `t [abuse-shadow] signal=facet_expansion host=ccc.gr urls=800 paths=8 expansion=90.0 repeat=1.0 reqs=800 verdict=would_shadow`
		// cost: high frac must rank first.
		ca = `t [abuse-shadow] signal=cost_pressure host=slowA.gr rps5xx=1.0 frac5xx=0.300 rt_avg=1.0 reqs=100 fails=30 verdict=would_shadow`
		cb = `t [abuse-shadow] signal=cost_pressure host=slowB.gr rps5xx=1.0 frac5xx=0.700 rt_avg=1.0 reqs=100 fails=70 verdict=would_shadow`
		// dc: dcB & dcC tie on frac=0.60 (dcC higher reqs → first); dcA strongest (0.95).
		da = `t [abuse-shadow] signal=dc_fraction host=dcA.gr dc_frac=0.950 dc_reqs=100 dc_ips=5 total_reqs=105 total_ips=6 verdict=would_shadow`
		db = `t [abuse-shadow] signal=dc_fraction host=dcB.gr dc_frac=0.600 dc_reqs=100 dc_ips=5 total_reqs=166 total_ips=8 verdict=would_shadow`
		dc = `t [abuse-shadow] signal=dc_fraction host=dcC.gr dc_frac=0.600 dc_reqs=500 dc_ips=9 total_reqs=833 total_ips=15 verdict=would_shadow`
	)
	s := Summarize([]string{fa, fb, fc, ca, cb, da, db, dc})

	gotF := []string{s.TopFacet[0].Host, s.TopFacet[1].Host, s.TopFacet[2].Host}
	if gotF[0] != "ccc.gr" || gotF[1] != "bbb.gr" || gotF[2] != "aaa.gr" {
		t.Errorf("top_facet order = %v, want [ccc bbb aaa] (desc expansion, urls tiebreak)", gotF)
	}
	if s.TopCost[0].Host != "slowB.gr" {
		t.Errorf("top_cost[0] = %q, want slowB.gr (desc frac5xx)", s.TopCost[0].Host)
	}
	gotD := []string{s.TopDC[0].Host, s.TopDC[1].Host, s.TopDC[2].Host}
	if gotD[0] != "dcA.gr" || gotD[1] != "dcC.gr" || gotD[2] != "dcB.gr" {
		t.Errorf("top_dc order = %v, want [dcA dcC dcB] (desc frac, dc_reqs tiebreak)", gotD)
	}
}
