package mailqueue

import "testing"

// Real exim -bp format: the "*** frozen ***" marker is appended to the HEADER
// line (after the sender), and a frozen bounce DSN has an empty <> sender.
const sampleBP = `25m  2.9K 1rABCD-000abc-1A <sender@example.com>
          user@dest.com
          user2@dest.com

 2h   541 1rABCE-000abd-2B <> *** frozen ***
          admin@bar.com

3d  1.5M 1rABCF-000abe-3C <newsletter@shop.gr>
          a@aol.com
`

func TestParseBP(t *testing.T) {
	msgs, trunc := parseBP(sampleBP)
	if trunc {
		t.Fatalf("unexpected truncation")
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d messages, want 3: %+v", len(msgs), msgs)
	}

	// msg 0: 25m, 2 recipients (dest.com), sender example.com
	if msgs[0].AgeSec != 1500 || msgs[0].Sender != "sender@example.com" || msgs[0].Recipients != 2 {
		t.Fatalf("msg0 wrong: %+v", msgs[0])
	}
	if msgs[0].SizeBytes != 2969 { // int(2.9*1024)
		t.Fatalf("msg0 size = %d", msgs[0].SizeBytes)
	}
	// msg 0 must NOT be frozen — the marker on msg1's header line must not leak
	// back to the previous message (the bug this guards).
	if msgs[0].Frozen {
		t.Fatalf("msg0 wrongly marked frozen (marker leaked from msg1)")
	}
	// msg 1: the frozen bounce — marker on the HEADER line, empty <> sender, 2h.
	if !msgs[1].Frozen || msgs[1].AgeSec != 7200 || msgs[1].Sender != "" || msgs[1].Recipients != 1 {
		t.Fatalf("msg1 should be the frozen <> message @2h with 1 rcpt: %+v", msgs[1])
	}
	// msg 2: 3d, 1.5M, not frozen
	if msgs[2].AgeSec != 3*86400 || msgs[2].SizeBytes != 1572864 || msgs[2].Frozen { // int(1.5*1024*1024)
		t.Fatalf("msg2 wrong: %+v", msgs[2])
	}
}

func TestParseAgeSize(t *testing.T) {
	for tok, want := range map[string]int64{"45s": 45, "25m": 1500, "2h": 7200, "3d": 259200, "1w": 604800} {
		if got, ok := parseAge(tok); !ok || got != want {
			t.Errorf("parseAge(%q) = %d,%v want %d", tok, got, ok, want)
		}
	}
	if _, ok := parseAge("frozen"); ok {
		t.Error("parseAge should reject non-age token")
	}
	for tok, want := range map[string]int64{"541": 541, "2.9K": 2969, "1.5M": 1572864} {
		if got, ok := parseSize(tok); !ok || got != want {
			t.Errorf("parseSize(%q) = %d,%v want %d", tok, got, ok, want)
		}
	}
}

func TestAggregateFromParse(t *testing.T) {
	msgs, _ := parseBP(sampleBP)
	senderDom := map[string]int{}
	recipDom := map[string]int{}
	frozen := 0
	for _, m := range msgs {
		if m.Frozen {
			frozen++
		}
		senderDom[domainOf(m.Sender)]++
		for _, d := range m.rcptDomains {
			recipDom[d]++
		}
	}
	if frozen != 1 {
		t.Fatalf("frozen = %d, want 1", frozen)
	}
	// msg1 is a <> bounce → no sender domain; example.com + shop.gr present.
	if senderDom["example.com"] != 1 || senderDom["shop.gr"] != 1 {
		t.Fatalf("sender domains wrong: %v", senderDom)
	}
	// msg0 had 2 recipients but both @dest.com → 1 distinct domain for that msg.
	if recipDom["dest.com"] != 1 || recipDom["bar.com"] != 1 || recipDom["aol.com"] != 1 {
		t.Fatalf("recipient domains wrong: %v", recipDom)
	}
	top := topDomains(senderDom, 2)
	if len(top) != 2 {
		t.Fatalf("topDomains cap failed: %d", len(top))
	}
}

func TestBuildEximReport(t *testing.T) {
	// total=3 (exim -bpc), frozen=1 (detector's authoritative marker count).
	r := BuildEximReport(sampleBP, 3, 1, DefaultTop)
	if r.MTA != "exim" || r.Total != 3 || r.Parsed != 3 || r.Frozen != 1 {
		t.Fatalf("report totals wrong: %+v", r)
	}
	if len(r.TopSenderDomains) == 0 || r.TopSenderDomains[0].Count < 1 {
		t.Fatalf("sender domains not aggregated: %+v", r.TopSenderDomains)
	}
	// age buckets: 25m→10m-1h, 2h→1h-6h, 3d→>1d
	if r.AgeBuckets["10m-1h"] != 1 || r.AgeBuckets["1h-6h"] != 1 || r.AgeBuckets[">1d"] != 1 {
		t.Fatalf("age buckets wrong: %v", r.AgeBuckets)
	}
	// Frozen is authoritative from the param, not the parsed count.
	if r2 := BuildEximReport(sampleBP, 3, 42, DefaultTop); r2.Frozen != 42 {
		t.Fatalf("Frozen should come from the authoritative param: %d", r2.Frozen)
	}
	// total=0 falls back to parsed count
	if r0 := BuildEximReport(sampleBP, 0, 0, DefaultTop); r0.Total != 3 {
		t.Fatalf("total fallback = %d, want 3", r0.Total)
	}
}

func TestTopSenders(t *testing.T) {
	// From sampleBP: sender@example.com (25m, fresh), <> (frozen, 2h),
	// newsletter@shop.gr (3d, deferred). One message each.
	r := BuildEximReport(sampleBP, 3, 1, DefaultTop)
	if len(r.TopSenders) != 3 {
		t.Fatalf("want 3 senders, got %d: %+v", len(r.TopSenders), r.TopSenders)
	}
	by := map[string]SenderQueueStat{}
	for _, s := range r.TopSenders {
		by[s.Sender] = s
	}
	if s := by["<>"]; s.Total != 1 || s.Frozen != 1 || s.Deferred != 0 {
		t.Fatalf("null sender (frozen bounce): %+v", s)
	}
	if s := by["newsletter@shop.gr"]; s.Total != 1 || s.Frozen != 0 || s.Deferred != 1 {
		t.Fatalf("newsletter (3d → deferred): %+v", s)
	}
	if s := by["sender@example.com"]; s.Total != 1 || s.Frozen != 0 || s.Deferred != 0 {
		t.Fatalf("fresh sender (25m → neither): %+v", s)
	}
	// All Total=1 → tie broken by sender ascending, so "<>" sorts first.
	if r.TopSenders[0].Sender != "<>" {
		t.Fatalf("tie-break should sort '<>' first: %+v", r.TopSenders)
	}

	// Same sender across several messages is summed with the frozen/deferred split.
	const dupBP = "2h 1K 1a-b-1 <spammer@x.gr> *** frozen ***\n" +
		"          v1@dest.com\n" +
		"2h 1K 1a-b-2 <spammer@x.gr> *** frozen ***\n" +
		"          v2@dest.com\n" +
		"3d 1K 1a-b-3 <spammer@x.gr>\n" +
		"          v3@dest.com\n"
	r2 := BuildEximReport(dupBP, 3, 2, DefaultTop)
	if len(r2.TopSenders) != 1 {
		t.Fatalf("want 1 aggregated sender, got %+v", r2.TopSenders)
	}
	if s := r2.TopSenders[0]; s.Sender != "spammer@x.gr" || s.Total != 3 || s.Frozen != 2 || s.Deferred != 1 {
		t.Fatalf("aggregation wrong: %+v", s)
	}
}

// Latest must deep-copy the AgeBuckets map so a caller can't corrupt the store.
func TestLatestDeepCopiesMap(t *testing.T) {
	TestOnlyReset()
	Publish(Report{MTA: "exim", AgeBuckets: map[string]int{"<10m": 1}})
	got, _ := Latest()
	got.AgeBuckets["<10m"] = 999 // mutate the copy
	again, _ := Latest()
	if again.AgeBuckets["<10m"] != 1 {
		t.Fatalf("Latest did not deep-copy AgeBuckets: %v", again.AgeBuckets)
	}
}

func TestPublishLatest(t *testing.T) {
	TestOnlyReset()
	if _, ok := Latest(); ok {
		t.Fatal("expected no report before publish")
	}
	Publish(Report{MTA: "exim", Total: 5})
	got, ok := Latest()
	if !ok || got.MTA != "exim" || got.Total != 5 || got.MeasuredAt.IsZero() {
		t.Fatalf("Latest after publish = %+v ok=%v", got, ok)
	}
}
