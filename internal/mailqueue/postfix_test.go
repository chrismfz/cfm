package mailqueue

import (
	"testing"
	"time"
)

// Real mailcow `postqueue -p` shape (first message is the exact operator
// sample), plus a held (`!`) message and a second connect-timeout to a
// different host so aggregation/normalization is exercised.
const samplePostqueue = `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
9758362208D   15353 Wed Aug  5 10:00:33  support@myip.gr
     (connect to hogar.gr[2606:4700:3031::ac43:a7ef]:25: Connection timed out)
                                         info@hogar.gr

A1B2C3D4E5!    2048 Tue Aug  4 09:15:00  newsletter@shop.gr
     (mail for other.com loops back to myself)
                                         a@other.com
                                         b@other.com

F6E7D8C9B0     4096 Wed Aug  5 11:59:00  bounce@myip.gr
     (connect to mx.other.net[203.0.113.9]:25: Connection timed out)
                                         c@other.net

-- 21 Kbytes in 3 Requests.
`

// now is fixed relative to the sample arrivals so ages are deterministic.
// Uses time.Local to match parsePostfixArrival (postqueue prints local time).
var nowFixed = time.Date(2026, 8, 5, 12, 0, 33, 0, time.Local)

func TestParsePostqueue(t *testing.T) {
	msgs, trunc := parsePostqueue(samplePostqueue, nowFixed)
	if trunc {
		t.Fatalf("unexpected truncation")
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d messages, want 3: %+v", len(msgs), msgs)
	}

	// msg0: the exact operator sample — 2h old, 1 rcpt, not frozen.
	if msgs[0].ID != "9758362208D" || msgs[0].SizeBytes != 15353 ||
		msgs[0].AgeSec != 7200 || msgs[0].Sender != "support@myip.gr" ||
		msgs[0].Recipients != 1 || msgs[0].Frozen {
		t.Fatalf("msg0 wrong: %+v", msgs[0])
	}
	// msg1: held (`!`) → frozen; queue id had its marker stripped; 2 rcpts (one domain).
	if msgs[1].ID != "A1B2C3D4E5" || !msgs[1].Frozen || msgs[1].Recipients != 2 {
		t.Fatalf("msg1 should be the held message with marker stripped: %+v", msgs[1])
	}
	// msg2: ~1m old.
	if msgs[2].AgeSec != 93 || msgs[2].Frozen {
		t.Fatalf("msg2 wrong: %+v", msgs[2])
	}
}

func TestBuildPostfixReport(t *testing.T) {
	r := BuildPostfixReport(samplePostqueue, nowFixed, 3, DefaultTop)
	if r.MTA != "postfix" || r.Total != 3 || r.Parsed != 3 || r.Frozen != 1 {
		t.Fatalf("report totals wrong: %+v", r)
	}
	// Deferred = non-frozen && age >= 1h → only msg0.
	if r.Deferred != 1 {
		t.Fatalf("deferred = %d, want 1", r.Deferred)
	}
	// Age buckets: msg2 <10m, msg0 1h-6h, msg1 >1d.
	if r.AgeBuckets["<10m"] != 1 || r.AgeBuckets["1h-6h"] != 1 || r.AgeBuckets[">1d"] != 1 {
		t.Fatalf("age buckets wrong: %v", r.AgeBuckets)
	}
	// Sender domains: myip.gr (msg0+msg2) beats shop.gr (msg1).
	if len(r.TopSenderDomains) == 0 || r.TopSenderDomains[0].Domain != "myip.gr" || r.TopSenderDomains[0].Count != 2 {
		t.Fatalf("top sender domains wrong: %+v", r.TopSenderDomains)
	}

	// The two connect-timeouts (different hosts) collapse to ONE deferred reason;
	// the loop-back is a separate frozen reason.
	byReason := map[string]DeferReason{}
	for _, d := range r.DeferReasons {
		byReason[d.Reason] = d
	}
	timeout, ok := byReason["connect to: Connection timed out"]
	if !ok || timeout.Category != "deferred" || timeout.Count != 2 {
		t.Fatalf("connect-timeout reason should collapse to deferred count 2: %+v", r.DeferReasons)
	}
	loop, ok := byReason["mail for other.com loops back to myself"]
	if !ok || loop.Category != "frozen" || loop.Count != 1 {
		t.Fatalf("loop-back reason should be frozen count 1: %+v", r.DeferReasons)
	}

	// total=0 falls back to the parsed count.
	if r0 := BuildPostfixReport(samplePostqueue, nowFixed, 0, DefaultTop); r0.Total != 3 {
		t.Fatalf("total fallback = %d, want 3", r0.Total)
	}
}

func TestBuildPostfixReport_Empty(t *testing.T) {
	r := BuildPostfixReport("Mail queue is empty\n", nowFixed, 0, DefaultTop)
	if r.MTA != "postfix" || r.Total != 0 || r.Parsed != 0 || len(r.DeferReasons) != 0 {
		t.Fatalf("empty queue should yield an empty report: %+v", r)
	}
}

func TestNormalizePostfixReason(t *testing.T) {
	cases := map[string]string{
		"connect to hogar.gr[2606:4700:3031::ac43:a7ef]:25: Connection timed out": "connect to: Connection timed out",
		"connect to mx.other.net[203.0.113.9]:25: Connection timed out":           "connect to: Connection timed out",
		"host mx.example.com[1.2.3.4] said: 550 mailbox unavailable":              "host said: 550 mailbox unavailable",
		"mail for other.com loops back to myself":                                 "mail for other.com loops back to myself",
	}
	for in, want := range cases {
		if got := normalizePostfixReason(in); got != want {
			t.Errorf("normalizePostfixReason(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePostfixArrival_YearRollback(t *testing.T) {
	// Reading the queue on Jan 2 with a Dec 31 arrival → last year, not this year.
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.Local)
	age, ok := parsePostfixArrival("Wed Dec 31 23:00:00", now)
	if !ok {
		t.Fatal("arrival should parse")
	}
	// Dec 31 2025 23:00 → Jan 2 2026 00:00 = 25h.
	if age != 25*3600 {
		t.Fatalf("age = %d, want %d (year should roll back)", age, 25*3600)
	}
}
