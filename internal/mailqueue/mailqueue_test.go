package mailqueue

import "testing"

const sampleBP = `25m  2.9K 1rABCD-000abc-1A <sender@example.com>
          user@dest.com
          user2@dest.com

 2h   541 1rABCE-000abd-2B <bounce@mail.foo.gr>
          admin@bar.com
          *** frozen ***

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
	// msg 1: frozen, 2h
	if !msgs[1].Frozen || msgs[1].AgeSec != 7200 {
		t.Fatalf("msg1 should be frozen@2h: %+v", msgs[1])
	}
	// msg 2: 3d, 1.5M
	if msgs[2].AgeSec != 3*86400 || msgs[2].SizeBytes != 1572864 { // int(1.5*1024*1024)
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
	if senderDom["example.com"] != 1 || senderDom["mail.foo.gr"] != 1 || senderDom["shop.gr"] != 1 {
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

func TestParseCount(t *testing.T) {
	// login-shell noise before the number → take the last numeric line.
	if n, err := parseCount("/etc/profile chatter\n42\n", nil); err != nil || n != 42 {
		t.Fatalf("parseCount = %d,%v", n, err)
	}
	if _, err := parseCount("no number here", nil); err == nil {
		t.Fatal("expected error when no numeric line")
	}
}
