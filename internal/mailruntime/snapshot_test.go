package mailruntime

import "testing"

func TestCountComms(t *testing.T) {
	comms := []string{"spamd", "spamd child", "spamd child", "exim", "spamd child", "mysqld"}
	if n := countComms(comms, DefaultSpamdChildComm); n != 3 {
		t.Fatalf("spamd child count = %d, want 3", n)
	}
	if n := countComms(comms, "spamd"); n != 1 {
		t.Errorf("master spamd count = %d, want 1", n)
	}
	if n := countComms(comms, "nope"); n != 0 {
		t.Errorf("absent comm = %d, want 0", n)
	}
}

func TestBuildSnapshot(t *testing.T) {
	// The regression shape: Exim 132/150 (88% → warn), spamd 10/10 (100% → crit).
	s := buildSnapshot(132, resolvedMax{150, true}, 10, resolvedMax{10, true})
	if s.SMTP.Sat != SatWarn {
		t.Errorf("smtp sat = %s, want warn", s.SMTP.Sat)
	}
	if s.Spamd.Sat != SatCritical {
		t.Errorf("spamd sat = %s, want critical", s.Spamd.Sat)
	}
	if s.Worst != SatCritical {
		t.Errorf("worst = %s, want critical", s.Worst)
	}
	if s.SMTP.Util.Pct != 88 {
		t.Errorf("smtp pct = %v, want 88", s.SMTP.Util.Pct)
	}
}

func TestBuildSnapshotUnknownMaxNeverOK(t *testing.T) {
	// SMTP max unresolved, spamd healthy → SMTP Unknown, and Worst must be
	// Unknown (not OK): an un-judged resource can't read as healthy.
	s := buildSnapshot(50, resolvedMax{Known: false}, 1, resolvedMax{10, true})
	if s.SMTP.Sat != SatUnknown {
		t.Errorf("smtp sat = %s, want unknown", s.SMTP.Sat)
	}
	if s.SMTP.Util.Current != 50 {
		t.Errorf("unknown resource must still carry current, got %d", s.SMTP.Util.Current)
	}
	if s.Spamd.Sat != SatOK {
		t.Errorf("spamd sat = %s, want ok", s.Spamd.Sat)
	}
	if s.Worst != SatUnknown {
		t.Errorf("worst = %s, want unknown (not ok)", s.Worst)
	}
}

func TestWorstOrdering(t *testing.T) {
	cases := []struct {
		a, b, want Saturation
	}{
		{SatCritical, SatOK, SatCritical},
		{SatOK, SatWarn, SatWarn},
		{SatUnknown, SatOK, SatUnknown}, // unknown beats ok (stays visible)
		{SatWarn, SatUnknown, SatWarn},  // real problem beats unknown
		{SatCritical, SatWarn, SatCritical},
		{SatOK, SatOK, SatOK},
	}
	for _, c := range cases {
		if got := worst(c.a, c.b); got != c.want {
			t.Errorf("worst(%s,%s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestEximMaxAndSpamdMaxResolution(t *testing.T) {
	if r := (EximMaxima{SMTPAcceptMax: 150, SMTPAcceptMaxFound: true}).EximMax(); !r.Known || r.Value != 150 {
		t.Errorf("found cap → %+v, want {150,true}", r)
	}
	if r := (EximMaxima{SMTPAcceptMaxFound: true, Unlimited: true}).EximMax(); r.Known {
		t.Errorf("unlimited (0) must be unknown, got %+v", r)
	}
	if r := (EximMaxima{}).EximMax(); r.Known {
		t.Errorf("absent must be unknown, got %+v", r)
	}

	if r := SpamdMax(8, true); !r.Known || r.Value != 8 {
		t.Errorf("SpamdMax(8,true) = %+v, want {8,true}", r)
	}
	if r := SpamdMax(0, true); r.Known {
		t.Errorf("SpamdMax(0,true) must be unknown, got %+v", r)
	}
	if r := SpamdMax(5, false); r.Known {
		t.Errorf("SpamdMax(_,false) must be unknown, got %+v", r)
	}
}
