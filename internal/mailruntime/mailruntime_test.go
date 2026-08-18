package mailruntime

import "testing"

func TestNewUtilisationAndClassify(t *testing.T) {
	tests := []struct {
		name      string
		current   int
		max       int
		wantKnown bool
		wantPct   float64
		wantSat   Saturation
	}{
		{"ok low", 10, 100, true, 10, SatOK},
		{"just under warn", 79, 100, true, 79, SatOK},
		{"warn boundary 80%", 80, 100, true, 80, SatWarn},
		{"warn mid", 90, 100, true, 90, SatWarn},
		{"crit boundary 95%", 95, 100, true, 95, SatCritical},
		{"at cap", 100, 100, true, 100, SatCritical},
		{"over cap", 150, 100, true, 150, SatCritical},
		{"zero use", 0, 100, true, 0, SatOK},
		{"max zero → unknown", 5, 0, false, 0, SatUnknown},
		{"max negative → unknown", 5, -1, false, 0, SatUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := NewUtilisation(tc.current, tc.max)
			if u.Known != tc.wantKnown {
				t.Fatalf("Known = %v, want %v", u.Known, tc.wantKnown)
			}
			if u.Pct != tc.wantPct {
				t.Errorf("Pct = %v, want %v", u.Pct, tc.wantPct)
			}
			if got := u.Classify(); got != tc.wantSat {
				t.Errorf("Classify = %s, want %s", got, tc.wantSat)
			}
		})
	}
}

func TestNewUtilisationClampsNegativeCurrent(t *testing.T) {
	u := NewUtilisation(-3, 100)
	if u.Current != 0 {
		t.Fatalf("negative current not clamped: %d", u.Current)
	}
	if u.Classify() != SatOK {
		t.Errorf("classify = %s, want ok", u.Classify())
	}
}

func TestUnknownIsNeverOK(t *testing.T) {
	u := Unknown(42)
	if u.Known {
		t.Fatal("Unknown() must not be Known")
	}
	if u.Current != 42 {
		t.Errorf("Unknown() must carry current for display, got %d", u.Current)
	}
	if u.Classify() != SatUnknown {
		t.Errorf("Unknown().Classify() = %s, want unknown", u.Classify())
	}
	// The load-bearing invariant of docs/whats-wrong-rootcause §3: an
	// unresolved cap must never read as ok.
	if u.Classify() == SatOK {
		t.Fatal("unknown collapsed to ok")
	}
}

func TestSaturationString(t *testing.T) {
	cases := map[Saturation]string{
		SatUnknown:  "unknown",
		SatOK:       "ok",
		SatWarn:     "warn",
		SatCritical: "critical",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(s), got, want)
		}
	}
}
