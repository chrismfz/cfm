package kernsec

import "testing"

func TestBootRowState(t *testing.T) {
	tests := []struct {
		name      string
		cur, nxt  CmdlineArgState
		nextKnown bool
		want      RuleState
	}{
		{name: "both ok", cur: ArgOK, nxt: ArgOK, nextKnown: true, want: StateOK},
		{name: "configured pending reboot", cur: ArgMissing, nxt: ArgOK, nextKnown: true, want: StateWARN},
		{name: "active but not persisted", cur: ArgOK, nxt: ArgMissing, nextKnown: true, want: StateDRIFT},
		{name: "missing both", cur: ArgMissing, nxt: ArgMissing, nextKnown: true, want: StateMISSING},
		{name: "missing current next unknown", cur: ArgMissing, nxt: ArgMissing, nextKnown: false, want: StateMISSING},
		// cur=DIFF + nxt=OK is treated as WARN (pending reboot — current
		// value disagrees but next-boot config has the right value), the
		// same bucket as cur=MISSING + nxt=OK.
		{name: "diff in current cleared by next", cur: ArgDiff, nxt: ArgOK, nextKnown: true, want: StateWARN},
		{name: "diff in next", cur: ArgOK, nxt: ArgDiff, nextKnown: true, want: StateDRIFT},
		{name: "diff in both", cur: ArgDiff, nxt: ArgDiff, nextKnown: true, want: StateDIFF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bootRowState(tc.cur, tc.nxt, tc.nextKnown)
			if got != tc.want {
				t.Fatalf("bootRowState(%v,%v,%v) = %v, want %v",
					tc.cur, tc.nxt, tc.nextKnown, got, tc.want)
			}
		})
	}
}

func TestStateColorName(t *testing.T) {
	tests := []struct {
		state RuleState
		want  string
	}{
		{StateOK, "green"},
		{StateSKIP, "white"},
		{StateDIFF, "yellow"},
		{StateWARN, "yellow"},
		{StateMISSING, "yellow"},
		{StateDRIFT, "red"},
	}
	for _, tc := range tests {
		if got := StateColorName(tc.state); got != tc.want {
			t.Errorf("StateColorName(%q) = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestPresence(t *testing.T) {
	if presence(true) != "present" {
		t.Error("presence(true) should be 'present'")
	}
	if presence(false) != "missing" {
		t.Error("presence(false) should be 'missing'")
	}
}

func TestBuildAuditRows_PopulatesShape(t *testing.T) {
	// Smoke: the function must not panic and must return one row per
	// rule in the static profile, with kinds split correctly. State
	// values depend on the runtime kernel and aren't asserted.
	rows := BuildAuditRows()
	wantTotal := len(KSPPSysctls) + len(KSPPBootArgs) + len(Tier1Modules)
	if len(rows) != wantTotal {
		t.Fatalf("BuildAuditRows() returned %d rows, want %d", len(rows), wantTotal)
	}
	var sysctlCount, bootCount, moduleCount int
	for _, r := range rows {
		switch r.Kind {
		case KindSysctl:
			sysctlCount++
		case KindBoot:
			bootCount++
		case KindModule:
			moduleCount++
		default:
			t.Errorf("unknown kind %q in row %+v", r.Kind, r)
		}
		if r.Display == "" {
			t.Errorf("row has empty Display: %+v", r)
		}
		if r.Description == "" {
			t.Errorf("row has empty Description: %+v", r)
		}
		if r.Affects == "" {
			t.Errorf("row has empty Affects: %+v", r)
		}
	}
	if sysctlCount != len(KSPPSysctls) {
		t.Errorf("sysctl row count %d, want %d", sysctlCount, len(KSPPSysctls))
	}
	if moduleCount != len(Tier1Modules) {
		t.Errorf("module row count %d, want %d", moduleCount, len(Tier1Modules))
	}
	if bootCount != len(KSPPBootArgs) {
		t.Errorf("boot row count %d, want %d", bootCount, len(KSPPBootArgs))
	}
}
