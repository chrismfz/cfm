package kernsec

import (
	"testing"

	ui "github.com/gizak/termui/v3"
)

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
	// rule across both tiers, with kinds split correctly. State
	// values depend on the runtime kernel and aren't asserted.
	conf := &Conf{Tier: Tier2, Overrides: map[string]RuleOverride{}}
	rows := BuildAuditRows(conf, HostProfile{})
	wantTotal := len(AllSysctls()) + len(AllBootArgs()) + len(AllModules()) + len(Tier1Mounts)
	if len(rows) != wantTotal {
		t.Fatalf("BuildAuditRows() returned %d rows, want %d", len(rows), wantTotal)
	}
	var sysctlCount, bootCount, moduleCount, mountCount int
	for _, r := range rows {
		switch r.Kind {
		case KindSysctl:
			sysctlCount++
		case KindBoot:
			bootCount++
		case KindModule:
			moduleCount++
		case KindMount:
			mountCount++
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
	if sysctlCount != len(AllSysctls()) {
		t.Errorf("sysctl row count %d, want %d", sysctlCount, len(AllSysctls()))
	}
	if moduleCount != len(AllModules()) {
		t.Errorf("module row count %d, want %d", moduleCount, len(AllModules()))
	}
	if bootCount != len(AllBootArgs()) {
		t.Errorf("boot row count %d, want %d", bootCount, len(AllBootArgs()))
	}
	if mountCount != len(Tier1Mounts) {
		t.Errorf("mount row count %d, want %d", mountCount, len(Tier1Mounts))
	}
}

func TestBuildAuditRows_Tier0AllOff(t *testing.T) {
	// Tier=0 (kernsec configured but no tier enabled) — every rule's
	// decision must be SkipByTier and every row state must be OFF.
	// Previously these rows showed as MISSING/WARN, prompting false-
	// positive drift signals.
	conf := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	rows := BuildAuditRows(conf, HostProfile{})
	if len(rows) == 0 {
		t.Fatal("expected non-empty rows for tier=0")
	}
	for _, r := range rows {
		if r.State != StateOFF {
			t.Errorf("tier=0 row %s has state=%s, want OFF (decision=%v reason=%q)",
				r.ID, r.State, r.Decision, r.Reason)
		}
		if r.Decision != SkipByTier {
			t.Errorf("tier=0 row %s has decision=%v, want SkipByTier",
				r.ID, r.Decision)
		}
	}
}

func TestBuildAuditRows_Tier1HidesTier2AsOff(t *testing.T) {
	// Tier=1 conf — Tier 2 rules should render as OFF (operator-disabled
	// because tier-gated), not as MISSING.
	conf := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	rows := BuildAuditRows(conf, HostProfile{})
	var tier2OffCount, tier2WrongState int
	for _, r := range rows {
		if r.Tier != Tier2 {
			continue
		}
		if r.State == StateOFF {
			tier2OffCount++
		} else {
			tier2WrongState++
			t.Errorf("tier=1 conf, tier 2 rule %s rendered as %s instead of OFF",
				r.ID, r.State)
		}
	}
	if tier2OffCount == 0 {
		t.Fatal("expected at least one Tier 2 rule to render as OFF under tier=1 conf")
	}
}

func TestBuildAuditRows_PerRuleSkipOverrideRendersOff(t *testing.T) {
	// Pick the first sysctl rule and apply state=skip in conf — must
	// render as OFF with reason citing the conf override.
	allSysctls := AllSysctls()
	if len(allSysctls) == 0 {
		t.Skip("no sysctl rules registered; nothing to override")
	}
	target := allSysctls[0].ID
	conf := &Conf{
		Tier:      Tier2,
		Overrides: map[string]RuleOverride{target: OverrideSkip},
	}
	rows := BuildAuditRows(conf, HostProfile{})
	for _, r := range rows {
		if r.ID != target {
			continue
		}
		if r.State != StateOFF {
			t.Errorf("per-rule skip override should render as OFF, got %s", r.State)
		}
		if r.Decision != SkipByConf {
			t.Errorf("per-rule skip override decision should be SkipByConf, got %v", r.Decision)
		}
		return
	}
	t.Fatalf("rule %s not found in rows", target)
}

func TestBuildAuditRows_HostProfileSkipRendersSKIPNotOff(t *testing.T) {
	// Host profile with HasContainers=true triggers SkipByHostProfile
	// for the tier2.namespace group. Those rows must render as SKIP
	// (not OFF — operator hasn't disabled them; the host can't safely
	// take them on).
	conf := &Conf{Tier: Tier2, Overrides: map[string]RuleOverride{}}
	profile := HostProfile{HasContainers: true}
	rows := BuildAuditRows(conf, profile)
	var foundNamespace, mislabelled int
	for _, r := range rows {
		if r.Group != "tier2.namespace" {
			continue
		}
		foundNamespace++
		if r.State != StateSKIP {
			mislabelled++
			t.Errorf("host-profile skip on rule %s should render as SKIP, got %s (decision=%v)",
				r.ID, r.State, r.Decision)
		}
	}
	if foundNamespace == 0 {
		t.Skip("no tier2.namespace rules registered to test against")
	}
	if mislabelled > 0 {
		t.Errorf("%d/%d tier2.namespace rules mis-labelled with HasContainers=true",
			mislabelled, foundNamespace)
	}
}

func TestBuildAuditRows_ForceOverrideReasonVisibleAgainstHostingPanelGate(t *testing.T) {
	conf := &Conf{
		Tier: Tier2,
		Overrides: map[string]RuleOverride{
			"KSEC-SCT-tier2.namespace-001": OverrideForce,
		},
	}
	rows := BuildAuditRows(conf, HostProfile{IsCPanel: true, HasHostingPanelWorkload: true})
	for _, row := range rows {
		if row.ID != "KSEC-SCT-tier2.namespace-001" {
			continue
		}
		if row.Decision != Apply || row.Reason != "forced by conf" || row.State == StateSKIP || row.State == StateOFF {
			t.Fatalf("row decision=%v state=%v reason=%q, want forced Apply visibility", row.Decision, row.State, row.Reason)
		}
		return
	}
	t.Fatal("namespace audit row not found")
}

func TestGroupWorstColor_SkipAndOffAreNeutralAlongsideOK(t *testing.T) {
	g := groupKey{Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace"}
	rows := []AuditRow{
		// universal rule applied OK
		{ID: "a", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateOK},
		// Debian-only sibling that doesn't exist on this kernel
		{ID: "b", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateSKIP},
	}
	if got := groupWorstColor(rows, g, nil); got != ui.ColorGreen {
		t.Errorf("group with OK + SKIP sibling should render GREEN, got %v", got)
	}

	// All neutral (no OK to anchor on) stays WHITE — operator
	// hasn't enforced anything in this group.
	allNeutral := []AuditRow{
		{ID: "a", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateSKIP},
		{ID: "b", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateOFF},
	}
	if got := groupWorstColor(allNeutral, g, nil); got != ui.ColorWhite {
		t.Errorf("group with all SKIP/OFF should stay WHITE, got %v", got)
	}

	// Yellow / red still dominates a green sibling — neutrality is
	// asymmetric (it can't lift a real failure off the group).
	withYellow := []AuditRow{
		{ID: "a", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateOK},
		{ID: "b", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateDIFF},
	}
	if got := groupWorstColor(withYellow, g, nil); got != ui.ColorYellow {
		t.Errorf("group with DIFF should be YELLOW, got %v", got)
	}

	withDrift := []AuditRow{
		{ID: "a", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateOK},
		{ID: "b", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateDRIFT},
	}
	if got := groupWorstColor(withDrift, g, nil); got != ui.ColorRed {
		t.Errorf("group with DRIFT should be RED, got %v", got)
	}
}

func TestGroupWorstColor_EXTGreensWhenLiveValueMatches(t *testing.T) {
	g := groupKey{Tier: Tier1, Kind: KindSysctl, Group: "net.ipv4"}
	// EXT row with matching live value contributes green.
	rows := []AuditRow{
		{ID: "a", Tier: Tier1, Kind: KindSysctl, Group: "net.ipv4",
			State: StateEXT, LiveValue: "1", ExpectedValue: "1"},
	}
	if got := groupWorstColor(rows, g, nil); got != ui.ColorGreen {
		t.Errorf("EXT with matching value should render GREEN at group level, got %v", got)
	}

	// EXT row with mismatched live value is neutral — alone, the
	// group is WHITE (nothing reliably enforced for the operator's
	// glance).
	mismatch := []AuditRow{
		{ID: "a", Tier: Tier1, Kind: KindSysctl, Group: "net.ipv4",
			State: StateEXT, LiveValue: "0", ExpectedValue: "1"},
	}
	if got := groupWorstColor(mismatch, g, nil); got != ui.ColorWhite {
		t.Errorf("EXT with mismatched value alone should be WHITE, got %v", got)
	}
}

func TestGroupWorstColor_PendingStillMagenta(t *testing.T) {
	g := groupKey{Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace"}
	rows := []AuditRow{
		{ID: "a", Tier: Tier2, Kind: KindSysctl, Group: "tier2.namespace", State: StateOK},
	}
	pending := map[string]RuleOverride{"a": OverrideForce}
	if got := groupWorstColor(rows, g, pending); got != ui.ColorMagenta {
		t.Errorf("pending override should override group color to magenta, got %v", got)
	}
}
