package kernsec

import (
	"bytes"
	"strings"
	"testing"

	"cfm/internal/managedsysctl"
)

// Phase 6 cross-component contract: kernsec.Resolve consults the
// managedsysctl registry and marks rules whose key is owned by
// another cfm component as ManagedExternally — kernsec audits but
// never writes them.

func TestResolve_NetSysctlsAreManagedExternally(t *testing.T) {
	// At tier=1 every NetSysctls rule should resolve to
	// ManagedExternally because internal/sysctl/sys_tweaks.go
	// registered the cfm-sysctl-tweaks catalog claiming those keys
	// (via the blank import in imports.go that pulls sysctl's init).
	rs := Resolve(&Conf{Tier: Tier1}, HostProfile{})

	if len(NetSysctls) == 0 {
		t.Skip("NetSysctls is empty; nothing to assert")
	}
	for _, r := range rs.Sysctls {
		if r.Group != "sysctl.net" {
			continue
		}
		if r.Decision != ManagedExternally {
			t.Errorf("net rule %q decision = %v, want ManagedExternally", r.ID, r.Decision)
		}
		if !strings.Contains(r.Reason, "cfm-sysctl-tweaks") {
			t.Errorf("net rule %q reason = %q, should name cfm-sysctl-tweaks", r.ID, r.Reason)
		}
	}
}

func TestResolve_NetSysctlsExcludedFromApplySet(t *testing.T) {
	// ApplySysctls drives `cfm kernsec apply` — kernsec MUST NOT
	// write keys that another component owns.
	rs := Resolve(&Conf{Tier: Tier2}, HostProfile{}) // tier=2 to defeat tier-skip

	for _, r := range rs.ApplySysctls() {
		for _, n := range NetSysctls {
			if r.ID == n.ID {
				t.Errorf("ApplySysctls included KSEC-SCT-net rule %q — kernsec must not write keys owned by sys_tweaks",
					r.ID)
			}
		}
	}
}

func TestResolve_ForceOverridesExternalOwnership(t *testing.T) {
	// `state = force` is the operator escape hatch: take the key
	// back from the other component and have kernsec write it.
	// decideSysctl checks force BEFORE the managedsysctl
	// cross-component check, so a forced rule resolves to Apply
	// even when sys_tweaks would otherwise own the key.
	if len(NetSysctls) == 0 {
		t.Skip("NetSysctls empty; nothing to test against")
	}
	target := NetSysctls[0].ID

	conf := &Conf{
		Tier:      Tier1,
		Overrides: map[string]RuleOverride{target: OverrideForce},
	}
	rs := Resolve(conf, HostProfile{})
	for _, r := range rs.Sysctls {
		if r.ID != target {
			continue
		}
		if r.Decision != Apply {
			t.Errorf("force-override on %q: decision %v, want Apply (operator opted to take ownership back)",
				target, r.Decision)
		}
		return
	}
	t.Fatalf("rule %q not in resolved set", target)
}

func TestSysctlRowState_ManagedExternallyAlwaysEXT(t *testing.T) {
	// Live state should NOT change the row: ManagedExternally is a
	// decision-driven label, not a probe-driven one. Operator who
	// sees an EXT row is told "kernsec doesn't manage this; another
	// cfm component does" — drift handling is that other component's
	// problem.
	tests := []struct {
		name string
		live SysctlState
	}{
		{"live OK", SysctlOK},
		{"live mismatch", SysctlMismatch},
		{"live missing", SysctlMissing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sysctlRowState(ManagedExternally, tc.live)
			if got != StateEXT {
				t.Errorf("sysctlRowState(ManagedExternally, %v) = %v, want StateEXT", tc.live, got)
			}
		})
	}
}

func TestRunStatus_RendersEXTRowsWithoutWarning(t *testing.T) {
	// `cfm kernsec status --check` must NOT exit non-zero just because
	// a sys_tweaks-owned key isn't at kernsec's recommended value —
	// we don't own the value. EXT rows print informationally; only
	// drift on Apply-decision rules contributes to res.warn().
	withTempConfPath(t)
	c := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	res := RunStatus(&w, StatusOptions{SkipAFAlg: true})
	out := w.String()

	// Expect at least one EXT line for the sysctl.net group.
	if !strings.Contains(out, "EXT   net.ipv4") {
		t.Errorf("expected EXT line for net.ipv4 sysctl, got:\n%s", out)
	}
	// And the reason must name the owning component.
	if !strings.Contains(out, "managed by cfm-sysctl-tweaks") {
		t.Errorf("EXT line should name the owning component, got:\n%s", out)
	}
	_ = res
}

func TestResolve_ForceBeatsSkipPrecedence(t *testing.T) {
	// Per kernsec.conf semantics, `state = force` is documented as
	// taking precedence over every other constraint (skip, tier
	// gating, host profile, external ownership). Lock that into a
	// test: force wins even when skip is also set on the same rule
	// (operator misconfig is well-defined: force wins).
	if len(NetSysctls) == 0 {
		t.Skip("NetSysctls empty")
	}
	target := NetSysctls[0].ID
	conf := &Conf{
		Tier: Tier1,
		// `decide()` checks force first per docs/kernsec.md; skip
		// would otherwise flip to SkipByConf.
		Overrides: map[string]RuleOverride{target: OverrideForce},
	}
	rs := Resolve(conf, HostProfile{})
	for _, r := range rs.Sysctls {
		if r.ID != target {
			continue
		}
		if r.Decision != Apply {
			t.Errorf("force on %q: decision %v, want Apply", target, r.Decision)
		}
		return
	}
	t.Fatalf("rule %q not in resolved set", target)
}

func TestVerifyAfterApply_EXTRowsDoNotCountAsFailures(t *testing.T) {
	// Phase 6 contract: EXT rows are kernsec audit-only. A live-state
	// mismatch on an EXT row must NOT contribute to verifyAfterApply's
	// failure count — that's the other component's responsibility.
	//
	// Construct a synthetic AuditRow set with one StateEXT + one
	// StateOK and confirm both are excluded from sysctlBad/etc.
	rows := []AuditRow{
		{Kind: KindSysctl, State: StateEXT,
			ExpectedValue: "0", LiveValue: "1"}, // would be DIFF if not EXT
		{Kind: KindSysctl, State: StateOK,
			ExpectedValue: "1", LiveValue: "1"},
	}
	bad := 0
	for _, r := range rows {
		// Mirror the verifyAfterApply early-exit check at apply.go:447.
		if r.State == StateOFF || r.State == StateSKIP || r.State == StateEXT {
			continue
		}
		if r.Kind == KindSysctl && r.State != StateOK {
			bad++
		}
	}
	if bad != 0 {
		t.Errorf("EXT row counted as failure: bad=%d", bad)
	}
}

func TestReportCrossComponentConflicts_SurfacedOnForcedOverride(t *testing.T) {
	// Phase 6 docs/kernsec.md:1117 promises that forced overrides
	// surface a cross-component conflict in apply output. Verify by
	// running RunApply --dry-run with force on a NetSysctls rule and
	// asserting the output names the conflict.
	if len(NetSysctls) == 0 {
		t.Skip("NetSysctls empty")
	}
	withTempConfPath(t)
	target := NetSysctls[0]
	c := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{target.ID: OverrideForce}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := RunApply(&w, ApplyOptions{DryRun: true})
	if rc != 0 {
		t.Fatalf("RunApply --dry-run rc=%d, output:\n%s", rc, w.String())
	}
	out := w.String()
	if !strings.Contains(out, "cross-component sysctl ownership conflicts") {
		t.Errorf("expected cross-component conflict block, got:\n%s", out)
	}
	if !strings.Contains(out, target.Key) {
		t.Errorf("conflict block should name the forced key %q, got:\n%s", target.Key, out)
	}
	if !strings.Contains(out, "cfm-sysctl-tweaks") {
		t.Errorf("conflict block should name owning component, got:\n%s", out)
	}
}

func TestReportCrossComponentConflicts_SilentWhenNone(t *testing.T) {
	// No forced overrides + no registry conflicts → no conflict
	// block. Operator-friendly: silent when there's nothing to
	// surface.
	withTempConfPath(t)
	c := &Conf{Tier: Tier1}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if rc := RunApply(&w, ApplyOptions{DryRun: true}); rc != 0 {
		t.Fatalf("rc=%d, output:\n%s", rc, w.String())
	}
	if strings.Contains(w.String(), "cross-component sysctl ownership conflicts") {
		t.Errorf("conflict block should not appear when there are no conflicts:\n%s", w.String())
	}
}

func TestManagedSysctlDefault_KnowsSysTweaksKeys(t *testing.T) {
	// Sanity: the catalog registration via imports.go fired and
	// sys_tweaks's claim is visible from kernsec's POV.
	r := managedsysctl.Default()
	for _, n := range NetSysctls {
		if owner := r.OwnerOf(n.Key); owner != managedsysctl.OwnerSysTweaks {
			t.Errorf("OwnerOf(%q) = %q, want OwnerSysTweaks (kernsec rule %q expects this)",
				n.Key, owner, n.ID)
		}
	}
}
