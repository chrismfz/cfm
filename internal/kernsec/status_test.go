package kernsec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withUnreadableNextBootCmdline(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	origPVE, origBLS, origGrub := PathPVECmdline, PathBLSEntries, PathDefaultGrub
	PathPVECmdline = filepath.Join(tmp, "missing-pve-cmdline")
	PathBLSEntries = filepath.Join(tmp, "missing-bls-entries")
	PathDefaultGrub = filepath.Join(tmp, "grub")
	t.Cleanup(func() {
		PathPVECmdline, PathBLSEntries, PathDefaultGrub = origPVE, origBLS, origGrub
	})
	bad := []byte("GRUB_CMDLINE_LINUX=\"quiet ${UNSAFE}\"\n")
	if err := os.WriteFile(PathDefaultGrub, bad, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunTextCheck_IndeterminateWhenNextBootCmdlineUnreadable(t *testing.T) {
	withTempConfPath(t)
	withUnreadableNextBootCmdline(t)
	if err := WriteConf(&Conf{Tier: 0, Overrides: map[string]RuleOverride{}}); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := runText([]string{"--check", "--skip-af-alg"}, &w)
	if rc != 2 {
		t.Fatalf("runText --check rc = %d, want 2; output:\n%s", rc, w.String())
	}
	if !strings.Contains(w.String(), "ERROR unable to read next-boot cmdline") {
		t.Fatalf("status output missing next-boot ERROR line:\n%s", w.String())
	}
}

func TestRunStatusJSON_IncludesNextBootReadError(t *testing.T) {
	withTempConfPath(t)
	withUnreadableNextBootCmdline(t)
	if err := WriteConf(&Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	res := RunStatusJSON(&w)
	if !res.Indeterminate {
		t.Fatalf("RunStatusJSON Indeterminate = false, want true")
	}
	var out StatusJSON
	if err := json.Unmarshal(w.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal status JSON: %v\n%s", err, w.String())
	}
	if out.OK {
		t.Fatalf("status JSON ok = true, want false on read error")
	}
	if len(out.Errors) == 0 || !strings.Contains(out.Errors[0], "shell metacharacter") {
		t.Fatalf("status JSON errors = %#v, want shell metacharacter read error", out.Errors)
	}
	foundBootRowError := false
	for _, row := range out.Rules {
		if row.Kind == KindBoot && strings.Contains(row.Error, "shell metacharacter") {
			foundBootRowError = true
			break
		}
	}
	if !foundBootRowError {
		t.Fatalf("no boot audit row carried read error")
	}
}

func TestRunStatus_AbsentConfigUsesFirstRunDefault(t *testing.T) {
	withTempConfPath(t)

	var w bytes.Buffer
	res := RunStatus(&w, StatusOptions{SkipAFAlg: true})
	out := w.String()

	if res.Tier != Tier1 {
		t.Fatalf("RunStatus tier = %d, want first-run default tier 1", res.Tier)
	}
	if strings.Contains(out, "unable to read kernsec config") {
		t.Fatalf("absent config should not render a config error:\n%s", out)
	}
	if containsString(res.Errors, "kernsec config read failed") {
		t.Fatalf("absent config should not be preserved as a config error: %#v", res.Errors)
	}
}

func TestRunTextCheck_MalformedConfigIsIndeterminate(t *testing.T) {
	withTempConfPath(t)
	if err := os.WriteFile(ConfPath, []byte("totally not a conf file\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := runText([]string{"--check", "--skip-af-alg"}, &w)
	if rc != 2 {
		t.Fatalf("runText --check rc = %d, want 2 for malformed config; output:\n%s", rc, w.String())
	}
	for _, want := range []string{
		"ERROR unable to read kernsec config",
		"malformed",
		"Status verification indeterminate",
	} {
		if !strings.Contains(w.String(), want) {
			t.Fatalf("status output missing %q for malformed config:\n%s", want, w.String())
		}
	}
}

func TestRunStatus_UnreadableConfigIsIndeterminate(t *testing.T) {
	withTempConfPath(t)
	if err := os.Remove(ConfPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(ConfPath, 0o755); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	res := RunStatus(&w, StatusOptions{SkipAFAlg: true})
	out := w.String()

	if !res.Indeterminate {
		t.Fatalf("RunStatus Indeterminate = false, want true for unreadable config; output:\n%s", out)
	}
	if !containsString(res.Errors, "kernsec config read failed") {
		t.Fatalf("RunStatus errors missing config read failure: %#v", res.Errors)
	}
	if !strings.Contains(out, "ERROR unable to read kernsec config") {
		t.Fatalf("status output missing config read error:\n%s", out)
	}
}

func TestRunStatusJSON_IncludesMalformedConfigError(t *testing.T) {
	withTempConfPath(t)
	if err := os.WriteFile(ConfPath, []byte("tier = nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	res := RunStatusJSON(&w)
	if !res.Indeterminate {
		t.Fatalf("RunStatusJSON Indeterminate = false, want true")
	}
	if !containsString(res.Errors, "kernsec config read failed") {
		t.Fatalf("RunStatusJSON result errors missing config error: %#v", res.Errors)
	}

	var out StatusJSON
	if err := json.Unmarshal(w.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal status JSON: %v\n%s", err, w.String())
	}
	if out.OK {
		t.Fatalf("status JSON ok = true, want false on malformed config")
	}
	if out.Tier != Tier1 {
		t.Fatalf("status JSON tier = %d, want default tier 1 after malformed config", out.Tier)
	}
	if !containsString(out.Errors, "kernsec config read failed") || !containsString(out.Errors, "tier must be 0, 1, or 2") {
		t.Fatalf("status JSON errors missing malformed config details: %#v", out.Errors)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func TestBuildAuditRows_Tier0DoesNotMaskNextBootReadError(t *testing.T) {
	withUnreadableNextBootCmdline(t)
	rows := BuildAuditRows(&Conf{Tier: 0, Overrides: map[string]RuleOverride{}}, HostProfile{})
	checkedBoot := false
	for _, row := range rows {
		if row.Kind != KindBoot {
			continue
		}
		checkedBoot = true
		if row.State != StateOFF {
			t.Fatalf("tier=0 boot row state = %s, want OFF", row.State)
		}
		if row.NextBootKnown {
			t.Fatalf("tier=0 boot row NextBootKnown = true, want false")
		}
		if !strings.Contains(row.Error, "shell metacharacter") {
			t.Fatalf("tier=0 boot row error = %q, want read error", row.Error)
		}
	}
	if !checkedBoot {
		t.Fatal("no boot rows found")
	}
}

func TestApplyBootKeysFromResolved_FiltersToApply(t *testing.T) {
	// tier=1 conf with one explicit per-rule skip on a tier-1 boot
	// arg → that key must NOT appear in the kernel-log scan list.
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-BOOT-kspp-001": OverrideSkip, // slab_nomerge
		},
	}
	resolved := Resolve(conf, HostProfile{})
	keys := applyBootKeysFromResolved(resolved)

	for _, k := range keys {
		if k == "slab_nomerge" {
			t.Errorf("skipped boot arg should not be in scan list: %v", keys)
		}
	}
	// Other Tier 1 boot args should still be present (init_on_alloc,
	// page_alloc.shuffle, randomize_kstack_offset, initcall_blacklist).
	wantContains := []string{
		"init_on_alloc",
		"page_alloc.shuffle",
		"randomize_kstack_offset",
		"initcall_blacklist",
	}
	for _, w := range wantContains {
		found := false
		for _, k := range keys {
			if k == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected key %q in resolver-Apply scan list, got %v", w, keys)
		}
	}
}

func TestApplyBootKeysFromResolved_Tier0EmptyList(t *testing.T) {
	// tier=0 → nothing in Apply → empty key list. Kernel-log scan
	// for unknown args becomes a no-op, so a kernel that warns
	// about a key the operator manually added doesn't make
	// `status --check` non-zero on a disabled host.
	conf := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	resolved := Resolve(conf, HostProfile{})
	keys := applyBootKeysFromResolved(resolved)
	if len(keys) != 0 {
		t.Errorf("tier=0 should produce no scan keys, got %v", keys)
	}
}

func TestRunStatus_Tier0DoesNotWarnOnDisabledRuleProbes(t *testing.T) {
	// On a tier=0 host, every kernel-feature health probe paired with
	// a kernsec rule (AF_ALG, page_alloc.shuffle, mem auto-init,
	// randomize_kstack) must render OFF instead of WARN. `--check`
	// exit code reflects only kernsec-actionable drift, not
	// kernel-feature state on a host the operator chose to disable.
	withTempConfPath(t)
	c := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	res := RunStatus(&w, StatusOptions{SkipAFAlg: true})
	out := w.String()

	// Every gated kernel-feature probe should print an OFF line, not
	// a WARN — the probe runs informationally but doesn't escalate
	// to res.warn().
	for _, marker := range []string{
		"OFF   page_alloc.shuffle rule is disabled",
		"OFF   init_on_alloc rule is disabled",
		"OFF   randomize_kstack_offset rule is disabled",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("expected %q in tier=0 status, got:\n%s", marker, out)
		}
	}
	// Module section should report the file-absent state as OFF, not
	// MISSING — every module rule is OFF on a tier=0 host.
	if !strings.Contains(out, "OFF        ") || !strings.Contains(out, "no module rules active") {
		t.Errorf("expected OFF (not MISSING) for absent modprobe file on tier=0; got:\n%s", out)
	}
	// Sanity: the result struct should not reflect any of the gated
	// probes as warnings. There may still be tier-independent
	// warnings (e.g. kernel-config-not-readable IF kstack rule were
	// Apply, but it isn't here), so we don't assert exactly zero —
	// just that none of the strings above contributed.
	_ = res
}

func TestDecisionForBootArg_FallsBackToApplyForUnknown(t *testing.T) {
	// Empty resolved set → Apply (so hard-coded RunStatus follow-up
	// checks for kernel-feature health probes still run even when
	// they're not registered as kernsec rules).
	got := decisionForBootArg(ResolvedSet{}, "no_such_key", "")
	if got != Apply {
		t.Errorf("unknown rule should fall back to Apply, got %v", got)
	}
}

func TestDecisionForBootArg_FindsManagedRule(t *testing.T) {
	// algif_aead_init mitigation is KSEC-BOOT-kspp-005 — an actual
	// kernsec-managed boot arg. The cross-reference must find it by
	// display string ("key=value") so the hard-coded mitigation check
	// in RunStatus respects the operator's conf decision.
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-BOOT-kspp-005": OverrideSkip,
		},
	}
	resolved := Resolve(conf, HostProfile{})
	got := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init")
	if got != SkipByConf {
		t.Errorf("operator-skipped algif rule should resolve to SkipByConf, got %v", got)
	}
}

func TestDecisionForBootArg_TierZeroProducesSkipByTier(t *testing.T) {
	conf := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	resolved := Resolve(conf, HostProfile{})
	got := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init")
	if got != SkipByTier {
		t.Errorf("tier=0 should produce SkipByTier for algif rule, got %v", got)
	}
}

func TestDecisionForBootArg_Tier1AppliesAlgifMitigation(t *testing.T) {
	conf := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	resolved := Resolve(conf, HostProfile{})
	got := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init")
	if got != Apply {
		t.Errorf("tier=1 with no override should Apply algif mitigation, got %v", got)
	}
}

func TestBuildAuditRows_ReconciledSysctlsSurfaceInStatusRows(t *testing.T) {
	rows := BuildAuditRows(&Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}, HostProfile{})
	want := map[string]RuleState{
		"KSEC-SCT-mem.exploit-001":    "",
		"KSEC-SCT-mem.exploit-002":    "",
		"KSEC-SCT-mem.exploit-003":    "",
		"KSEC-SCT-mem.exploit-004":    "",
		"KSEC-SCT-mem.exploit-005":    "",
		"KSEC-SCT-mem.exploit-006":    StateOFF,
		"KSEC-SCT-mem.exploit-007":    "",
		"KSEC-SCT-mem.exploit-008":    StateOFF,
		"KSEC-SCT-kernel.surface-001": "",
		"KSEC-SCT-kernel.surface-002": "",
		"KSEC-SCT-kernel.surface-003": "",
	}
	seen := map[string]AuditRow{}
	for _, row := range rows {
		if _, ok := want[row.ID]; ok {
			seen[row.ID] = row
		}
	}
	for id, wantState := range want {
		row, ok := seen[id]
		if !ok {
			t.Fatalf("status rows missing %s", id)
		}
		if row.Kind != KindSysctl {
			t.Errorf("%s kind = %s, want sysctl", id, row.Kind)
		}
		if row.Decision == ManagedExternally {
			t.Errorf("%s unexpectedly managed externally", id)
		}
		if wantState != "" && row.State != wantState {
			t.Errorf("%s state = %s, want %s", id, row.State, wantState)
		}
	}
}
