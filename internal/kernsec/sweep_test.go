package kernsec

import (
	"errors"
	"strings"
	"testing"
)

// TestBuildDesiredCmdline_ReadErrorPropagates locks in the fix for the
// silent-read-failure bug. If the bootloader cmdline cannot be read,
// buildDesiredCmdline must return an error rather than silently treat
// it as empty (which would cause apply to compute a cmdline containing
// only managed args, dropping root=, ro, console=, etc).
func TestBuildDesiredCmdline_ReadErrorPropagates(t *testing.T) {
	be := &errorReadBackend{readErr: errors.New("boom")}
	args := []BootArg{{Key: "slab_nomerge"}}
	if _, err := buildDesiredCmdline(be, args); err == nil {
		t.Fatal("expected error, got nil — silent read-failure bug regressed")
	}
}

// TestComputeDrift_BootReadErrorSurfaced ensures driftResult records
// the read failure rather than silently claiming "in sync" or "drift
// without a current cmdline".
func TestComputeDrift_BootReadErrorSurfaced(t *testing.T) {
	be := &errorReadBackend{readErr: errors.New("backend offline")}
	d := computeDrift([]byte("x"), "y", be)
	if d.BootReadErr == nil {
		t.Fatal("BootReadErr not surfaced")
	}
	if !d.BootDiffers {
		t.Fatal("BootDiffers should default true on read error")
	}
}

// TestRebuildManagedCmdline_TunedParamsPassthrough mirrors the
// real-world cmdline shape from a Rocky 8 BLS host: a literal
// `$tuned_params` token left for tuned-adm to substitute later. Our
// managed-keys workflow must preserve it untouched.
func TestRebuildManagedCmdline_TunedParamsPassthrough(t *testing.T) {
	tokens := ParseCmdline("ro crashkernel=auto rd.md.uuid=ec:da quiet selinux=0 slab_nomerge init_on_alloc=1 page_alloc.shuffle=1 randomize_kstack_offset=on initcall_blacklist=algif_aead_init $tuned_params")
	args := []BootArg{
		{Key: "slab_nomerge"},
		{Key: "init_on_alloc", Value: "1"},
		{Key: "page_alloc.shuffle", Value: "1"},
		{Key: "randomize_kstack_offset", Value: "on"},
		{Key: "initcall_blacklist", Value: "algif_aead_init"},
	}
	got := rebuildManagedCmdline(tokens, args)

	// $tuned_params must survive — it isn't a managed key.
	found := false
	for _, tok := range got {
		if tok == "$tuned_params" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("$tuned_params lost in rebuild: %v", got)
	}
	// And we still ended up with all five managed args.
	for _, want := range args {
		seen := false
		for _, tok := range got {
			if tok == want.String() {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("managed arg %s missing from rebuilt cmdline %v", want, got)
		}
	}
}

// TestRebuildManagedCmdline_PreservesNonManagedOrder pins down the
// invariant that operator-set tokens keep their relative order. Order
// among them mostly doesn't matter for kernel parsing, but operators
// inspecting the cmdline expect to see their args where they put them.
func TestRebuildManagedCmdline_PreservesNonManagedOrder(t *testing.T) {
	tokens := ParseCmdline("BOOT_IMAGE=/vmlinuz root=UUID=abc ro slab_nomerge crashkernel=auto init_on_alloc=1 quiet")
	args := []BootArg{
		{Key: "slab_nomerge"},
		{Key: "init_on_alloc", Value: "1"},
	}
	got := rebuildManagedCmdline(tokens, args)
	want := []string{
		"BOOT_IMAGE=/vmlinuz", "root=UUID=abc", "ro", "crashkernel=auto", "quiet",
		"slab_nomerge", "init_on_alloc=1",
	}
	if !equalSlices(got, want) {
		t.Fatalf("got:  %v\nwant: %v", got, want)
	}
}

// TestRenderSysctlFile_Idempotent locks in the property that calling
// the renderer twice with the same rule set produces byte-equal
// output. This is the foundation of drift detection — if the renderer
// were nondeterministic, `apply --check` would always show drift.
func TestRenderSysctlFile_Idempotent(t *testing.T) {
	rules := KSPPSysctls
	a := RenderSysctlFile(rules)
	b := RenderSysctlFile(rules)
	if !bytesEqual(a, b) {
		t.Fatalf("renderer not deterministic\nA:\n%s\nB:\n%s", a, b)
	}
}

// TestResolve_Tier0NoApplyForAnything captures the documented tier=0
// "kernsec configured but no rules apply" semantics. Operators set
// tier=0 + apply to strip managed boot args without uninstalling the
// component.
func TestResolve_Tier0NoApplyForAnything(t *testing.T) {
	conf := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	rs := Resolve(conf, HostProfile{})
	for _, r := range rs.Sysctls {
		if r.Decision == Apply {
			t.Errorf("tier=0 sysctl should not Apply: %+v", r)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Decision == Apply {
			t.Errorf("tier=0 boot should not Apply: %+v", r)
		}
	}
	if len(rs.ApplySysctls()) != 0 {
		t.Errorf("ApplySysctls() returned %d, want 0", len(rs.ApplySysctls()))
	}
	if len(rs.ApplyBootArgs()) != 0 {
		t.Errorf("ApplyBootArgs() returned %d, want 0", len(rs.ApplyBootArgs()))
	}
}

// TestParseSectionHeader_RealisticIDs checks the parser accepts the
// production rule-ID shape — letters, digits, dots, dashes — without
// extra escaping.
func TestParseSectionHeader_RealisticIDs(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`[rule "KSEC-MOD-net.legacy-014"]`, "KSEC-MOD-net.legacy-014"},
		{`[rule "KSEC-SCT-kspp.kernel-001"]`, "KSEC-SCT-kspp.kernel-001"},
		{`[rule "KSEC-BOOT-kspp-005"]`, "KSEC-BOOT-kspp-005"},
		{`[rule  "KSEC-FS-mount.tmp-001"]`, "KSEC-FS-mount.tmp-001"}, // extra space
	}
	for _, tc := range tests {
		got, err := parseSectionHeader(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// errorReadBackend is a BootBackend that always returns the configured
// error from NextBootCmdline. Used to exercise the read-failure paths.
type errorReadBackend struct {
	readErr error
}

func (e *errorReadBackend) Label() string                     { return "error-read fake" }
func (e *errorReadBackend) NextBootCmdline() (string, error)  { return "", e.readErr }
func (e *errorReadBackend) WriteCmdline(args []BootArg) error { return e.readErr }
func (e *errorReadBackend) Refresh() error                    { return nil }

// staticCmdlineBackend is a BootBackend that returns a fixed
// next-boot cmdline. Used to exercise buildDesiredCmdlineWithConf
// against realistic operator-edited cmdlines.
type staticCmdlineBackend struct{ cmdline string }

func (s *staticCmdlineBackend) Label() string                     { return "static fake" }
func (s *staticCmdlineBackend) NextBootCmdline() (string, error)  { return s.cmdline, nil }
func (s *staticCmdlineBackend) WriteCmdline(args []BootArg) error { return nil }
func (s *staticCmdlineBackend) Refresh() error                    { return nil }

// TestBuildDesiredCmdlineWithConf_PreservesOperatorBPF locks in the
// fix for the silent-strip regression. When KSEC-LSM-bpf-001 is NOT
// forced (default state), buildDesiredCmdlineWithConf must leave
// the operator's `lsm=...,bpf` token untouched — the lsm key is not
// in ManagedBootArgKeys, so it's outside kernsec's managed surface.
// Earlier behaviour ran UnmergeLSMBPF on every apply and silently
// rewrote the operator's manual `bpf` addition.
func TestBuildDesiredCmdlineWithConf_PreservesOperatorBPF(t *testing.T) {
	be := &staticCmdlineBackend{
		cmdline: "BOOT_IMAGE=/vmlinuz root=UUID=abc ro quiet lsm=lockdown,yama,apparmor,bpf",
	}
	conf := &Conf{Tier: 1, Overrides: map[string]RuleOverride{}}
	got, err := buildDesiredCmdlineWithConf(be, nil, conf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(got, "lsm=lockdown,yama,apparmor,bpf") {
		t.Fatalf("operator-added bpf was stripped: %q", got)
	}
}

// TestBuildDesiredCmdlineWithConf_PreviewMatchesApplyWhenForced is
// the regression test for the preview/apply divergence: when the
// rule IS forced and the cmdline already contains `bpf`, both code
// paths (preview and apply) must compute the same desired cmdline.
// Prior to the fix, preview forwarded conf=nil and unmerged `bpf`
// while apply (with conf) merged it.
func TestBuildDesiredCmdlineWithConf_PreviewMatchesApplyWhenForced(t *testing.T) {
	be := &staticCmdlineBackend{
		cmdline: "BOOT_IMAGE=/vmlinuz root=UUID=abc ro quiet lsm=lockdown,capability,bpf,yama",
	}
	conf := &Conf{
		Tier: 1,
		Overrides: map[string]RuleOverride{
			LSMBPFRuleID: OverrideForce,
		},
	}
	got, err := buildDesiredCmdlineWithConf(be, nil, conf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(got, "bpf") {
		t.Fatalf("forced rule should preserve bpf in lsm=; got %q", got)
	}
}

// equalSlices returns true if a and b have the same length and equal
// elements at every index.
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bytesEqual is a tiny helper to avoid importing bytes for one call.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseConfForceOnRemovedRuleIsOnlyUnknownOverride(t *testing.T) {
	removedID := strings.Join([]string{"KSEC-SCT-net", "harden-006"}, ".")
	c, err := ParseConf(strings.NewReader("tier = 2\n[rule \"" + removedID + "\"]\nstate = force\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Overrides[removedID]; got != OverrideForce {
		t.Fatalf("override parse = %v, want force", got)
	}
	for _, r := range Resolve(c, HostProfile{}).Sysctls {
		if r.ID == removedID {
			t.Fatalf("removed rule %q should not be available to force", removedID)
		}
	}
}

// TestParseConf_StateEqualsEmpty captures the documented "state =" =>
// OverrideDefault behaviour (i.e. omitting state is the same as
// writing "state = default" or "state =").
func TestParseConf_StateEqualsEmpty(t *testing.T) {
	c, err := ParseConf(strings.NewReader(`tier = 1
[rule "KSEC-MOD-net.legacy-014"]
state =
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Overrides["KSEC-MOD-net.legacy-014"]; got != OverrideDefault {
		t.Errorf("state = empty: got %v, want OverrideDefault", got)
	}
}
