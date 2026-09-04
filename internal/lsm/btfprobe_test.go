//go:build linux

package lsm

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestSelectLsmDriftVariants_NeutralisesWrongArity exercises the BTF-
// driven variant selector against an in-memory spec. We don't load
// into the kernel here — the kernel under tests is whatever the CI
// runner uses and we cannot assume its hook arity. Instead we verify
// that selectLsmDriftVariants picks ONE variant and replaces the
// other's instructions with a no-op, leaving the chosen variant's
// instructions untouched. The kernel-side probe behaviour itself is
// covered by the integration test (TestLoaderAttachSensitiveWrite).
func TestSelectLsmDriftVariants_NeutralisesWrongArity(t *testing.T) {
	// Build a minimal CollectionSpec containing both variants of one
	// drifting hook. Real-looking instructions so we can detect the
	// no-op rewrite by comparing length.
	realInsns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 1),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"cfm_fs005_setattr_noidmap": {
				Name:         "cfm_fs005_setattr_noidmap",
				Type:         ebpf.LSM,
				Instructions: append(asm.Instructions{}, realInsns...),
			},
			"cfm_fs005_setattr_idmap": {
				Name:         "cfm_fs005_setattr_idmap",
				Type:         ebpf.LSM,
				Instructions: append(asm.Instructions{}, realInsns...),
			},
			// inode_setxattr absent from spec — selector must tolerate
			// drift entries whose variants are missing without erroring.
		},
	}

	picks, err := selectLsmDriftVariants(spec)
	if err != nil {
		// BTF probe is allowed to fail on a sandboxed CI runner that
		// lacks /sys/kernel/btf/vmlinux; skip rather than fail.
		if strings.Contains(err.Error(), "load kernel BTF") ||
			strings.Contains(err.Error(), "look up bpf_lsm_") {
			t.Skipf("kernel BTF not accessible: %v", err)
		}
		t.Fatalf("selectLsmDriftVariants: %v", err)
	}

	chosen, ok := picks["bpf_lsm_inode_setattr"]
	if !ok {
		t.Fatal("selector did not pick a variant for bpf_lsm_inode_setattr")
	}
	if chosen != "cfm_fs005_setattr_noidmap" && chosen != "cfm_fs005_setattr_idmap" {
		t.Fatalf("unexpected pick: %q", chosen)
	}

	// The chosen variant must still have the original instruction
	// stream; the other must be exactly the 2-insn no-op.
	other := "cfm_fs005_setattr_idmap"
	if chosen == other {
		other = "cfm_fs005_setattr_noidmap"
	}
	if got := len(spec.Programs[chosen].Instructions); got != len(realInsns) {
		t.Errorf("chosen variant %q instructions rewritten (%d insns, want %d)",
			chosen, got, len(realInsns))
	}
	if got := len(spec.Programs[other].Instructions); got != 2 {
		t.Errorf("neutralised variant %q has %d insns, want 2 (mov+return)",
			other, got)
	}

	// xattr absent — must not appear in picks.
	if _, ok := picks["bpf_lsm_inode_setxattr"]; ok {
		t.Error("selector picked a variant for bpf_lsm_inode_setxattr when neither was in the spec")
	}
}

// TestEmitLoadFailureHint maps each known error class to its hint
// pattern. Cheap regression guard against accidental hint regressions.
func TestEmitLoadFailureHint(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		expect string
	}{
		{
			name:   "verifier rejects arg count",
			err:    errors.New(`load BPF objects: field CfmFs005Setattr: program cfm_fs005_setattr: load program: permission denied: func 'bpf_lsm_inode_setattr' doesn't have 4-th argument`),
			expect: "different arity",
		},
		{
			name:   "BTF probe itself failed",
			err:    errors.New("probe LSM hook signatures: load kernel BTF: open /sys/kernel/btf/vmlinux: no such file or directory"),
			expect: "Could not read kernel BTF",
		},
		{
			name:   "generic load failure falls back to audit.log hint",
			err:    errors.New("some other failure"),
			expect: "SELinux/AppArmor",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			emitLoadFailureHint(&buf, tc.err)
			if !strings.Contains(buf.String(), tc.expect) {
				t.Errorf("hint for %q lacks %q\ngot: %s", tc.name, tc.expect, buf.String())
			}
		})
	}
}

// newTaskStorageTestSpec builds a minimal in-memory spec with the
// task-storage map and its two users plus one unrelated program, so we
// can assert selectTaskStorageVariant's surgery without a real kernel.
func newTaskStorageTestSpec() *ebpf.CollectionSpec {
	realInsns := asm.Instructions{
		asm.Mov.Imm(asm.R1, 1),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
	tsMap := func(name string) *ebpf.MapSpec {
		return &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.TaskStorage,
			Flags:      1, // BPF_F_NO_PREALLOC
			KeySize:    4,
			ValueSize:  8,
			MaxEntries: 0,
		}
	}
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			// BOTH task-storage maps embedded in the real object, so the
			// test catches a downgrade that handles only one of them.
			cfmlsmMapCfmCredTransitionTasks: tsMap(cfmlsmMapCfmCredTransitionTasks),
			cfmlsmMapCfmWebOriginTasks:      tsMap(cfmlsmMapCfmWebOriginTasks),
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"cfm_cred002": {Name: "cfm_cred002", Type: ebpf.LSM, Instructions: append(asm.Instructions{}, realInsns...)},
			"cfm_cred003": {Name: "cfm_cred003", Type: ebpf.Tracing, Instructions: append(asm.Instructions{}, realInsns...)},
			"cfm_other":   {Name: "cfm_other", Type: ebpf.LSM, Instructions: append(asm.Instructions{}, realInsns...)},
		},
	}
}

func TestSelectTaskStorageVariant_NativeWhenSupported(t *testing.T) {
	prev := preflightTaskStorageMapProbe
	preflightTaskStorageMapProbe = func() error { return nil }
	t.Cleanup(func() { preflightTaskStorageMapProbe = prev })

	spec := newTaskStorageTestSpec()
	shape, err := selectTaskStorageVariant(spec)
	if err != nil {
		t.Fatalf("selectTaskStorageVariant: %v", err)
	}
	if shape != "native" {
		t.Errorf("shape: got %q, want native", shape)
	}
	if got := spec.Maps[cfmlsmMapCfmCredTransitionTasks].Type; got != ebpf.TaskStorage {
		t.Errorf("map type must be untouched when supported; got %v", got)
	}
	if got := len(spec.Programs["cfm_cred002"].Instructions); got != 4 {
		t.Errorf("cfm_cred002 must be untouched when supported; got %d insns", got)
	}
	if got := len(spec.Programs["cfm_cred003"].Instructions); got != 4 {
		t.Errorf("cfm_cred003 must be untouched when supported; got %d insns", got)
	}
}

func TestSelectTaskStorageVariant_DowngradesWhenUnsupported(t *testing.T) {
	prev := preflightTaskStorageMapProbe
	preflightTaskStorageMapProbe = func() error { return ebpf.ErrNotSupported }
	t.Cleanup(func() { preflightTaskStorageMapProbe = prev })

	spec := newTaskStorageTestSpec()
	shape, err := selectTaskStorageVariant(spec)
	if err != nil {
		t.Fatalf("selectTaskStorageVariant: %v", err)
	}
	if shape != "downgraded" {
		t.Fatalf("shape: got %q, want downgraded", shape)
	}
	// BOTH task-storage maps must be rewritten to creatable HASH
	// placeholders — missing either one leaves a TASK_STORAGE map that
	// still fails LoadAndAssign on the target kernel.
	for _, name := range []string{cfmlsmMapCfmCredTransitionTasks, cfmlsmMapCfmWebOriginTasks} {
		m := spec.Maps[name]
		if m.Type != ebpf.Hash {
			t.Errorf("%s type: got %v, want Hash", name, m.Type)
		}
		if m.MaxEntries == 0 || m.KeySize == 0 || m.ValueSize == 0 {
			t.Errorf("%s placeholder must have non-zero key/value/max_entries; got key=%d val=%d max=%d", name, m.KeySize, m.ValueSize, m.MaxEntries)
		}
		if m.Flags != 0 {
			t.Errorf("%s placeholder flags must be cleared; got %d", name, m.Flags)
		}
		if m.Key != nil || m.Value != nil {
			t.Errorf("%s placeholder BTF key/value must be cleared", name)
		}
	}
	// No map may remain TASK_STORAGE-typed after the downgrade.
	for name, m := range spec.Maps {
		if m.Type == ebpf.TaskStorage {
			t.Errorf("map %s still TASK_STORAGE after downgrade", name)
		}
	}
	// The two cred-transition users must be neutralised to r0=0; exit (2 insns).
	if got := len(spec.Programs["cfm_cred002"].Instructions); got != 2 {
		t.Errorf("cfm_cred002 must be neutralised; got %d insns, want 2", got)
	}
	if got := len(spec.Programs["cfm_cred003"].Instructions); got != 2 {
		t.Errorf("cfm_cred003 must be neutralised; got %d insns, want 2", got)
	}
	// An unrelated program must be left intact.
	if got := len(spec.Programs["cfm_other"].Instructions); got != 4 {
		t.Errorf("cfm_other must be untouched; got %d insns, want 4", got)
	}
}

func TestSelectTaskStorageVariant_NativeOnAmbiguousProbeError(t *testing.T) {
	prev := preflightTaskStorageMapProbe
	preflightTaskStorageMapProbe = func() error { return errors.New("operation not permitted") }
	t.Cleanup(func() { preflightTaskStorageMapProbe = prev })

	spec := newTaskStorageTestSpec()
	shape, err := selectTaskStorageVariant(spec)
	if err != nil {
		t.Fatalf("selectTaskStorageVariant: %v", err)
	}
	if shape != "native" {
		t.Errorf("an ambiguous probe error must leave the spec native; got shape %q", shape)
	}
	if got := spec.Maps[cfmlsmMapCfmCredTransitionTasks].Type; got != ebpf.TaskStorage {
		t.Errorf("map must be untouched on ambiguous error; got %v", got)
	}
}

// TestSelectTaskStorageVariant_RealSpec_LeavesNoTaskStorageMap loads the
// ACTUAL embedded BPF object (not a synthetic spec) and asserts the
// downgrade leaves zero TASK_STORAGE-typed maps and forces the FS-005
// web-origin monitor off. This is the regression guard for "a new
// task-storage map was added to the C source but not handled by the
// downgrade" — the exact class of bug that shipped a half-done degrade.
func TestSelectTaskStorageVariant_RealSpec_LeavesNoTaskStorageMap(t *testing.T) {
	spec, err := loadCfmlsm()
	if err != nil {
		t.Fatalf("loadCfmlsm: %v", err)
	}

	// Sanity: the real object must actually contain task-storage maps,
	// otherwise this test would pass vacuously.
	var tsBefore int
	for _, m := range spec.Maps {
		if m.Type == ebpf.TaskStorage {
			tsBefore++
		}
	}
	if tsBefore == 0 {
		t.Fatal("real object has no TASK_STORAGE maps — test would be vacuous")
	}

	prev := preflightTaskStorageMapProbe
	preflightTaskStorageMapProbe = func() error { return ebpf.ErrNotSupported }
	t.Cleanup(func() { preflightTaskStorageMapProbe = prev })

	shape, err := selectTaskStorageVariant(spec)
	if err != nil {
		t.Fatalf("selectTaskStorageVariant: %v", err)
	}
	if shape != "downgraded" {
		t.Fatalf("shape: got %q, want downgraded", shape)
	}

	// The whole point: no map may remain TASK_STORAGE-typed, or the real
	// LoadAndAssign would still fail on a task-storage-free kernel.
	for name, m := range spec.Maps {
		if m.Type == ebpf.TaskStorage {
			t.Errorf("map %s still TASK_STORAGE after downgrade — LoadAndAssign would still fail", name)
		}
	}

	// FS-005's web-origin monitor must be forced off so its
	// bpf_task_storage_get calls are dead-code-eliminated.
	vs, ok := spec.Variables[cfmlsmVarCfmFs005WebOriginMonitor]
	if !ok {
		t.Fatalf("real object missing variable %s", cfmlsmVarCfmFs005WebOriginMonitor)
	}
	var monitor uint8
	if err := vs.Get(&monitor); err != nil {
		t.Fatalf("read %s: %v", cfmlsmVarCfmFs005WebOriginMonitor, err)
	}
	if monitor != 0 {
		t.Errorf("%s: got %d, want 0 (forced off on downgrade)", cfmlsmVarCfmFs005WebOriginMonitor, monitor)
	}

	// The cred-transition users must be neutralised.
	for _, n := range []string{"cfm_cred002", "cfm_cred003"} {
		if ps, ok := spec.Programs[n]; ok {
			if got := len(ps.Instructions); got != 2 {
				t.Errorf("%s must be neutralised to 2 insns; got %d", n, got)
			}
		}
	}
}
