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
