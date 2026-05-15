//go:build linux

package lsm

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// lsmHookParamCount reports the kernel LSM hook's argument count for
// the given BPF trampoline symbol (e.g. "bpf_lsm_inode_setattr"). The
// returned number is the number of *hook arguments* the kernel
// declares — it does NOT include the synthetic `ret` slot that the
// BPF trampoline appends and that BPF_PROG sees.
//
// Empirically (cilium/ebpf v0.21 against EL9 5.14): bpftool dumps
// `bpf_lsm_inode_setattr` with vlen=3 (dentry, attr, ret) but
// cilium/ebpf's FuncProto.Params returns 2 (dentry, attr). This
// function returns the cilium/ebpf view because that is what the
// caller will compare against the per-variant declared arg counts.
//
// Resolves against the live kernel BTF via cilium/ebpf's
// btf.LoadKernelSpec(); the daemon's preflight has already verified
// /sys/kernel/btf/vmlinux is present, so this is the fast path.
func lsmHookParamCount(hookName string) (int, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, fmt.Errorf("load kernel BTF: %w", err)
	}
	var fn *btf.Func
	if err := spec.TypeByName(hookName, &fn); err != nil {
		return 0, fmt.Errorf("look up %s in kernel BTF: %w", hookName, err)
	}
	fp, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("kernel BTF entry %s is not a FuncProto", hookName)
	}
	return len(fp.Params), nil
}

// lsmDriftVariant names a pair of BPF program variants that exist
// because a single LSM hook drifted in argument count across kernels.
type lsmDriftVariant struct {
	// hook is the kernel BTF symbol used for arity detection,
	// e.g. "bpf_lsm_inode_setattr".
	hook string

	// noidmap is the program name compiled for the pre-mnt_idmap
	// signature (EL9 / pre-5.12 upstream).
	noidmap string

	// idmap is the program name compiled for the mnt_userns/mnt_idmap
	// signature (upstream 5.12+ / EL10).
	idmap string

	// noidmapHookArgs is the kernel-declared hook argument count
	// matching the `noidmap` variant, as reported by
	// lsmHookParamCount (i.e. WITHOUT the synthetic ret slot).
	noidmapHookArgs int

	// idmapHookArgs is the matching hook arg count for `idmap`.
	idmapHookArgs int
}

// lsmDriftVariants is the set of LSM hooks whose BPF trampoline arity
// differs across the kernels we support. Add to this slice if a future
// hook starts drifting.
//
// The expected counts are kernel HOOK arg counts (no ret slot) because
// that's what lsmHookParamCount reports — see its godoc for why.
var lsmDriftVariants = []lsmDriftVariant{
	{
		hook:            "bpf_lsm_inode_setattr",
		noidmap:         "cfm_fs005_setattr_noidmap",
		idmap:           "cfm_fs005_setattr_idmap",
		noidmapHookArgs: 2, // (dentry, iattr) — EL9 / pre-5.12
		idmapHookArgs:   3, // (mnt_userns_or_idmap, dentry, iattr)
	},
	{
		hook:            "bpf_lsm_inode_setxattr",
		noidmap:         "cfm_fs005_setxattr_noidmap",
		idmap:           "cfm_fs005_setxattr_idmap",
		noidmapHookArgs: 5, // (dentry, name, value, size, flags)
		idmapHookArgs:   6, // + first arg mnt_userns/mnt_idmap
	},
}

// selectLsmDriftVariants inspects the kernel's BTF for each drifting
// LSM hook and replaces the wrong-arity BPF program's instructions
// with a trivial `return 0` so it loads harmlessly. The Go loader
// then attaches only the surviving variant via programsFor().
//
// Returns a map keyed by hook name with the chosen program name, so
// the caller can wire programsFor() to the right ebpf.Program field.
//
// Why neutralise rather than delete from spec.Programs: the bpf2go-
// generated cfmlsmObjects struct has a tagged field for every program
// in the .o, and LoadAndAssign fails fast if any tagged program is
// missing from the spec. Replacing the wrong-arity variant with a
// no-op satisfies LoadAndAssign (the program still exists under its
// name) while costing only ~16 bytes of kernel memory; nothing
// attaches to it because programsFor() returns the chosen variant.
func selectLsmDriftVariants(spec *ebpf.CollectionSpec) (map[string]string, error) {
	chosen := make(map[string]string, len(lsmDriftVariants))
	for _, d := range lsmDriftVariants {
		// If neither variant is in the spec, this is an older .o
		// that pre-dates the split; nothing to do.
		_, haveNo := spec.Programs[d.noidmap]
		_, haveYes := spec.Programs[d.idmap]
		if !haveNo && !haveYes {
			continue
		}

		n, err := lsmHookParamCount(d.hook)
		if err != nil {
			return nil, fmt.Errorf("probe %s: %w", d.hook, err)
		}
		var keep, drop string
		switch n {
		case d.noidmapHookArgs:
			keep, drop = d.noidmap, d.idmap
		case d.idmapHookArgs:
			keep, drop = d.idmap, d.noidmap
		default:
			return nil, fmt.Errorf("kernel exposes %s with %d hook args; expected %d (no-idmap) or %d (idmap). "+
				"This kernel may have introduced a third LSM hook signature; report the kernel version "+
				"and `bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A8 'bpf_lsm_inode_'` output upstream.",
				d.hook, n, d.noidmapHookArgs, d.idmapHookArgs)
		}
		// The chosen variant must actually be in the spec, otherwise
		// programsFor() would silently drop the entry at attach time
		// (FS-005 would attach only 7 of 9 sub-programs without saying
		// why). Surface that here as a load failure instead.
		if _, ok := spec.Programs[keep]; !ok {
			return nil, fmt.Errorf("kernel needs %s variant %q for %s but it is not in the embedded BPF object; "+
				"run `make bpf` to regenerate, or check that cfmlsm.bpf.c carries both _noidmap and _idmap variants",
				humanArity(n), keep, d.hook)
		}
		if err := neutraliseProgramSpec(spec, drop); err != nil {
			// Drop variant missing is fine — there's just nothing
			// to neutralise. Any other error is real.
			if !errors.Is(err, errProgramNotInSpec) {
				return nil, fmt.Errorf("neutralise %s: %w", drop, err)
			}
		}
		chosen[d.hook] = keep
	}
	return chosen, nil
}

// humanArity labels an arity for diagnostic messages.
func humanArity(n int) string {
	return fmt.Sprintf("%d-hook-arg", n)
}

// errProgramNotInSpec is returned by neutraliseProgramSpec when the
// caller asked it to rewrite a program that isn't in the spec. The
// selector treats it as non-fatal — there's no wrong-arity variant
// to disable. Other neutralisation failures bubble up.
var errProgramNotInSpec = errors.New("program not in spec")

// neutraliseProgramSpec rewrites name's instructions to a minimal
// `r0 = 0; exit` no-op. The program type and attach target stay
// untouched so LoadAndAssign still satisfies its tagged struct field;
// the verifier accepts the program on any LSM hook because the no-op
// reads no ctx fields. Nothing else attaches to it.
func neutraliseProgramSpec(spec *ebpf.CollectionSpec, name string) error {
	ps, ok := spec.Programs[name]
	if !ok {
		return errProgramNotInSpec
	}
	ps.Instructions = asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
	return nil
}
