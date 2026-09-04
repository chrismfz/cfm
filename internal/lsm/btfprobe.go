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

	// pickKey is the identifier the chosen-program-name is stored
	// under in the Loader's driftPicks map (and looked up via
	// pickedDriftProgram). Defaults to `hook` when empty. Specified
	// separately so multiple policies can attach to the same kernel
	// hook with different program-name pairs — e.g. FS-005 and
	// FS-007 both hook inode_setattr but with distinct (noidmap,
	// idmap) variant program names.
	pickKey string

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

// keyFor returns the picks-map key for this variant — pickKey when
// set, otherwise hook for backward compatibility with entries that
// have only one (noidmap, idmap) program pair per kernel hook.
func (d lsmDriftVariant) keyFor() string {
	if d.pickKey != "" {
		return d.pickKey
	}
	return d.hook
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
	// CFML-FS-007 shares the inode_setattr / inode_setxattr hooks with
	// FS-005 but compiles its own program-name pair so the two
	// policies can be enabled / disabled / enforced independently.
	{
		hook:            "bpf_lsm_inode_setattr",
		pickKey:         "bpf_lsm_inode_setattr_fs007",
		noidmap:         "cfm_fs007_setattr_noidmap",
		idmap:           "cfm_fs007_setattr_idmap",
		noidmapHookArgs: 2,
		idmapHookArgs:   3,
	},
	{
		hook:            "bpf_lsm_inode_setxattr",
		pickKey:         "bpf_lsm_inode_setxattr_fs007",
		noidmap:         "cfm_fs007_setxattr_noidmap",
		idmap:           "cfm_fs007_setxattr_idmap",
		noidmapHookArgs: 5,
		idmapHookArgs:   6,
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
		chosen[d.keyFor()] = keep
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

// credCapAmbientShape reports the layout of struct cred's
// `cap_ambient` field in the live kernel's BTF. CFML-CRED-004's BPF
// program copes with both known shapes via bpf_core_field_exists, so
// this helper exists only as a defensive net: if the kernel exposes
// some THIRD layout we haven't seen, the BPF program would emit a
// poisoned CO-RE relocation and the kernel verifier would reject the
// whole load with "invalid func unknown#NNN". Neutralising
// cfm_cred004 in that case keeps the other thirteen policies
// loadable.
//
// Returns one of:
//   - "modern":  kernel_cap_t = struct { __u64 val; }     — Linux 6.3+
//   - "legacy":  kernel_cap_t = struct kernel_cap_struct { __u32 cap[2]; }
//     — pre-6.3 (EL9 5.14)
//   - "unknown": neither shape matches; caller should neutralise.
func credCapAmbientShape() (string, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return "", fmt.Errorf("load kernel BTF: %w", err)
	}
	var credT *btf.Struct
	if err := spec.TypeByName("cred", &credT); err != nil {
		return "", fmt.Errorf("look up struct cred in kernel BTF: %w", err)
	}
	var capAmbient *btf.Member
	for i := range credT.Members {
		if credT.Members[i].Name == "cap_ambient" {
			capAmbient = &credT.Members[i]
			break
		}
	}
	if capAmbient == nil {
		return "", fmt.Errorf("struct cred has no cap_ambient member in kernel BTF")
	}
	// Walk through any typedef wrappers (kernel_cap_t) to the
	// underlying struct.
	t := btf.UnderlyingType(capAmbient.Type)
	st, ok := t.(*btf.Struct)
	if !ok {
		return "unknown", nil
	}
	hasVal, hasCap := false, false
	for i := range st.Members {
		switch st.Members[i].Name {
		case "val":
			hasVal = true
		case "cap":
			hasCap = true
		}
	}
	switch {
	case hasVal:
		return "modern", nil
	case hasCap:
		return "legacy", nil
	default:
		return "unknown", nil
	}
}

// errMapNotInSpec is returned by downgradeTaskStorageMapSpec when the
// map it was asked to rewrite is absent from the spec. The selector
// treats it as non-fatal — there is nothing to downgrade.
var errMapNotInSpec = errors.New("map not in spec")

// downgradeTaskStorageMapSpec rewrites the cfm_cred_transition_tasks map
// spec from BPF_MAP_TYPE_TASK_STORAGE to a tiny, universally-creatable
// BPF_MAP_TYPE_HASH placeholder. Used only on kernels that backport BPF
// LSM programs but not task-local storage (upstream 5.11) — e.g.
// CloudLinux 8 lve 4.18. The map is referenced only by cfm_cred002 /
// cfm_cred003 (via bpf_task_storage_get); those are neutralised in the
// same pass, so the placeholder is created but never used.
//
// Rewriting (rather than deleting) the map is required because the
// bpf2go-generated cfmlsmObjects struct has a field tagged for this map,
// and LoadAndAssign fails the whole load if a struct field has no
// matching spec entry. A 1-entry HASH with cleared BTF creates on every
// kernel that supports BPF LSM at all.
func downgradeTaskStorageMapSpec(spec *ebpf.CollectionSpec) error {
	ms, ok := spec.Maps[cfmlsmMapCfmCredTransitionTasks]
	if !ok {
		return errMapNotInSpec
	}
	ms.Type = ebpf.Hash
	ms.Flags = 0
	ms.KeySize = 4
	ms.ValueSize = 8
	ms.MaxEntries = 1
	// Clear BTF + static contents so the placeholder carries no
	// task-storage-specific type info the downgraded kernel might reject.
	ms.Key = nil
	ms.Value = nil
	ms.Contents = nil
	return nil
}

// selectTaskStorageVariant makes the shared BPF object loadable on
// kernels without task-local storage maps. When the map-type probe
// reports BPF_MAP_TYPE_TASK_STORAGE unsupported, it neutralises the two
// programs that use the map (cfm_cred002 / cfm_cred003 → CFML-CRED-002 /
// CFML-CRED-003) and downgrades the map spec to a HASH placeholder, so
// LoadAndAssign succeeds and the remaining policies attach instead of
// the whole object failing with "map create: invalid argument".
//
// Returns the shape for logging/diagnostics:
//   - "native"     → task-storage supported; spec untouched.
//   - "downgraded" → map + its two programs neutralised.
//
// Only a definitive ErrNotSupported triggers the downgrade. Any other
// probe error (EPERM without caps, a transient failure) leaves the spec
// native: the load then fails cleanly and preflight/caps surface the
// real reason, rather than silently dropping two policies on an
// ambiguous signal.
//
// The probe (features.HaveMapType) is memoized process-wide by
// cilium/ebpf, so the preflight per-policy probes and this loader probe
// share one syscall result and cannot disagree on a definitive answer.
//
// Scope note: this downgrade only addresses the task-storage MAP. The
// object also embeds two fentry/commit_creds programs (cfm_cred003 —
// neutralised here — and cfm_cred004), which LoadAndAssign still loads
// eagerly; a kernel that supports BPF-LSM but not BPF trampolines
// (fentry) would still fail the whole load. That is not a regression
// (such a host previously stayed dormant and now falls back to the same
// dormant + backoff state), and the target kernels — RHEL 8-based
// CloudLinux 8 lve, where the specific gap is task-storage (5.11), not
// fentry (5.5, backported to EL8) — are expected to load the fentry
// programs. If a kernel lacking both surfaces, dropping the fentry
// programs from the load is a separate follow-up.
func selectTaskStorageVariant(spec *ebpf.CollectionSpec) (string, error) {
	err := preflightTaskStorageMapProbe()
	if err == nil {
		return "native", nil
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return "native", nil
	}
	for _, name := range []string{"cfm_cred002", "cfm_cred003"} {
		if nerr := neutraliseProgramSpec(spec, name); nerr != nil &&
			!errors.Is(nerr, errProgramNotInSpec) {
			return "", fmt.Errorf("neutralise %s for task-storage downgrade: %w", name, nerr)
		}
	}
	if derr := downgradeTaskStorageMapSpec(spec); derr != nil &&
		!errors.Is(derr, errMapNotInSpec) {
		return "", fmt.Errorf("downgrade task-storage map: %w", derr)
	}
	return "downgraded", nil
}

// selectCredCapVariant neutralises cfm_cred004 if the kernel exposes
// neither the modern nor the legacy cap_ambient layout. The BPF
// program already handles both known shapes at load time via
// bpf_core_field_exists; this is the third-layout safety net.
//
// Returns the detected shape ("modern", "legacy", "unknown",
// "no-program") for logging.
func selectCredCapVariant(spec *ebpf.CollectionSpec) (string, error) {
	if _, ok := spec.Programs["cfm_cred004"]; !ok {
		return "no-program", nil
	}
	shape, err := credCapAmbientShape()
	if err != nil {
		return "", fmt.Errorf("probe struct cred.cap_ambient shape: %w", err)
	}
	if shape == "unknown" {
		if err := neutraliseProgramSpec(spec, "cfm_cred004"); err != nil &&
			!errors.Is(err, errProgramNotInSpec) {
			return "", fmt.Errorf("neutralise cfm_cred004: %w", err)
		}
	}
	return shape, nil
}

// BTFDriftPick reports the variant the loader will pick for a single
// drifting LSM hook, based on the kernel BTF arity. Diagnostic only —
// does not load any BPF program. Surfaced by `cfm lsm status`,
// `cfm lsm init`, and `cfm lsm probe`.
type BTFDriftPick struct {
	// Hook is the kernel BTF symbol probed, e.g. "bpf_lsm_inode_setattr".
	Hook string
	// Arity is the kernel's hook arg count (0 on probe failure).
	Arity int
	// Picked is the BPF program variant name the loader would
	// select. Empty when the arity does not match any known variant
	// (in which case the loader would fail; surfaced as Reason).
	Picked string
	// PickKey is the policy-specific drift key (e.g.
	// "bpf_lsm_inode_setattr_fs007"), so the operator can tell apart
	// FS-005 and FS-007 picks on the same hook.
	PickKey string
	// Reason is set on failure / unknown-arity.
	Reason string
}

// BTFDiagnostics is the BTF-only snapshot used by status / init /
// probe surfaces. All probes are read-only (no BPF load required).
type BTFDiagnostics struct {
	// DriftPicks reports the picked variant for each drifting LSM
	// hook, one entry per (hook, pickKey) pair.
	DriftPicks []BTFDriftPick

	// CredCapShape is "modern" (6.3+), "legacy" (pre-6.3),
	// "unknown" (third layout — cfm_cred004 would be neutralised at
	// load time), or "btf-unavailable" (kernel BTF could not be
	// loaded; the loader would also neutralise cfm_cred004 in that
	// case — see loader.go).
	CredCapShape string

	// CredCapShapeError, when non-empty, is the BTF-lookup error
	// behind a CredCapShape of "btf-unavailable" or "unknown".
	CredCapShapeError string
}

// RunBTFDiagnostics runs every BTF probe the loader would run, but
// without loading any BPF programs. Intended for status / init /
// probe display: an operator can see what the loader will pick
// before deciding to enable.
//
// Errors are folded into individual fields (DriftPicks[i].Reason,
// CredCapShapeError) so a partial result is still useful — e.g. if
// one hook is missing from BTF but the others resolve fine.
func RunBTFDiagnostics() BTFDiagnostics {
	var diag BTFDiagnostics

	for _, v := range lsmDriftVariants {
		pick := BTFDriftPick{Hook: v.hook, PickKey: v.keyFor()}
		n, err := lsmHookParamCount(v.hook)
		if err != nil {
			pick.Reason = err.Error()
			diag.DriftPicks = append(diag.DriftPicks, pick)
			continue
		}
		pick.Arity = n
		switch n {
		case v.noidmapHookArgs:
			pick.Picked = v.noidmap
		case v.idmapHookArgs:
			pick.Picked = v.idmap
		default:
			pick.Reason = fmt.Sprintf("kernel exposes %s with %d hook args; expected %d or %d",
				v.hook, n, v.noidmapHookArgs, v.idmapHookArgs)
		}
		diag.DriftPicks = append(diag.DriftPicks, pick)
	}

	shape, err := credCapAmbientShape()
	if err != nil {
		diag.CredCapShape = "btf-unavailable"
		diag.CredCapShapeError = err.Error()
	} else {
		diag.CredCapShape = shape
	}

	return diag
}
