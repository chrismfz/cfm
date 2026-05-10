package kernsec

import (
	"fmt"
	"os"
	"strings"
)

// BLSBackend implements BootBackend for BLS / grubby installs
// (RHEL/Alma/Rocky and similar). Reads next-boot args via
// `grubby --info=ALL` (every installed kernel, not just default —
// `apply` rewrites every entry, so the drift check must inspect every
// entry too); writes via a single `grubby --update-kernel=ALL`
// invocation that combines --remove-args and --args.
type BLSBackend struct {
	FS FS
}

func (b *BLSBackend) Label() string {
	return "BLS / grubby"
}

// blsKernelEntry is one kernel block parsed out of grubby --info=ALL.
type blsKernelEntry struct {
	Kernel string // path to kernel image, used for divergence diagnostics
	Args   string // contents of args="..." for this entry
}

// NextBootCmdline returns the args string from grubby --info=ALL.
//
// `WriteCmdline` only rewrites kernsec-managed keys via
// `grubby --update-kernel=ALL --remove-args=<managed> --args=<desired>`,
// so each kernel entry's UNmanaged args (crashkernel=, distro-specific
// tunables, …) legitimately differ across installed kernels. The
// divergence check therefore projects each entry's args through
// KeepManagedArgs first and compares only the managed subset.
//
// If the managed subset diverges between kernels, the args from the
// first entry are returned together with a non-nil error naming the
// divergent kernels — `computeDrift` surfaces this to the operator
// as drift so the next boot doesn't land on a stale entry.
//
// Empty grubby output (no kernels) → ("", nil), matching the previous
// DEFAULT-only behaviour.
func (b *BLSBackend) NextBootCmdline() (string, error) {
	out, err := b.FS.RunCapture("grubby", "--info=ALL")
	if err != nil {
		return "", err
	}
	entries := nonRecoveryKernelEntries(parseGrubbyAll(out))
	if len(entries) == 0 {
		return "", nil
	}
	first := entries[0].Args
	firstManaged := KeepManagedArgs(ParseCmdline(first))
	var diverged []string
	for _, e := range entries[1:] {
		entryManaged := KeepManagedArgs(ParseCmdline(e.Args))
		if !sameTokens(entryManaged, firstManaged) {
			diverged = append(diverged, e.Kernel)
		}
	}
	if len(diverged) > 0 {
		return first, fmt.Errorf(
			"BLS kernel entries diverge on managed args from %s — stale on: %s",
			entries[0].Kernel, strings.Join(diverged, ", "),
		)
	}
	return first, nil
}

// parseGrubbyAll parses the multi-block output of `grubby --info=ALL`.
// Format (one block per kernel, blank lines between):
//
//	index=0
//	kernel="/boot/vmlinuz-6.1.0"
//	args="ro crashkernel=auto slab_nomerge"
//	root="UUID=..."
//	initrd="/boot/initramfs-..."
//	title="..."
//
// Returns one entry per block. Blocks lacking either kernel= or args=
// are still emitted so a divergence check sees them; absent fields are
// "".
func parseGrubbyAll(out string) []blsKernelEntry {
	var (
		entries []blsKernelEntry
		cur     blsKernelEntry
		started bool
	)
	flush := func() {
		if started {
			entries = append(entries, cur)
		}
		cur = blsKernelEntry{}
		started = false
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			// Blank line ends a block.
			flush()
			continue
		case strings.HasPrefix(t, "index="):
			// New block boundary inside the same chunk of output (some
			// grubby builds don't separate blocks with blank lines).
			flush()
			started = true
		case strings.HasPrefix(t, "kernel="):
			started = true
			cur.Kernel = unquoteValue(strings.TrimPrefix(t, "kernel="))
		case strings.HasPrefix(t, "args="):
			started = true
			cur.Args = unquoteValue(strings.TrimPrefix(t, "args="))
		}
	}
	flush()
	return entries
}

// unquoteValue strips one matching pair of leading/trailing double
// quotes around a grubby --info value. Plain prefix.TrimPrefix is not
// enough — grubby quotes args="..." but unquoted index=0 is also valid.
func unquoteValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// writeBLSSnapshot saves the default kernel's args to BLSBackupPath
// exactly once (before the first kernsec write), so `cfm kernsec
// rollback` can replay the pre-kernsec cmdline on BLS hosts.
func (b *BLSBackend) writeBLSSnapshot() error {
	// Already snapshotted — honour the one-shot guarantee.
	if _, err := os.Stat(BLSBackupPath); err == nil {
		return nil
	}
	out, err := b.FS.RunCapture("grubby", "--info=DEFAULT")
	if err != nil {
		// Non-fatal: snapshot is best-effort. The apply still proceeds;
		// rollback will fall back to managed-args-strip mode.
		return nil
	}
	entries := parseGrubbyAll(out)
	var savedArgs string
	if len(entries) > 0 {
		// Strip managed args from the snapshot: we want the pre-kernsec
		// non-managed args, not the managed args that may already be
		// present from a previous partial apply or manual edit.
		clean := RemoveManagedArgs(ParseCmdline(entries[0].Args))
		savedArgs = strings.Join(clean, " ")
	}
	if err := AtomicWriteFile(BLSBackupPath, []byte(savedArgs), 0o644); err != nil {
		// Best-effort; non-fatal.
		return nil
	}
	return nil
}

// WriteCmdline runs a single `grubby --update-kernel=...` invocation
// that combines `--remove-args` (stripping every managed-keys token)
// with `--args=` (the desired set). grubby applies removes before adds
// within a single call, closing the window where every kernel sat
// stripped of managed args between the previous two-call sequence.
//
// Before writing, a one-shot snapshot of the default kernel's pre-kernsec
// args is saved to BLSBackupPath so `cfm kernsec rollback` can recover.
//
// SAFETY (Phase 6 audit C4): the previous code used
// `--update-kernel=ALL` which DOES include `vmlinuz-*-rescue-*` and
// `*-debug` entries — the rescue kernel exists to recover from
// exactly the situation a bad cmdline arg creates. If
// `lockdown=integrity` (or any other arg) makes the regular kernel
// unbootable, applying the same arg to the rescue entry leaves the
// operator with no recovery path. Now the backend enumerates
// kernels via `grubby --info=ALL`, filters out rescue + debug
// kernels by path, and writes only the explicit list.
//
// grubby commits to the active BLS entries immediately, so Refresh()
// is a no-op on this backend.
func (b *BLSBackend) WriteCmdline(args []BootArg) error {
	// Best-effort pre-apply snapshot for rollback — non-fatal if it
	// fails (write proceeds regardless).
	_ = b.writeBLSSnapshot()

	out, err := b.FS.RunCapture("grubby", "--info=ALL")
	if err != nil {
		return fmt.Errorf("grubby --info=ALL: %v: %s", err, strings.TrimSpace(out))
	}
	entries := nonRecoveryKernelEntries(parseGrubbyAll(out))
	targets := kernelPaths(entries)
	if len(targets) == 0 {
		// No targetable kernels. Could be a fresh chroot install
		// before the first kernel package landed; skip gracefully
		// rather than confuse grubby with `--update-kernel=`.
		return nil
	}

	addArgs := make([]string, 0, len(args))
	for _, a := range args {
		addArgs = append(addArgs, a.String())
	}
	cmd := []string{
		"--update-kernel=" + strings.Join(targets, ","),
		"--remove-args=" + strings.Join(ManagedBootArgKeys, " "),
	}
	if len(addArgs) > 0 {
		cmd = append(cmd, "--args="+strings.Join(addArgs, " "))
	}
	if out, err := b.FS.RunCapture("grubby", cmd...); err != nil {
		return fmt.Errorf("grubby update-kernel: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// nonRecoveryKernelEntries returns the BLS entries kernsec should read/write
// — every entry whose kernel image path contains neither a `rescue` nor
// `debug` token. Recovery / debug kernels are intentionally excluded so a
// bad managed arg can't brick the rescue path.
//
// Keeping the full blsKernelEntry records lets NextBootCmdline compare the
// same target set that WriteCmdline and rollbackBLS update, while still
// preserving Args for managed-argument divergence checks.
func nonRecoveryKernelEntries(entries []blsKernelEntry) []blsKernelEntry {
	var out []blsKernelEntry
	for _, e := range entries {
		if e.Kernel == "" {
			continue
		}
		if isRecoveryKernel(e.Kernel) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// kernelPaths projects BLS entries to their kernel image paths for grubby
// --update-kernel=<path>[,<path>...] calls.
func kernelPaths(entries []blsKernelEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Kernel)
	}
	return out
}

// nonRecoveryKernels returns the kernel paths kernsec should write.
func nonRecoveryKernels(entries []blsKernelEntry) []string {
	return kernelPaths(nonRecoveryKernelEntries(entries))
}

// isRecoveryKernel reports whether the given kernel image path looks
// like a rescue-or-debug entry that kernsec should leave alone.
//
// Token-based to avoid false positives on legitimate kernel names
// that contain the substring (e.g. `vmlinuz-debugmode-stripped`):
// the basename is split on `/_+-.` separators and a recovery hit
// requires an EXACT token match against `rescue` or `debug` (case-
// insensitive). This handles every separator convention vendors
// use: `-rescue-`, `+debug`, `_debug_`, `.debug`.
func isRecoveryKernel(path string) bool {
	lower := strings.ToLower(path)
	for _, token := range strings.FieldsFunc(lower, isKernelPathSep) {
		if token == "rescue" || token == "debug" {
			return true
		}
	}
	return false
}

func isKernelPathSep(r rune) bool {
	switch r {
	case '/', '-', '_', '+', '.':
		return true
	}
	return false
}

// Refresh is a no-op on BLS — grubby already committed.
func (b *BLSBackend) Refresh() error {
	return nil
}
