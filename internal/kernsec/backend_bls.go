package kernsec

import (
	"fmt"
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
// All installed kernel entries should agree, since `WriteCmdline` runs
// `grubby --update-kernel=ALL`. If any entry diverges, the args from
// the first entry are returned together with a non-nil error naming
// the divergent kernels — `computeDrift` treats any non-nil error as
// "refuse to apply, surface to operator," which is exactly the right
// behaviour: a manually-edited / package-update-stale kernel entry
// must be flagged before the next reboot lands on it.
//
// Empty grubby output (no kernels) → ("", nil), matching the previous
// DEFAULT-only behaviour.
func (b *BLSBackend) NextBootCmdline() (string, error) {
	out, err := b.FS.RunCapture("grubby", "--info=ALL")
	if err != nil {
		return "", err
	}
	entries := parseGrubbyAll(out)
	if len(entries) == 0 {
		return "", nil
	}
	first := entries[0].Args
	var diverged []string
	for _, e := range entries[1:] {
		if !sameTokens(ParseCmdline(e.Args), ParseCmdline(first)) {
			diverged = append(diverged, e.Kernel)
		}
	}
	if len(diverged) > 0 {
		return first, fmt.Errorf(
			"BLS kernel entries diverge from %s — stale args on: %s",
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

// WriteCmdline runs a single `grubby --update-kernel=ALL` invocation
// that combines `--remove-args` (stripping every managed-keys token)
// with `--args=` (the desired set). grubby applies removes before adds
// within a single call, closing the window where every kernel sat
// stripped of managed args between the previous two-call sequence.
//
// grubby commits to the active BLS entries immediately, so Refresh()
// is a no-op on this backend.
func (b *BLSBackend) WriteCmdline(args []BootArg) error {
	addArgs := make([]string, 0, len(args))
	for _, a := range args {
		addArgs = append(addArgs, a.String())
	}
	cmd := []string{
		"--update-kernel=ALL",
		"--remove-args=" + strings.Join(ManagedBootArgKeys, " "),
	}
	if len(addArgs) > 0 {
		cmd = append(cmd, "--args="+strings.Join(addArgs, " "))
	}
	if out, err := b.FS.RunCapture("grubby", cmd...); err != nil {
		return fmt.Errorf("grubby update-kernel=ALL: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Refresh is a no-op on BLS — grubby already committed.
func (b *BLSBackend) Refresh() error {
	return nil
}
