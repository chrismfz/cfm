package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// PathFstab is the system mount table. var (not const) so tests can
// redirect it to a temp file.
var PathFstab = "/etc/fstab"

// kernsecManagedFstabComment is appended (with a leading tab) to any
// fstab line kernsec creates from scratch. Existing operator-owned
// lines are NOT re-annotated — the comment only marks lines we
// actually added so the operator can grep for them later.
const kernsecManagedFstabComment = "# managed by cfm kernsec — see `cfm kernsec status` / `cfm kernsec disable`"

// EnableMountOptions tunes EnableMount behaviour. NoRemount keeps the
// fstab edit but skips the live `mount -o remount` so the operator
// applies it manually on their own schedule. NoDaemonReload is the
// same idea for `systemctl daemon-reload`. Both default false — the
// happy path edits fstab AND propagates to the running kernel.
type EnableMountOptions struct {
	NoRemount      bool
	NoDaemonReload bool
}

// EnableMount adds the rule's recommended options to /etc/fstab and
// remounts the mount point so the running kernel picks them up. Safe
// to re-run; idempotent when the line is already in the desired
// shape. Refuses if the existing fstab line contains an option that
// directly contradicts the recommendation (e.g. `exec` when we want
// `noexec`) — the operator has to resolve the conflict explicitly so
// kernsec doesn't silently overwrite their intent.
//
// Returns nil on success (including when the line was already
// correct and no edit was needed); a non-nil error means the
// /etc/fstab edit, the daemon-reload, or the remount failed.
//
// Only runs when rule.CanEnable is true. The current Tier1Mounts set
// has CanEnable=true only on /dev/shm; /tmp and /var/tmp deliberately
// stay tip-only.
func EnableMount(rule MountRule, w io.Writer, opts EnableMountOptions) error {
	if !rule.CanEnable {
		return fmt.Errorf("EnableMount: rule %s has CanEnable=false (audit-only)", rule.ID)
	}
	recommended := splitCSV(rule.Recommended)
	if len(recommended) == 0 {
		return fmt.Errorf("EnableMount: rule %s has no recommended options", rule.ID)
	}

	content, readErr := os.ReadFile(PathFstab)
	if readErr != nil {
		return fmt.Errorf("read %s: %w", PathFstab, readErr)
	}
	lines := strings.Split(string(content), "\n")

	updated, action, err := applyEnableToFstabLines(lines, rule, recommended)
	if err != nil {
		return err
	}

	if action == fstabActionNoChange {
		fmt.Fprintf(w, "[Mount] %s already hardened in %s — no fstab edit needed.\n",
			rule.MountPoint, PathFstab)
	} else {
		if err := BackupOnce(PathFstab, PathFstab+BackupSuffix); err != nil {
			return fmt.Errorf("backup %s: %w", PathFstab, err)
		}
		newContent := strings.Join(updated, "\n")
		if err := AtomicWriteFile(PathFstab, []byte(newContent), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", PathFstab, err)
		}
		switch action {
		case fstabActionAppended:
			fmt.Fprintf(w, "[Mount] appended /dev/shm line to %s (backup: %s%s).\n",
				PathFstab, PathFstab, BackupSuffix)
		case fstabActionEdited:
			fmt.Fprintf(w, "[Mount] added %s to existing %s line in %s (backup: %s%s).\n",
				strings.Join(missingFromCSV(rule.Recommended, lines, rule.MountPoint), ","),
				rule.MountPoint, PathFstab, PathFstab, BackupSuffix)
		}
	}

	if !opts.NoDaemonReload {
		if err := runSystemctlDaemonReload(); err != nil {
			fmt.Fprintf(w, "[Mount] systemctl daemon-reload failed: %v — continuing\n", err)
		} else {
			fmt.Fprintln(w, "[Mount] systemctl daemon-reload completed.")
		}
	}
	if opts.NoRemount {
		fmt.Fprintf(w, "[Mount] --no-remount: not touching the running %s. Apply manually:\n",
			rule.MountPoint)
		fmt.Fprintf(w, "        mount -o remount,%s %s\n", rule.Recommended, rule.MountPoint)
		return nil
	}

	if err := runRemount(rule.MountPoint, rule.Recommended); err != nil {
		return fmt.Errorf("remount %s with %s: %w (fstab edit IS persisted; remount manually or reboot)",
			rule.MountPoint, rule.Recommended, err)
	}
	fmt.Fprintf(w, "[Mount] remounted %s with %s (now live).\n",
		rule.MountPoint, rule.Recommended)
	return nil
}

// DisableMount strips kernsec's managed options from the rule's
// fstab line and remounts so the running kernel reverts. Idempotent;
// safe to re-run on an already-disabled mount. The fstab line itself
// is preserved if the operator had non-kernsec options on it (e.g.
// `size=`, `mode=`); only kernsec's managed options are removed. If
// kernsec is the sole owner of the line (we appended it ourselves
// and the operator never edited it), the line is removed entirely.
func DisableMount(rule MountRule, w io.Writer, opts EnableMountOptions) error {
	if !rule.CanEnable {
		return nil // audit-only rule; nothing kernsec-owned to disable
	}
	managed := splitCSV(rule.Recommended)

	content, err := os.ReadFile(PathFstab)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", PathFstab, err)
	}
	lines := strings.Split(string(content), "\n")

	updated, action := applyDisableToFstabLines(lines, rule, managed)
	if action == fstabActionNoChange {
		fmt.Fprintf(w, "[Mount] %s already absent / not kernsec-managed in %s — no fstab edit needed.\n",
			rule.MountPoint, PathFstab)
	} else {
		if err := BackupOnce(PathFstab, PathFstab+BackupSuffix); err != nil {
			return fmt.Errorf("backup %s: %w", PathFstab, err)
		}
		if err := AtomicWriteFile(PathFstab, []byte(strings.Join(updated, "\n")), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", PathFstab, err)
		}
		switch action {
		case fstabActionRemoved:
			fmt.Fprintf(w, "[Mount] removed kernsec-owned %s line from %s.\n",
				rule.MountPoint, PathFstab)
		case fstabActionEdited:
			fmt.Fprintf(w, "[Mount] stripped %s from existing %s line in %s.\n",
				rule.Recommended, rule.MountPoint, PathFstab)
		}
	}

	if !opts.NoDaemonReload {
		if err := runSystemctlDaemonReload(); err != nil {
			fmt.Fprintf(w, "[Mount] systemctl daemon-reload failed: %v — continuing\n", err)
		}
	}
	if opts.NoRemount {
		fmt.Fprintf(w, "[Mount] --no-remount: not touching the running %s. Operator decides when to remount.\n",
			rule.MountPoint)
		return nil
	}
	// Disable remount: reset to the kernel/systemd defaults. For
	// /dev/shm the systemd PID 1 defaults are nosuid,nodev,mode=1777
	// — but `mount -o remount,rw,exec,suid,dev` removes our flags
	// explicitly. This is the operator-observable disable.
	revertOpts := revertOptionsFor(rule.MountPoint, managed)
	if revertOpts != "" {
		if err := runRemount(rule.MountPoint, revertOpts); err != nil {
			fmt.Fprintf(w, "[Mount] revert remount of %s failed: %v — fstab edit IS persisted, reboot will apply.\n",
				rule.MountPoint, err)
		} else {
			fmt.Fprintf(w, "[Mount] remounted %s with %s (kernsec hardening reverted at runtime).\n",
				rule.MountPoint, revertOpts)
		}
	}
	return nil
}

// fstabAction is the outcome of applying enable/disable to the
// in-memory fstab line list. Used to drive the operator-facing log
// line so they know whether a backup was taken, a line was created,
// edited, removed, or nothing happened.
type fstabAction int

const (
	fstabActionNoChange fstabAction = iota
	fstabActionAppended
	fstabActionEdited
	fstabActionRemoved
)

// applyEnableToFstabLines is the pure-Go core of EnableMount: takes
// the existing fstab lines + rule + recommended options, returns the
// updated lines and what kind of change was applied. Refuses (via
// non-nil error) when an existing fstab line carries the negation of
// a recommended option (e.g. `exec` when we want `noexec`).
func applyEnableToFstabLines(lines []string, rule MountRule, recommended []string) ([]string, fstabAction, error) {
	idx, parsed, ok := findFstabLineIndex(lines, rule.MountPoint)
	if !ok {
		// No existing line — append a tmpfs entry with the
		// recommendation. /dev/shm specifically gets the kernel
		// default mode (1777) preserved so we don't change perms.
		line := defaultFstabLineFor(rule)
		// Strip a trailing blank line if present so our append
		// doesn't widen the gap; reattach a trailing newline.
		appended := lines
		if n := len(appended); n > 0 && appended[n-1] == "" {
			appended = appended[:n-1]
		}
		appended = append(appended, line, "")
		return appended, fstabActionAppended, nil
	}

	existing := splitCSV(parsed.Options)
	// Conflict check: operator explicitly wanted the opposite of
	// what we recommend (e.g. `exec`, `suid`, `dev`).
	for _, r := range recommended {
		anti := antiOption(r)
		if anti == "" {
			continue
		}
		if containsOption(existing, anti) {
			return nil, fstabActionNoChange, fmt.Errorf(
				"%s: existing /etc/fstab line for %s sets `%s` which contradicts kernsec recommendation `%s`; resolve by hand",
				rule.ID, rule.MountPoint, anti, r)
		}
	}

	merged := appendMissingToCSV(parsed.Options, recommended)
	if merged == parsed.Options {
		return lines, fstabActionNoChange, nil
	}
	lines[idx] = replaceOptionsColumn(lines[idx], parsed.Options, merged)
	return lines, fstabActionEdited, nil
}

// applyDisableToFstabLines is the disable counterpart of
// applyEnableToFstabLines. Strips the managed options from the
// /etc/fstab line for `rule.MountPoint`. If kernsec is the sole
// owner of the line (we appended it and the kernsec-managed marker
// comment is still present), the entire line is removed.
func applyDisableToFstabLines(lines []string, rule MountRule, managed []string) ([]string, fstabAction) {
	idx, parsed, ok := findFstabLineIndex(lines, rule.MountPoint)
	if !ok {
		return lines, fstabActionNoChange
	}

	// Kernsec-owned line: we appended it (marked by our managed
	// comment). Remove the whole line so disable returns the host
	// to its pre-cfm state.
	if strings.Contains(lines[idx], kernsecManagedFstabComment) {
		out := append([]string{}, lines[:idx]...)
		out = append(out, lines[idx+1:]...)
		return out, fstabActionRemoved
	}

	existing := splitCSV(parsed.Options)
	var kept []string
	changed := false
	for _, o := range existing {
		if containsOption(managed, o) {
			changed = true
			continue
		}
		kept = append(kept, o)
	}
	if !changed {
		return lines, fstabActionNoChange
	}
	if len(kept) == 0 {
		kept = []string{"defaults"}
	}
	newOpts := strings.Join(kept, ",")
	lines[idx] = replaceOptionsColumn(lines[idx], parsed.Options, newOpts)
	return lines, fstabActionEdited
}

// findFstabLineIndex returns the (lines-array index, parsed
// fstabLine, ok) for the first uncommented fstab line whose
// mount-point column matches `mountPoint`. Comment lines are
// skipped (operator may have a commented-out template line).
func findFstabLineIndex(lines []string, mountPoint string) (int, fstabLine, bool) {
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		if fields[1] != mountPoint {
			continue
		}
		return i, fstabLine{
			LineNumber: i + 1,
			Raw:        raw,
			Source:     fields[0],
			MountPoint: fields[1],
			FSType:     fields[2],
			Options:    fields[3],
		}, true
	}
	return -1, fstabLine{}, false
}

// defaultFstabLineFor returns the fstab line text kernsec writes
// when no existing entry exists for the mount point. Marked with
// kernsecManagedFstabComment so disable can later identify
// kernsec-owned lines and remove them entirely.
func defaultFstabLineFor(rule MountRule) string {
	opts := rule.Recommended
	switch rule.MountPoint {
	case "/dev/shm":
		// Preserve the kernel/systemd default mode (1777) so we
		// don't tighten perms by accident — the existing /dev/shm
		// is world-rwx with sticky bit.
		opts = "defaults," + opts + ",mode=1777"
		return fmt.Sprintf("tmpfs\t/dev/shm\ttmpfs\t%s\t0 0\t%s",
			opts, kernsecManagedFstabComment)
	}
	// Other mount points use a generic skeleton; today this branch
	// is unreachable because only /dev/shm has CanEnable=true.
	return fmt.Sprintf("tmpfs\t%s\ttmpfs\tdefaults,%s\t0 0\t%s",
		rule.MountPoint, opts, kernsecManagedFstabComment)
}

// replaceOptionsColumn returns `line` with its options column (the
// fourth whitespace-separated field) swapped from `oldOpts` to
// `newOpts`. Preserves the original whitespace, the operator's
// column alignment, and any trailing comment.
func replaceOptionsColumn(line, oldOpts, newOpts string) string {
	idx := strings.Index(line, oldOpts)
	if idx < 0 {
		return line
	}
	return line[:idx] + newOpts + line[idx+len(oldOpts):]
}

// missingFromCSV returns the recommended options that were missing
// from the /etc/fstab line BEFORE this enable run. Used only for the
// operator-facing log line; the actual diff is computed inside
// applyEnableToFstabLines.
func missingFromCSV(recommended string, originalLines []string, mountPoint string) []string {
	_, parsed, ok := findFstabLineIndex(originalLines, mountPoint)
	if !ok {
		return splitCSV(recommended)
	}
	_, missing := splitMountOptions(parsed.Options, recommended)
	return missing
}

// antiOption returns the option that explicitly negates `opt`, or
// "" if there's no negation form. Used for conflict detection: if
// the operator wrote `exec` we will not silently overwrite that
// when applying `noexec`.
func antiOption(opt string) string {
	switch opt {
	case "noexec":
		return "exec"
	case "nosuid":
		return "suid"
	case "nodev":
		return "dev"
	}
	return ""
}

// revertOptionsFor returns the explicit-negation form of every
// managed option, joined for `mount -o remount,…`. Used by
// DisableMount to clear kernsec's flags from the running kernel.
// Empty string if there's nothing to revert.
func revertOptionsFor(mountPoint string, managed []string) string {
	var rev []string
	for _, o := range managed {
		if a := antiOption(o); a != "" {
			rev = append(rev, a)
		}
	}
	return strings.Join(rev, ",")
}

// containsOption returns true if `opt` is in `set`.
func containsOption(set []string, opt string) bool {
	for _, s := range set {
		if s == opt {
			return true
		}
	}
	return false
}

// runSystemctlDaemonReload triggers `systemctl daemon-reload` so
// systemd regenerates the mount unit from the updated fstab. var
// so tests can substitute a no-op stub.
var runSystemctlDaemonReload = func() error {
	cmd := exec.Command("systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runRemount runs `mount -o remount,<opts> <mountPoint>` so the
// running kernel picks up the new mount options. var so tests can
// substitute a deterministic stub.
var runRemount = func(mountPoint, opts string) error {
	cmd := exec.Command("mount", "-o", "remount,"+opts, mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
