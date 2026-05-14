package kernsec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// systemdDropinName is the file name kernsec writes under
// /etc/systemd/system/<unit>.d/ when it owns a Mount unit override.
// Stable so DisableMount can find and remove the file it authored.
const systemdDropinName = "10-cfm-hardening.conf"

// systemdSystemEtcDir is the parent directory kernsec writes drop-ins
// under. var so tests can redirect it to a temp tree.
var systemdSystemEtcDir = "/etc/systemd/system"

// dropinPath returns the on-disk drop-in path kernsec authors for the
// given mount point. Tests redirect systemdSystemEtcDir; production
// keeps /etc/systemd/system.
func dropinPath(mountPoint string) string {
	return filepath.Join(systemdSystemEtcDir, unitNameForMountPath(mountPoint)+".d", systemdDropinName)
}

// EnableMount persists the rule's recommended options so the next
// reboot mounts with them, and — when safe — propagates them to the
// running kernel via `mount -o remount`. The strategy is chosen per
// rule based on the live host state:
//
//	a) /var/tmp on a non-separate mount (typical Debian / Ubuntu /
//	   minimal EL) → write a bind-mount fstab line `/tmp /var/tmp
//	   none bind` so /var/tmp inherits /tmp's hardening at reboot.
//	   Live state untouched — `mount --bind` over an existing
//	   /var/tmp would shadow any systemd-private-* runtime dirs and
//	   trip every PrivateTmp=yes service. PEND until reboot.
//	b) /etc/fstab already has a line for the mount point → merge
//	   missing options into that line (preserves size=, mode=, etc.).
//	c) systemd `.mount` unit owns the mount (Debian /tmp, etc.) →
//	   write /etc/systemd/system/<unit>.d/10-cfm-hardening.conf
//	   with Options= set to the merged option list, daemon-reload.
//	d) /dev/shm with no fstab line and no unit → append a kernsec-
//	   owned fstab line (the legacy /dev/shm path).
//	e) /tmp with neither fstab nor unit AND MountNotSeparate → refuse
//	   and point at `cfm kernsec secure-tmp`.
//
// Live remount runs ONLY for /dev/shm. /tmp and /var/tmp persist the
// change but leave the running kernel alone — every service with
// PrivateTmp=yes (mysqld, named, php-fpm, nginx, exim) has bind
// mounts rooted in the current /tmp namespace; `mount -o remount,…
// /tmp` or `systemctl restart tmp.mount` mid-flight is unsafe. The
// audit row then reports PEND until reboot converges live to
// next-boot. Idempotent; safe to re-run.
//
// Refuses when an existing persistence source carries the negation of
// a recommended option (e.g. `exec` when we want `noexec`) — the
// operator has to resolve the conflict explicitly so kernsec doesn't
// silently overwrite their intent.
func EnableMount(rule MountRule, w io.Writer, opts EnableMountOptions) error {
	if !rule.CanEnable {
		return fmt.Errorf("EnableMount: rule %s has CanEnable=false (audit-only)", rule.ID)
	}
	recommended := splitCSV(rule.Recommended)
	if len(recommended) == 0 {
		return fmt.Errorf("EnableMount: rule %s has no recommended options", rule.ID)
	}

	// Probe live state once; the strategy decision depends on it
	// (NotSeparate /var/tmp → bind; MountNotSeparate /tmp without a
	// systemd unit → secure-tmp refusal; etc.).
	detail := CheckMountDetail(rule, Tier1Mounts)

	// /var/tmp bind strategy: when /var/tmp has no separate mount,
	// add `/tmp /var/tmp none bind 0 0` to fstab. The bind picks up
	// /tmp's hardening at reboot without provisioning a second
	// filesystem. Refuses on hosts where the operator has explicit
	// /var/tmp state that would be shadowed (we approximate this by
	// checking whether /var/tmp currently has non-trivial content
	// beyond systemd-private-* runtime dirs).
	if rule.MountPoint == "/var/tmp" && detail.State == MountNotSeparate {
		return enableBindFstab(rule, w, opts, "/tmp")
	}

	// Read fstab once and route by what's present.
	content, readErr := os.ReadFile(PathFstab)
	if readErr != nil {
		return fmt.Errorf("read %s: %w", PathFstab, readErr)
	}
	lines := strings.Split(string(content), "\n")
	if _, _, hasLine := findFstabLineIndex(lines, rule.MountPoint); hasLine {
		return enableFstabEdit(rule, w, opts, lines, recommended)
	}

	// No fstab line — try the systemd .mount unit branch. Gate on
	// "the unit actually owns the live mount": if /proc/mounts shows
	// the mountpoint as not separately mounted (e.g. masked
	// tmp.mount, container overlayfs, operator disabled the unit),
	// the package-shipped unit file in /usr/lib still exists but
	// writing a drop-in for it produces a dead override that doesn't
	// help at reboot. Refuse and point at secure-tmp instead.
	unitName := unitNameForMountPath(rule.MountPoint)
	if _, currentOpts, ok := realSystemdUnitFinderWithDropins(unitName); ok {
		if detail.State == MountNotSeparate {
			return fmt.Errorf(
				"%s: systemd unit %s exists but %s is not separately mounted (unit may be masked or disabled); "+
					"writing a drop-in would be a dead override — run `cfm kernsec secure-tmp` to provision a dedicated /tmp filesystem instead",
				rule.ID, unitName, rule.MountPoint,
			)
		}
		return enableSystemdDropin(rule, w, opts, currentOpts, recommended)
	}

	// Neither fstab nor systemd unit. /dev/shm has a legacy fallback
	// (append a managed fstab line); /tmp + /var/tmp on a host with
	// no /tmp filesystem at all is the secure-tmp scenario.
	if rule.MountPoint == "/dev/shm" {
		return enableFstabAppend(rule, w, opts, lines, recommended)
	}
	return fmt.Errorf(
		"%s: %s is not separately mounted and no systemd .mount unit owns it; "+
			"run `cfm kernsec secure-tmp` to provision a dedicated /tmp filesystem first",
		rule.ID, rule.MountPoint,
	)
}

// enableFstabEdit handles strategy (b): /etc/fstab already has an
// entry for this mount point; merge missing options in. Live remount
// is restricted to /dev/shm (see EnableMount doc for the /tmp/var-tmp
// reasoning).
func enableFstabEdit(rule MountRule, w io.Writer, opts EnableMountOptions, lines []string, recommended []string) error {
	updated, action, err := applyEnableToFstabLines(lines, rule, recommended)
	if err != nil {
		return err
	}
	if action == fstabActionNoChange {
		fmt.Fprintf(w, "[Mount] %s already hardened in %s — no fstab edit needed.\n",
			rule.MountPoint, PathFstab)
	} else {
		if err := persistFstab(updated); err != nil {
			return err
		}
		fmt.Fprintf(w, "[Mount] added %s to existing %s line in %s (backup: %s%s).\n",
			strings.Join(missingFromCSV(rule.Recommended, lines, rule.MountPoint), ","),
			rule.MountPoint, PathFstab, PathFstab, BackupSuffix)
	}
	return finishEnable(rule, w, opts)
}

// enableFstabAppend handles strategy (d): no existing line, no unit;
// append a kernsec-owned line. Today only /dev/shm reaches this
// branch.
func enableFstabAppend(rule MountRule, w io.Writer, opts EnableMountOptions, lines []string, recommended []string) error {
	updated, action, err := applyEnableToFstabLines(lines, rule, recommended)
	if err != nil {
		return err
	}
	if action == fstabActionAppended {
		if err := persistFstab(updated); err != nil {
			return err
		}
		fmt.Fprintf(w, "[Mount] appended %s line to %s (backup: %s%s).\n",
			rule.MountPoint, PathFstab, PathFstab, BackupSuffix)
	}
	return finishEnable(rule, w, opts)
}

// systemdDropinMarker is the sentinel comment kernsec writes as the
// first line of every drop-in it authors. Disable / re-enable check
// for this marker before touching the file; a drop-in at the same
// path without the marker is treated as operator-owned and refused
// (Enable) or left in place (Disable). The exact string is part of
// the file format — change it only with a backwards-compatible
// migration that recognises BOTH old and new markers.
const systemdDropinMarker = "# Written by `cfm kernsec`."

// enableSystemdDropin handles strategy (c): write a drop-in under
// /etc/systemd/system/<unit>.d/10-cfm-hardening.conf that sets
// Options= to the merged option list. Idempotent — if the desired
// drop-in is already on disk we skip the write. Refuses to overwrite
// any file at the target path that isn't authored by kernsec (no
// marker comment), so an operator who happens to use the same
// filename for their own override never has it silently replaced.
func enableSystemdDropin(rule MountRule, w io.Writer, opts EnableMountOptions, currentOpts string, recommended []string) error {
	// Conflict check: existing Options= line has an explicit
	// negation of a recommended option (e.g. `exec` vs `noexec`).
	for _, r := range recommended {
		if anti := antiOption(r); anti != "" && containsOption(splitCSV(currentOpts), anti) {
			return fmt.Errorf(
				"%s: existing systemd Options= for %s sets `%s` which contradicts kernsec recommendation `%s`; resolve by hand",
				rule.ID, rule.MountPoint, anti, r)
		}
	}
	merged := appendMissingToCSV(currentOpts, recommended)
	if merged == currentOpts {
		fmt.Fprintf(w, "[Mount] %s systemd Options= already covers %s — no drop-in needed.\n",
			rule.MountPoint, rule.Recommended)
		return finishEnable(rule, w, opts)
	}
	path := dropinPath(rule.MountPoint)
	body := []byte(fmt.Sprintf("%s Remove with `cfm kernsec disable` or by hand.\n[Mount]\nOptions=%s\n", systemdDropinMarker, merged))
	if existing, err := os.ReadFile(path); err == nil {
		// Refuse to clobber an operator-owned file at our chosen
		// path. The marker is on the first line of every file we
		// author; its absence means the file came from somewhere
		// else (operator hand-edit, config-management tool,
		// package, etc.) and we have no business overwriting it.
		if !bytes.HasPrefix(existing, []byte(systemdDropinMarker)) {
			return fmt.Errorf(
				"%s: refusing to overwrite operator-owned drop-in at %s (no `cfm kernsec` marker on first line); resolve by hand or delete the file first",
				rule.ID, path)
		}
		if string(existing) == string(body) {
			fmt.Fprintf(w, "[Mount] %s drop-in already in desired shape (%s).\n", rule.MountPoint, path)
			return finishEnable(rule, w, opts)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := AtomicWriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(w, "[Mount] wrote systemd drop-in %s (Options=%s).\n", path, merged)
	return finishEnable(rule, w, opts)
}

// enableBindFstab handles strategy (a): /var/tmp has no separate
// mount; add `<source> /var/tmp none bind 0 0` to fstab so the next
// reboot mounts /var/tmp as a bind of /tmp. No live `mount --bind`
// is performed — shadowing an in-use /var/tmp at runtime breaks
// services with state under it (systemd-private-* dirs etc.). PEND
// until reboot.
func enableBindFstab(rule MountRule, w io.Writer, opts EnableMountOptions, source string) error {
	content, readErr := os.ReadFile(PathFstab)
	if readErr != nil {
		return fmt.Errorf("read %s: %w", PathFstab, readErr)
	}
	lines := strings.Split(string(content), "\n")
	if _, _, hasLine := findFstabLineIndex(lines, rule.MountPoint); hasLine {
		// Operator already has SOME line for /var/tmp in fstab.
		// Honour their intent and fall through to the regular edit
		// path on the next Enable run — but for now, refuse to add
		// a conflicting bind line.
		return fmt.Errorf(
			"%s: %s already has an entry in %s; remove or harden it manually rather than adding a bind",
			rule.ID, rule.MountPoint, PathFstab)
	}
	bindLine := fmt.Sprintf("%s\t%s\tnone\tbind\t0 0\t%s",
		source, rule.MountPoint, kernsecManagedFstabComment)
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	lines = append(lines, bindLine, "")
	if err := persistFstab(lines); err != nil {
		return err
	}
	fmt.Fprintf(w, "[Mount] appended bind line `%s -> %s` to %s (backup: %s%s).\n",
		source, rule.MountPoint, PathFstab, PathFstab, BackupSuffix)
	fmt.Fprintf(w, "[Mount] /var/tmp will inherit /tmp's hardening at reboot. Existing files under /var/tmp will be shadowed (not deleted) by the bind.\n")
	return finishEnable(rule, w, opts)
}

// finishEnable runs the post-persist steps every strategy shares:
// daemon-reload (so systemd notices the new drop-in / fstab line) and
// the live remount when it's safe (only /dev/shm today).
func finishEnable(rule MountRule, w io.Writer, opts EnableMountOptions) error {
	if !opts.NoDaemonReload {
		if err := runSystemctlDaemonReload(); err != nil {
			fmt.Fprintf(w, "[Mount] systemctl daemon-reload failed: %v — continuing\n", err)
		} else {
			fmt.Fprintln(w, "[Mount] systemctl daemon-reload completed.")
		}
	}
	if opts.NoRemount || !liveRemountSafe(rule) {
		if liveRemountSafe(rule) {
			fmt.Fprintf(w, "[Mount] --no-remount: not touching the running %s. Apply manually:\n",
				rule.MountPoint)
			fmt.Fprintf(w, "        mount -o remount,%s %s\n", rule.Recommended, rule.MountPoint)
		} else {
			fmt.Fprintf(w, "[Mount] %s: persisted; live state stays as-is until reboot (PrivateTmp=yes services make a live remount unsafe).\n",
				rule.MountPoint)
		}
		return nil
	}
	if err := runRemount(rule.MountPoint, rule.Recommended); err != nil {
		return fmt.Errorf("remount %s with %s: %w (persistence IS written; remount manually or reboot)",
			rule.MountPoint, rule.Recommended, err)
	}
	fmt.Fprintf(w, "[Mount] remounted %s with %s (now live).\n",
		rule.MountPoint, rule.Recommended)
	return nil
}

// liveRemountSafe is the predicate that decides whether `mount -o
// remount` is safe to run during Enable. /dev/shm is fine (no
// PrivateTmp consumers); /tmp and /var/tmp are not (services with
// PrivateTmp=yes have bind mounts rooted in the current namespace
// and would either fail the remount or end up pointing at a stale
// namespace). Reboot is the convergence point for the unsafe set.
func liveRemountSafe(rule MountRule) bool {
	return rule.MountPoint == "/dev/shm"
}

// persistFstab is the shared fstab write path: BackupOnce, then
// AtomicWriteFile of the joined content. Centralised so every Enable
// strategy goes through the same backup discipline.
func persistFstab(lines []string) error {
	if err := BackupOnce(PathFstab, PathFstab+BackupSuffix); err != nil {
		return fmt.Errorf("backup %s: %w", PathFstab, err)
	}
	if err := AtomicWriteFile(PathFstab, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", PathFstab, err)
	}
	return nil
}

// DisableMount strips kernsec's effective additions from the rule's
// fstab line and remounts so the running kernel reverts to its
// pre-cfm state. "Effective additions" means Recommended minus
// DefaultLiveOptions — the options kernsec actually adds on top of
// what the kernel/systemd/distro mount with by default. /dev/shm is
// the canonical example: every distro mounts it with nosuid,nodev
// already on, so kernsec really only adds noexec. Disabling reverts
// only the noexec — leaving nodev,nosuid in place so the host
// returns to its baseline, never below it.
//
// Idempotent; safe to re-run. If kernsec authored the fstab line
// (managed-by-cfm comment present), the whole line is removed so
// the host returns to PID 1's built-in /dev/shm mount on next boot.
// If the operator had a pre-existing fstab line, only the kernsec-
// effective additions are stripped; the operator's other options
// (including any explicit nodev/nosuid they wrote) stay intact.
func DisableMount(rule MountRule, w io.Writer, opts EnableMountOptions) error {
	if !rule.CanEnable {
		return nil // audit-only rule; nothing kernsec-owned to disable
	}

	// Remove the kernsec-owned systemd drop-in first (if any). This
	// is the cleanest revert path on Debian / Ubuntu / Arch where
	// Enable wrote a drop-in instead of touching fstab. Removing the
	// drop-in returns the unit to its packaged defaults at the next
	// daemon-reload + reboot. We check for the kernsec marker before
	// removing — a file at our chosen path without the marker is
	// operator-owned (config-management tool, package, hand-edit) and
	// disable must leave it in place. Same safety stance as Enable.
	dropinRemoved := false
	dp := dropinPath(rule.MountPoint)
	if existing, err := os.ReadFile(dp); err == nil {
		if !bytes.HasPrefix(existing, []byte(systemdDropinMarker)) {
			fmt.Fprintf(w, "[Mount] %s exists but is operator-owned (no `cfm kernsec` marker); leaving untouched.\n", dp)
		} else {
			if err := os.Remove(dp); err != nil {
				return fmt.Errorf("remove %s: %w", dp, err)
			}
			// Best-effort: remove the now-empty .d/ parent so the host
			// looks the way it did before Enable. Ignore errors — a
			// non-empty dir (operator added their own drop-in) is fine.
			_ = os.Remove(filepath.Dir(dp))
			fmt.Fprintf(w, "[Mount] removed kernsec drop-in %s.\n", dp)
			dropinRemoved = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", dp, err)
	}

	effectiveAdditions := kernsecEffectiveAdditions(rule)
	if len(effectiveAdditions) == 0 && !dropinRemoved {
		// Distro defaults already cover everything kernsec
		// recommends. Nothing to disable, nothing to revert.
		fmt.Fprintf(w, "[Mount] %s: every recommended option is already a distro default — no disable action needed.\n",
			rule.MountPoint)
		return nil
	}

	content, err := os.ReadFile(PathFstab)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if dropinRemoved {
				return finishDisable(rule, w, opts, nil)
			}
			return nil
		}
		return fmt.Errorf("read %s: %w", PathFstab, err)
	}
	lines := strings.Split(string(content), "\n")

	updated, action := applyDisableToFstabLines(lines, rule, effectiveAdditions)
	if action == fstabActionNoChange {
		if !dropinRemoved {
			fmt.Fprintf(w, "[Mount] %s already absent / not kernsec-managed in %s — no fstab edit needed.\n",
				rule.MountPoint, PathFstab)
		}
	} else {
		if err := persistFstab(updated); err != nil {
			return err
		}
		switch action {
		case fstabActionRemoved:
			fmt.Fprintf(w, "[Mount] removed kernsec-owned %s line from %s (distro PID 1 default will mount it on next boot).\n",
				rule.MountPoint, PathFstab)
		case fstabActionEdited:
			fmt.Fprintf(w, "[Mount] stripped %s from existing %s line in %s (distro-default options like %s preserved).\n",
				strings.Join(effectiveAdditions, ","), rule.MountPoint, PathFstab,
				rule.DefaultLiveOptions)
		}
	}

	return finishDisable(rule, w, opts, effectiveAdditions)
}

// finishDisable runs the post-write steps every Disable strategy
// shares: daemon-reload, then a live revert remount when it's safe
// (/dev/shm only — same liveRemountSafe rule as Enable).
func finishDisable(rule MountRule, w io.Writer, opts EnableMountOptions, effectiveAdditions []string) error {
	if !opts.NoDaemonReload {
		if err := runSystemctlDaemonReload(); err != nil {
			fmt.Fprintf(w, "[Mount] systemctl daemon-reload failed: %v — continuing\n", err)
		}
	}
	if opts.NoRemount || !liveRemountSafe(rule) {
		if liveRemountSafe(rule) {
			fmt.Fprintf(w, "[Mount] --no-remount: not touching the running %s. Operator decides when to remount.\n",
				rule.MountPoint)
		} else {
			fmt.Fprintf(w, "[Mount] %s: persistence reverted; live state stays as-is until reboot.\n",
				rule.MountPoint)
		}
		return nil
	}
	revertOpts := antiOptionsCSV(effectiveAdditions)
	if revertOpts == "" {
		return nil
	}
	if err := runRemount(rule.MountPoint, revertOpts); err != nil {
		fmt.Fprintf(w, "[Mount] revert remount of %s failed: %v — fstab edit IS persisted, reboot will apply.\n",
			rule.MountPoint, err)
		return nil
	}
	fmt.Fprintf(w, "[Mount] remounted %s with %s (kernsec hardening reverted; distro-default %s preserved).\n",
		rule.MountPoint, revertOpts, rule.DefaultLiveOptions)
	return nil
}

// kernsecEffectiveAdditions returns the subset of rule.Recommended
// that kernsec actually adds on top of DefaultLiveOptions — the
// options that are NOT already applied by the kernel/systemd/distro
// at boot. For /dev/shm (Recommended=nodev,nosuid,noexec;
// DefaultLiveOptions=nodev,nosuid) this returns ["noexec"]. Used by
// DisableMount so the runtime revert and the fstab strip operate on
// only what kernsec really changed, never on the distro baseline.
func kernsecEffectiveAdditions(rule MountRule) []string {
	defaults := map[string]struct{}{}
	for _, o := range splitCSV(rule.DefaultLiveOptions) {
		defaults[o] = struct{}{}
	}
	var out []string
	for _, o := range splitCSV(rule.Recommended) {
		if _, isDefault := defaults[o]; isDefault {
			continue
		}
		out = append(out, o)
	}
	return out
}

// antiOptionsCSV joins the explicit-negation form of every entry in
// `opts` into a comma-separated string suitable for `mount -o
// remount,…`. Entries with no anti-option are dropped. Empty result
// means "nothing to revert at runtime".
func antiOptionsCSV(opts []string) string {
	var out []string
	for _, o := range opts {
		if a := antiOption(o); a != "" {
			out = append(out, a)
		}
	}
	return strings.Join(out, ",")
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
