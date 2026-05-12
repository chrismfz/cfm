package kernsec

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MountTip is a structured, scenario-aware remediation guide for one
// mount audit row. The tip is text intended for an operator to read
// and copy-paste from `cfm kernsec status`; the TUI Detail panel
// shows a one-line summary plus a pointer to the full guide.
//
// kernsec NEVER mutates fstab or .mount units; the tip is advice
// only. It exists because the right remediation depends on five
// things that vary per host (live mount opts, fstab line presence,
// systemd .mount unit presence, whether the path is a symlink/bind,
// whether the path is even a separate mount), and asking every
// operator to puzzle through that themselves is the noise the audit
// section was already producing.
type MountTip struct {
	// Headline is a one-line summary of the tip — e.g.
	// "edit existing fstab line" or "create a separate /tmp".
	// Suitable for the TUI Detail one-liner.
	Headline string
	// Body is the full text guide, line by line. Lines are pre-
	// formatted with the indent the renderer expects ("  cmd ...").
	Body []string
}

// BuildMountTip composes a remediation tip for one MountRule by
// observing the live filesystem state: /proc/mounts, /etc/fstab,
// /etc/systemd/system/<unit>, and the resolved MountDetail (which
// already classified the path as OK / PARTIAL / MISSING / SYMLINK /
// BIND / NOT-SEPARATE). The tip is empty for MountOK rows — there's
// nothing to advise on a fully-hardened mount.
//
// Production callers pass rule + Tier1Mounts (for the bind-sibling
// pointer) and let BuildMountTip read the filesystem itself. Tests
// drive the same code path via buildMountTip with injected readers.
func BuildMountTip(rule MountRule) MountTip {
	d := CheckMountDetail(rule, Tier1Mounts)
	return buildMountTip(rule, d, realFstabReader, realSystemdUnitFinder)
}

// buildMountTip is the testable inner function. It takes pre-resolved
// MountDetail (so tests don't have to fake /proc/mounts twice) and
// injectable hooks for fstab + systemd unit lookup.
func buildMountTip(
	rule MountRule,
	d MountDetail,
	readFstab func() ([]fstabLine, error),
	findUnit func(unitName string) (path, options string, ok bool),
) MountTip {
	switch d.State {
	case MountOK:
		return MountTip{} // nothing to advise
	case MountSymlink:
		target := d.SymlinkTarget
		if target == "" {
			target = "<resolve failed>"
		}
		return MountTip{
			Headline: fmt.Sprintf("symlink → %s; harden the target row to inherit", target),
			Body: []string{
				fmt.Sprintf("  %s is a symlink to %s. Mount options on a symlink are meaningless;",
					rule.MountPoint, target),
				fmt.Sprintf("  the live options come from whatever filesystem mounts %s.", target),
				"",
				fmt.Sprintf("  Find the %s row in this audit and apply its tip — this row", target),
				"  will then turn green automatically (the symlink follows the target).",
			},
		}
	case MountBindOfAnother:
		primary := d.BindPrimaryPath
		return MountTip{
			Headline: fmt.Sprintf("bind of %s; harden the primary row to inherit", primary),
			Body: []string{
				fmt.Sprintf("  %s is a bind mount sharing source %s with %s.",
					rule.MountPoint, d.Source, primary),
				fmt.Sprintf("  Remounting %s directly is also legal, but the cleanest path is to",
					rule.MountPoint),
				fmt.Sprintf("  fix the %s row — both mount points will pick up the new options.",
					primary),
				"",
				fmt.Sprintf("  If you must remount this side only:"),
				fmt.Sprintf("    mount -o remount,%s %s",
					joinOrAll(d.Missing, rule.Recommended), rule.MountPoint),
			},
		}
	case MountNotSeparate:
		return tipCreateSeparateMount(rule)
	case MountPartialOptions, MountMissingOptions:
		return tipFixExistingMount(rule, d, readFstab, findUnit)
	}
	return MountTip{}
}

// tipFixExistingMount handles PARTIAL / MISSING — the mount exists,
// some (or no) options are present, the operator needs to add the
// missing ones AND make the change survive reboot. We inspect three
// places (fstab, systemd .mount unit, "neither") and emit the
// narrowest tip that matches.
func tipFixExistingMount(
	rule MountRule,
	d MountDetail,
	readFstab func() ([]fstabLine, error),
	findUnit func(unitName string) (path, options string, ok bool),
) MountTip {
	missing := d.Missing
	if len(missing) == 0 {
		// Defensive: PartialOptions implies missing != nil, but a
		// caller-supplied MountDetail might not have populated it.
		// Fall back to the full recommended set.
		missing = strings.Split(rule.Recommended, ",")
	}
	missingCSV := strings.Join(missing, ",")
	remountCmd := fmt.Sprintf("mount -o remount,%s %s", missingCSV, rule.MountPoint)

	fstabLines, _ := readFstab()
	if fl, ok := findFstabEntry(fstabLines, rule.MountPoint); ok {
		body := []string{
			fmt.Sprintf("  Existing fstab line:"),
			fmt.Sprintf("    /etc/fstab:%d  %s", fl.LineNumber, fl.Raw),
			"",
			fmt.Sprintf("  1. Edit /etc/fstab line %d — add %s to the options column.",
				fl.LineNumber, missingCSV),
			"     (Example new options column:",
			fmt.Sprintf("        %s)", appendMissingToCSV(fl.Options, missing)),
			"",
			fmt.Sprintf("  2. Apply at runtime (no reboot needed):"),
			fmt.Sprintf("       %s", remountCmd),
			"",
			fmt.Sprintf("  3. Verify:  findmnt %s", rule.MountPoint),
		}
		return MountTip{
			Headline: "edit existing /etc/fstab line",
			Body:     body,
		}
	}

	unitName := unitNameForMountPath(rule.MountPoint)
	if unitPath, currentOpts, ok := findUnit(unitName); ok {
		// systemd .mount unit owns this mount. Recommend a drop-in
		// override rather than editing the unit in place — survives
		// package updates, easier to roll back.
		dropinDir := filepath.Join("/etc/systemd/system", unitName+".d")
		dropinFile := filepath.Join(dropinDir, "10-cfm-hardening.conf")
		newOpts := appendMissingToCSV(currentOpts, missing)
		body := []string{
			fmt.Sprintf("  Existing systemd unit: %s", unitPath),
			fmt.Sprintf("  Current Options=: %s", currentOpts),
			"",
			fmt.Sprintf("  1. Create a drop-in override (does not edit the unit in place):"),
			fmt.Sprintf("       mkdir -p %s", dropinDir),
			fmt.Sprintf("       cat > %s <<'EOF'", dropinFile),
			fmt.Sprintf("       [Mount]"),
			fmt.Sprintf("       Options=%s", newOpts),
			"       EOF",
			"",
			fmt.Sprintf("  2. Reload + restart the mount unit:"),
			"       systemctl daemon-reload",
			fmt.Sprintf("       systemctl restart %s", unitName),
			"",
			fmt.Sprintf("  3. Verify:  findmnt %s", rule.MountPoint),
		}
		return MountTip{
			Headline: fmt.Sprintf("override systemd %s via drop-in", unitName),
			Body:     body,
		}
	}

	// Neither fstab nor a systemd unit — typical for /dev/shm, which
	// PID 1 mounts itself with built-in defaults. Operator must
	// CREATE persistence; pick fstab as the most portable option.
	body := []string{}
	if rule.MountPoint == "/dev/shm" {
		body = append(body,
			"  /dev/shm is mounted by systemd PID 1 with built-in defaults",
			"  (nosuid,nodev,mode=1777). It has no fstab line or .mount unit yet,",
			"  which is why `grep -R dev-shm /etc` returns nothing on this host.",
			"",
		)
	} else {
		body = append(body,
			fmt.Sprintf("  %s is mounted but has no /etc/fstab line and no", rule.MountPoint),
			"  systemd .mount unit under /etc — the mount is happening from a",
			"  source we can't see (early-boot init, image overlay, etc).",
			"",
		)
	}
	body = append(body,
		"  Persist via /etc/fstab (most portable):",
	)
	body = append(body, fmt.Sprintf("    Append:  %s", recommendedFstabLine(rule)))
	body = append(body,
		"",
		"  Apply at runtime (no reboot):",
		fmt.Sprintf("    %s", remountCmd),
		"",
		fmt.Sprintf("  Verify:  findmnt %s", rule.MountPoint),
	)
	return MountTip{
		Headline: "no fstab line yet — add one to persist",
		Body:     body,
	}
}

// tipCreateSeparateMount handles MountNotSeparate — /tmp or /var/tmp
// is on the root filesystem, so the audit cannot apply mount options
// here without first carving out a dedicated filesystem. We give the
// operator both common patterns (RAM-backed tmpfs, disk-backed loop
// file in the cPanel `securetmp` style) so they can pick the one that
// matches the host's workload + RAM budget.
func tipCreateSeparateMount(rule MountRule) MountTip {
	switch rule.MountPoint {
	case "/tmp":
		return MountTip{
			Headline: "/tmp is on /; create a dedicated mount before hardening",
			Body: []string{
				"  /tmp has no dedicated filesystem — it lives on the root partition.",
				"  Two common patterns to give it its own filesystem (pick one):",
				"",
				"  Option A — RAM-backed tmpfs (fast, no disk I/O, lost on reboot):",
				"    Append to /etc/fstab:",
				"      tmpfs /tmp tmpfs nodev,nosuid,noexec,size=4G,mode=1777 0 0",
				"    Apply now (will move existing /tmp contents to RAM):",
				"      mount /tmp",
				"    Caveats: tmpfs counts against RAM; size= caps it. Increase only",
				"    if you have headroom. Do not use on hosts with tiny RAM.",
				"",
				"  Option B — disk-backed loop file (cPanel `securetmp` style):",
				"    fallocate -l 4G /var/tmpDSK",
				"    mkfs.ext4 -F /var/tmpDSK",
				"    Append to /etc/fstab:",
				"      /var/tmpDSK /tmp ext4 nodev,nosuid,noexec,loop 0 0",
				"    Migrate existing contents first if /tmp isn't empty:",
				"      mkdir /tmp.new && mount /var/tmpDSK /tmp.new",
				"      cp -a /tmp/. /tmp.new/ && umount /tmp.new && rmdir /tmp.new",
				"    Then:",
				"      mount /tmp",
				"",
				"  Verify either way:  findmnt /tmp",
			},
		}
	case "/var/tmp":
		return MountTip{
			Headline: "/var/tmp is on /; bind to /tmp once /tmp is a separate mount",
			Body: []string{
				"  /var/tmp has no dedicated filesystem. The simplest correct fix is",
				"  to make it a bind of /tmp (which must itself be a separate mount),",
				"  so both directories share the same hardening.",
				"",
				"  1. First make /tmp a separate mount — see the /tmp row's tip.",
				"",
				"  2. Then bind /var/tmp to /tmp.  Append to /etc/fstab:",
				"       /tmp /var/tmp none bind 0 0",
				"     Apply:",
				"       mount /var/tmp",
				"",
				"  Alternative: replace /var/tmp with a symlink to /tmp (older",
				"  cPanel pattern). Bind is preferred — preserves the directory",
				"  inode and most package managers expect /var/tmp to be a real path.",
				"",
				"  Verify:  findmnt /var/tmp",
			},
		}
	case "/dev/shm":
		// /dev/shm is always a separate mount on systemd hosts; this
		// branch is unreachable in practice but covered defensively.
		return MountTip{
			Headline: "/dev/shm is not separately mounted (unexpected on systemd)",
			Body: []string{
				"  /dev/shm is normally mounted by systemd PID 1 itself. If it's",
				"  showing as 'not a separate mount' something has gone wrong with",
				"  the early-boot mount-setup sequence — investigate before adding",
				"  fstab lines.",
			},
		}
	}
	return MountTip{}
}

// recommendedFstabLine returns the suggested fstab line for a mount
// the operator is currently missing entirely. tmpfs targets get a
// tmpfs source; everything else gets a placeholder the operator must
// edit to point at the right device.
func recommendedFstabLine(rule MountRule) string {
	switch rule.MountPoint {
	case "/dev/shm":
		return fmt.Sprintf("tmpfs %s tmpfs defaults,%s 0 0",
			rule.MountPoint, rule.Recommended)
	case "/tmp", "/var/tmp":
		return fmt.Sprintf("tmpfs %s tmpfs defaults,%s,size=4G,mode=1777 0 0",
			rule.MountPoint, rule.Recommended)
	}
	return fmt.Sprintf("<DEVICE> %s <FSTYPE> defaults,%s 0 0",
		rule.MountPoint, rule.Recommended)
}

// fstabLine is one entry from /etc/fstab. Captured with the original
// raw text so the tip renderer can quote the operator's actual line
// instead of a reconstructed approximation.
type fstabLine struct {
	LineNumber int
	Raw        string
	Source     string
	MountPoint string
	FSType     string
	Options    string
}

// findFstabEntry returns the first fstab line whose mount-point
// column matches `path`. Comment lines and blank lines are skipped.
func findFstabEntry(lines []fstabLine, path string) (fstabLine, bool) {
	for _, l := range lines {
		if l.MountPoint == path {
			return l, true
		}
	}
	return fstabLine{}, false
}

// parseFstab parses /etc/fstab content into fstabLine entries.
// Whitespace-separated columns; comment ('#') and blank lines are
// skipped. Lines with fewer than four columns (source, mountpoint,
// fstype, options) are skipped as malformed.
func parseFstab(content string) []fstabLine {
	var out []fstabLine
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineno := 0
	for scanner.Scan() {
		lineno++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		out = append(out, fstabLine{
			LineNumber: lineno,
			Raw:        raw,
			Source:     fields[0],
			MountPoint: fields[1],
			FSType:     fields[2],
			Options:    fields[3],
		})
	}
	return out
}

// realFstabReader is the production /etc/fstab reader. var so tests
// can substitute in-memory fixtures.
var realFstabReader = func() ([]fstabLine, error) {
	b, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return nil, err
	}
	return parseFstab(string(b)), nil
}

// unitNameForMountPath returns the systemd unit name for a mount
// path. Mirrors `systemd-escape --path`: leading slash dropped,
// remaining slashes replaced with '-'.
//
//	/tmp     -> tmp.mount
//	/var/tmp -> var-tmp.mount
//	/dev/shm -> dev-shm.mount
func unitNameForMountPath(p string) string {
	clean := strings.TrimPrefix(p, "/")
	if clean == "" {
		return "-.mount"
	}
	return strings.ReplaceAll(clean, "/", "-") + ".mount"
}

// systemdUnitSearchPaths lists the directories systemd searches for
// .mount units, in precedence order. /etc wins over /run wins over
// /usr — same precedence the unit-loader uses. We also include the
// fstab generator output so operators see "yes, this mount is owned
// by a generated unit — your fstab line IS the source of truth".
var systemdUnitSearchPaths = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/run/systemd/generator",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// realSystemdUnitFinder looks for `unitName` in the standard systemd
// unit search paths and parses out its current `Options=` line if
// present. var so tests can substitute.
var realSystemdUnitFinder = func(unitName string) (string, string, bool) {
	for _, dir := range systemdUnitSearchPaths {
		path := filepath.Join(dir, unitName)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		opts := parseUnitOptionsLine(string(b))
		return path, opts, true
	}
	return "", "", false
}

// parseUnitOptionsLine returns the value of the `Options=` line in a
// systemd .mount unit. Returns "" if not present.
func parseUnitOptionsLine(content string) string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	inMount := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inMount = strings.EqualFold(line, "[Mount]")
			continue
		}
		if !inMount {
			continue
		}
		if eq := strings.IndexByte(line, '='); eq > 0 {
			key := strings.TrimSpace(line[:eq])
			val := strings.TrimSpace(line[eq+1:])
			if strings.EqualFold(key, "Options") {
				return val
			}
		}
	}
	return ""
}

// appendMissingToCSV adds every option in `missing` to `current` (a
// comma-separated option set) without producing duplicates. Used by
// the tip renderer to show the operator the exact options column
// they should end up with.
func appendMissingToCSV(current string, missing []string) string {
	have := map[string]struct{}{}
	parts := strings.Split(current, ",")
	out := make([]string, 0, len(parts)+len(missing))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := have[p]; dup {
			continue
		}
		have[p] = struct{}{}
		out = append(out, p)
	}
	for _, m := range missing {
		if _, dup := have[m]; dup {
			continue
		}
		have[m] = struct{}{}
		out = append(out, m)
	}
	return strings.Join(out, ",")
}

// joinOrAll returns the comma-joined list when non-empty, falling
// back to the full recommended set. Used when callers may pass an
// empty Missing slice for bind sibling rows (we still want the
// example remount command to do something useful).
func joinOrAll(missing []string, fallback string) string {
	if len(missing) > 0 {
		return strings.Join(missing, ",")
	}
	return fallback
}
