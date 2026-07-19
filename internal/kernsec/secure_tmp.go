package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// secure-tmp constants. Fixed paths so operators recognise the layout
// on sight (cPanel / WHM standard); the subcommand intentionally does
// not expose a --device or --no-bind-var-tmp flag because every real
// hosting deployment ends up at this exact pairing anyway and a
// freestanding script would only encourage drift.
const (
	// SecureTmpDevicePath is the backing loop file that becomes /tmp
	// after reboot.
	SecureTmpDevicePath = "/var/tmpDSK"
	// SecureTmpScratchPath is the temporary mount point used to format
	// + stage /var/tmp contents into the new filesystem before fstab
	// takes effect. Hidden under /mnt with a leading dot so it doesn't
	// clutter operator-facing listings.
	SecureTmpScratchPath = "/mnt/.cfm-newtmp"
	// SecureTmpLabel is the ext4 label written into the loop file so
	// the mount survives device renames (loop numbers shift across
	// reboot) and is identifiable in `lsblk -f` / `blkid`.
	SecureTmpLabel = "cfm-securetmp"

	// secureTmpMinSize / MaxSize are the sanity bounds on the
	// operator-supplied size. Below 1G is almost certainly a typo
	// (cPanel default is 4G; we recommend 8G+ on busy servers); above
	// 256G is well past any realistic /tmp workload and probably a
	// misplaced disk-image size.
	secureTmpMinBytes = int64(1) << 30                // 1 GiB
	secureTmpMaxBytes = int64(256) << 30              // 256 GiB
	secureTmpHeadroom = int64(1) << 30                // require 1 GiB free above the requested size
	secureTmpMaxPctOfFree = 50                        // refuse if size > 50% of available free space on backing FS
)

// SecureTmpOptions controls the secure-tmp subcommand.
type SecureTmpOptions struct {
	// SizeBytes is the requested size of /var/tmpDSK in bytes. Parsed
	// from the operator-facing --size flag (e.g. "16G" → 16*GiB) by
	// ParseSecureTmpSize.
	SizeBytes int64
	// DryRun prints the plan without creating the loop file, mounting
	// scratch, or editing fstab. Safe to run as non-root.
	DryRun bool
}

// RunSecureTmp is the entry point for `cfm kernsec secure-tmp`. The
// flow is intentionally reboot-required: on a running production host
// /tmp is held open by every service with PrivateTmp=yes (mysqld,
// named, nginx, php-fpm, exim, …) plus tmux/screen sockets and open
// FDs on temp files. A live `umount /tmp` returns EBUSY and any
// remount-under-them risks stale FDs or service restart cascades.
// Instead the subcommand prepares the new filesystem, stages
// /var/tmp's persistent contents into it, edits fstab, and tells the
// operator to reboot at a convenient window.
//
// Idempotency: refuses if /var/tmpDSK already exists, refuses if /tmp
// is already a separate mount, refuses if fstab already has a /tmp or
// /var/tmp entry. Operators who hit the second-run path are explicitly
// told to revert (rm the device + restore fstab from .cfm-kernsec.bak)
// rather than silently shadowing existing state.
func RunSecureTmp(w io.Writer, opts SecureTmpOptions) int {
	if !opts.DryRun && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec secure-tmp: must run as root (use --dry-run to inspect without writing)")
		return 1
	}

	if err := opts.validate(); err != nil {
		fmt.Fprintln(w, "kernsec secure-tmp:", err)
		return 2
	}

	// Pre-flights gather every refusal up-front so the operator sees
	// the complete list of problems in one pass, not one error per
	// re-run. realSecureTmpEnv reads /proc/self/mountinfo, /etc/fstab,
	// statfs(2), and stat(2) on /var/tmpDSK; tests inject fakes.
	env, err := secureTmpEnv()
	if err != nil {
		fmt.Fprintln(w, "kernsec secure-tmp: pre-flight read error:", err)
		return 1
	}
	if blockers := preflightSecureTmp(opts, env); len(blockers) > 0 {
		fmt.Fprintln(w, "kernsec secure-tmp: refusing — host is not in a state where a clean install is safe:")
		for _, b := range blockers {
			fmt.Fprintf(w, "  - %s\n", b)
		}
		return 1
	}

	planFstab := secureTmpFstabLines()
	fmt.Fprintln(w, "===== CFM kernsec secure-tmp =====")
	fmt.Fprintf(w, "  size:          %s\n", humanBytes(opts.SizeBytes))
	fmt.Fprintf(w, "  device:        %s\n", SecureTmpDevicePath)
	fmt.Fprintf(w, "  label:         %s\n", SecureTmpLabel)
	fmt.Fprintf(w, "  scratch mount: %s\n", SecureTmpScratchPath)
	fmt.Fprintln(w, "  fstab entries to append:")
	for _, ln := range planFstab {
		fmt.Fprintf(w, "    %s\n", ln)
	}
	fmt.Fprintln(w, "  /var/tmp staging: non-systemd-private contents copied into the new filesystem")
	fmt.Fprintln(w)

	if opts.DryRun {
		fmt.Fprintln(w, "(dry-run; nothing written)")
		fmt.Fprintln(w, "===================================")
		return 0
	}

	release, err := acquireKernsecLock()
	if err != nil {
		fmt.Fprintln(w, "kernsec secure-tmp:", err)
		return 1
	}
	defer release()

	if rc := secureTmpExecute(w, opts); rc != 0 {
		return rc
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[+] secure-tmp staged. Reboot at a convenient window to activate:")
	fmt.Fprintln(w, "      systemctl reboot")
	fmt.Fprintln(w, "    After reboot, verify with:")
	fmt.Fprintln(w, "      findmnt /tmp        (should show /var/tmpDSK at /tmp)")
	fmt.Fprintln(w, "      findmnt /var/tmp    (should show bind of /tmp)")
	fmt.Fprintln(w, "===================================")
	return 0
}

// validate sanity-checks the parsed options. Per-host concerns
// (existing fstab entries, /tmp already separate, free space) belong
// in preflightSecureTmp; this is the always-runs cheap argument check.
func (o SecureTmpOptions) validate() error {
	if o.SizeBytes < secureTmpMinBytes {
		return fmt.Errorf("--size too small (got %s, minimum %s)",
			humanBytes(o.SizeBytes), humanBytes(secureTmpMinBytes))
	}
	if o.SizeBytes > secureTmpMaxBytes {
		return fmt.Errorf("--size too large (got %s, maximum %s) — re-check, this is almost certainly a typo",
			humanBytes(o.SizeBytes), humanBytes(secureTmpMaxBytes))
	}
	return nil
}

// ParseSecureTmpSize parses an operator-supplied size string. Accepts
// `<N>G` (GiB) or `<N>M` (MiB) — no bare-byte form, since /tmp <1G is
// not a realistic hosting workload and we don't want to encourage it.
// Case-insensitive; whitespace tolerated. Returns bytes.
func ParseSecureTmpSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, errors.New("--size is required (e.g. --size 16G)")
	}
	var mult int64
	switch {
	case strings.HasSuffix(s, "GB"):
		s = strings.TrimSuffix(s, "GB")
		mult = 1 << 30
	case strings.HasSuffix(s, "G"):
		s = strings.TrimSuffix(s, "G")
		mult = 1 << 30
	case strings.HasSuffix(s, "MB"):
		s = strings.TrimSuffix(s, "MB")
		mult = 1 << 20
	case strings.HasSuffix(s, "M"):
		s = strings.TrimSuffix(s, "M")
		mult = 1 << 20
	default:
		return 0, fmt.Errorf("unrecognised size %q — use a G or M suffix (e.g. 16G)", s)
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("unrecognised size — expected positive integer + G/M suffix")
	}
	return n * mult, nil
}

// secureTmpEnv holds the per-host facts preflightSecureTmp consults.
// Populated by the production secureTmpEnv() reader; tests inject a
// hand-rolled value to drive each refusal path.
type secureTmpEnvFacts struct {
	// TmpIsSeparate / VarTmpIsSeparate report whether /tmp or
	// /var/tmp is already a distinct mount in /proc/self/mountinfo.
	// Either being true refuses the install.
	TmpIsSeparate    bool
	VarTmpIsSeparate bool
	// FstabHasTmp / FstabHasVarTmp report whether /etc/fstab already
	// has an entry for /tmp or /var/tmp. Either being true refuses —
	// we don't want to leave duplicate / conflicting fstab lines that
	// the operator then has to untangle.
	FstabHasTmp    bool
	FstabHasVarTmp bool
	// DeviceExists reports whether /var/tmpDSK already exists on
	// disk. If it does, the operator either has a half-finished
	// install or an unrelated file we shouldn't overwrite.
	DeviceExists bool
	// FreeBytes is the available space on the filesystem that will
	// hold /var/tmpDSK (i.e. statfs of /var). Used to refuse silly
	// sizes that would fill the disk.
	FreeBytes int64
}

// secureTmpEnv is the production reader. var so tests can replace it
// without touching the system.
var secureTmpEnv = func() (secureTmpEnvFacts, error) {
	out := secureTmpEnvFacts{}

	loaded, err := readMountPoints()
	if err != nil {
		return out, fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}
	out.TmpIsSeparate = loaded["/tmp"]
	out.VarTmpIsSeparate = loaded["/var/tmp"]

	fstab, err := realFstabReader()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("read /etc/fstab: %w", err)
	}
	for _, l := range fstab {
		switch l.MountPoint {
		case "/tmp":
			out.FstabHasTmp = true
		case "/var/tmp":
			out.FstabHasVarTmp = true
		}
	}

	if _, err := os.Stat(SecureTmpDevicePath); err == nil {
		out.DeviceExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("stat %s: %w", SecureTmpDevicePath, err)
	}

	out.FreeBytes = statfsFreeBytes(filepath.Dir(SecureTmpDevicePath))
	return out, nil
}

// readMountPoints returns the set of currently-mounted mount points
// from /proc/self/mountinfo. Used to distinguish "/tmp is a separate
// mount" from "/tmp lives on /" — the audit's MountNotSeparate state
// uses the same data path.
func readMountPoints() (map[string]bool, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		// mountinfo columns: 1=mount-id 2=parent 3=major:minor
		// 4=root 5=mount-point …
		if len(fields) < 5 {
			continue
		}
		out[fields[4]] = true
	}
	return out, nil
}

// statfsFreeBytes returns the bytes available to a non-root user on
// the filesystem containing `path`. We use the unprivileged figure
// (Bavail) rather than Bfree because reserved-blocks shouldn't count
// toward the operator's headroom — exhausting them would surface as
// ENOSPC on every userspace process.
func statfsFreeBytes(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

// preflightSecureTmp returns the list of human-readable blockers
// (empty means safe to proceed). Order is deterministic so test
// fixtures can pin specific messages.
func preflightSecureTmp(opts SecureTmpOptions, env secureTmpEnvFacts) []string {
	var blockers []string
	if env.TmpIsSeparate {
		blockers = append(blockers,
			"/tmp is already a separate mount — secure-tmp is for hosts where /tmp lives on /. "+
				"Edit /etc/fstab directly if you want to change its options.")
	}
	if env.VarTmpIsSeparate {
		blockers = append(blockers,
			"/var/tmp is already a separate mount — edit /etc/fstab directly to change it.")
	}
	if env.FstabHasTmp {
		blockers = append(blockers,
			"/etc/fstab already has an entry for /tmp — review and remove it before running secure-tmp.")
	}
	if env.FstabHasVarTmp {
		blockers = append(blockers,
			"/etc/fstab already has an entry for /var/tmp — review and remove it before running secure-tmp.")
	}
	if env.DeviceExists {
		blockers = append(blockers,
			SecureTmpDevicePath+" already exists — either a previous secure-tmp run is half-done "+
				"(remove the file and re-run) or the path is in use by something else.")
	}
	if env.FreeBytes >= 0 {
		needed := opts.SizeBytes + secureTmpHeadroom
		if env.FreeBytes < needed {
			blockers = append(blockers, fmt.Sprintf(
				"not enough free space on %s — need %s (%s requested + %s headroom), have %s available",
				filepath.Dir(SecureTmpDevicePath),
				humanBytes(needed), humanBytes(opts.SizeBytes), humanBytes(secureTmpHeadroom),
				humanBytes(env.FreeBytes)))
		}
		// Refuse if the operator asked for >50% of available space —
		// the host will run with no room to spare for actual workload.
		pct := (opts.SizeBytes * 100) / max1(env.FreeBytes)
		if pct > int64(secureTmpMaxPctOfFree) {
			blockers = append(blockers, fmt.Sprintf(
				"--size %s is %d%% of available free space on %s (max %d%%) — leave headroom for the actual workload",
				humanBytes(opts.SizeBytes), pct, filepath.Dir(SecureTmpDevicePath),
				secureTmpMaxPctOfFree))
		}
	}
	return blockers
}

// max1 returns x or 1 to keep percentage math safe when statfs failed.
func max1(x int64) int64 {
	if x < 1 {
		return 1
	}
	return x
}

// secureTmpFstabLines returns the two lines secure-tmp appends to
// /etc/fstab. Kept as a separate function so dry-run preview, the
// real fstab edit, and tests render exactly the same text.
//
// Both lines carry `nofail` deliberately: without it, systemd makes a
// fstab entry a hard requirement of local-fs.target, so a damaged or
// deleted /var/tmpDSK (fsck pass is 0 — the ext4 inside is never
// checked) would drop the host into emergency mode at boot — no SSH,
// console-only recovery. With nofail the host still boots and /tmp
// falls back to a plain root directory: temporarily unhardened (no
// noexec) but UP and reachable, which is the right availability
// trade-off for a remote fleet. A hardening gap can be fixed over
// SSH; a host stuck in emergency mode cannot.
func secureTmpFstabLines() []string {
	return []string{
		fmt.Sprintf("%s  /tmp      ext4  loop,nofail,nodev,nosuid,noexec,rw  0 0", SecureTmpDevicePath),
		"/tmp        /var/tmp  none  bind,nofail                          0 0",
	}
}

// secureTmpExecute runs the live install: fallocate, mkfs, scratch
// mount, /var/tmp staging, scratch umount, fstab edit. Each step
// emits a one-line progress message so the operator can correlate
// failure with the exact stage.
//
// Cleanup-on-failure: any error past fallocate leaves the partly-built
// /var/tmpDSK on disk and (potentially) a scratch mount up. We refuse
// to "tidy up" by deleting it automatically — an operator-readable
// message that names the leftover state is safer than a silent rm of a
// file the operator might be inspecting.
func secureTmpExecute(w io.Writer, opts SecureTmpOptions) int {
	// 1. fallocate the backing file.
	fmt.Fprintf(w, "[1/5] fallocate %s (%s)\n", SecureTmpDevicePath, humanBytes(opts.SizeBytes))
	if err := runCmd("fallocate", "-l", strconv.FormatInt(opts.SizeBytes, 10), SecureTmpDevicePath); err != nil {
		fmt.Fprintln(w, "      ERROR:", err)
		return 1
	}
	if err := os.Chmod(SecureTmpDevicePath, 0o600); err != nil {
		fmt.Fprintln(w, "      chmod 0600:", err)
		return 1
	}

	// 2. Format ext4 with the cfm-securetmp label. -F is required
	// because the target is a regular file, not a block device, and
	// mke2fs would otherwise prompt.
	fmt.Fprintln(w, "[2/5] mkfs.ext4 -F -L "+SecureTmpLabel)
	if err := runCmd("mkfs.ext4", "-F", "-L", SecureTmpLabel, SecureTmpDevicePath); err != nil {
		fmt.Fprintln(w, "      ERROR:", err)
		fmt.Fprintf(w, "      leftover state: %s (remove manually before re-running)\n", SecureTmpDevicePath)
		return 1
	}

	// 3. Mount at scratch path so we can populate it before fstab kicks in.
	fmt.Fprintf(w, "[3/5] mount %s at %s (scratch)\n", SecureTmpDevicePath, SecureTmpScratchPath)
	if err := os.MkdirAll(SecureTmpScratchPath, 0o755); err != nil {
		fmt.Fprintln(w, "      mkdir scratch:", err)
		fmt.Fprintf(w, "      leftover state: %s (remove manually before re-running)\n", SecureTmpDevicePath)
		return 1
	}
	if err := runCmd("mount", "-o", "loop,nodev,nosuid,noexec,rw", SecureTmpDevicePath, SecureTmpScratchPath); err != nil {
		fmt.Fprintln(w, "      mount scratch:", err)
		fmt.Fprintf(w, "      leftover state: %s (remove manually before re-running)\n", SecureTmpDevicePath)
		return 1
	}
	if err := os.Chmod(SecureTmpScratchPath, 0o1777); err != nil {
		fmt.Fprintln(w, "      chmod 1777 scratch:", err)
		// Best-effort umount; ignore errors from cleanup itself.
		_ = runCmd("umount", SecureTmpScratchPath)
		return 1
	}

	// 4. Stage /var/tmp contents (excluding systemd-private-*) into
	// the new filesystem. /tmp is intentionally NOT copied: systemd-
	// tmpfiles wipes /tmp at every boot, so its contents are
	// throwaway by contract.
	fmt.Fprintln(w, "[4/5] stage /var/tmp contents (skipping systemd-private-*)")
	staged, copyErr := stageVarTmpInto(SecureTmpScratchPath)
	if copyErr != nil {
		fmt.Fprintln(w, "      stage:", copyErr)
		_ = runCmd("umount", SecureTmpScratchPath)
		return 1
	}
	fmt.Fprintf(w, "      staged %d /var/tmp entries\n", staged)

	if err := runCmd("umount", SecureTmpScratchPath); err != nil {
		fmt.Fprintln(w, "      umount scratch:", err)
		return 1
	}
	_ = os.Remove(SecureTmpScratchPath) // best-effort cleanup of the empty dir

	// 5. Append the two fstab lines. BackupOnce gives the operator a
	// one-shot restore point (/etc/fstab.cfm-kernsec.bak) for a clean
	// revert later: stop services, umount /var/tmp + /tmp, restore
	// fstab from .bak, rm /var/tmpDSK, reboot.
	fmt.Fprintln(w, "[5/5] append /etc/fstab")
	if err := appendSecureTmpFstab(); err != nil {
		fmt.Fprintln(w, "      ERROR:", err)
		return 1
	}
	return 0
}

// stageVarTmpInto copies every top-level entry of /var/tmp into dst,
// skipping systemd-private-* directories (those are recreated by
// systemd when each service restarts after boot; copying them would
// preserve stale bind-mount source dirs the host no longer needs).
// Returns the number of entries copied.
//
// Uses /usr/bin/cp -a --one-file-system so the copy preserves owner,
// mode, timestamps, xattrs, ACLs without us reimplementing them in
// Go. Errors from the cp invocation propagate to the caller so the
// scratch mount gets cleaned up.
func stageVarTmpInto(dst string) (int, error) {
	entries, err := os.ReadDir("/var/tmp")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read /var/tmp: %w", err)
	}
	count := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "systemd-private-") {
			continue
		}
		src := filepath.Join("/var/tmp", name)
		if err := runCmd("cp", "-a", "--one-file-system", src, dst+"/"); err != nil {
			return count, fmt.Errorf("cp %s: %w", src, err)
		}
		count++
	}
	return count, nil
}

// appendSecureTmpFstab adds the two secure-tmp fstab entries to
// /etc/fstab, taking a BackupOnce of the original first. Refuses to
// run if either entry is already present (preflightSecureTmp catches
// that earlier; this is the defence-in-depth re-check at the actual
// write point).
func appendSecureTmpFstab() error {
	const fstabPath = "/etc/fstab"
	current, err := os.ReadFile(fstabPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", fstabPath, err)
	}
	currStr := string(current)
	// Defence in depth: pre-flight already refused on these, but if a
	// concurrent edit slipped in we want a hard fail rather than a
	// duplicate line.
	for _, mp := range []string{" /tmp ", " /tmp\t", " /var/tmp ", " /var/tmp\t"} {
		if strings.Contains(currStr, mp) {
			return fmt.Errorf("/etc/fstab now contains %s — refusing to append duplicate entry",
				strings.TrimSpace(mp))
		}
	}
	if err := BackupOnce(fstabPath, fstabPath+BackupSuffix); err != nil {
		return fmt.Errorf("backup fstab: %w", err)
	}
	var b strings.Builder
	b.Write(current)
	if len(current) > 0 && current[len(current)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString("\n# Added by cfm kernsec secure-tmp — hardened /tmp + /var/tmp.\n")
	b.WriteString("# Revert: remove these two lines, restore from " + fstabPath + BackupSuffix + ", rm " + SecureTmpDevicePath + ".\n")
	for _, ln := range secureTmpFstabLines() {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return AtomicWriteFile(fstabPath, []byte(b.String()), 0o644)
}

// runCmd is the production command runner. var so tests can override
// it to record invocations without spawning external binaries.
var runCmd = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// humanBytes formats a byte count as "8.0G" / "512M" / "1024" for
// operator-facing output. Cutoffs match what `df -h` / fallocate
// would print so the operator sees consistent units across tools.
func humanBytes(n int64) string {
	switch {
	case n < 0:
		return "?"
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dG", n>>30)
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/float64(1<<30))
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dM", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/float64(1<<20))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
