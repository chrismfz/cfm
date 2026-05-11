package kernsec

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// BLSBackupPath is where WriteCmdline saves the pre-apply BLS rollback
// snapshot on grubby hosts. Unlike the GRUB and Proxmox backends, BLS has
// no single source file — so we capture per-kernel managed tokens into
// this path and use them in `cfm kernsec rollback`.
var BLSBackupPath = "/var/lib/cfm/kernsec-bls-cmdline.cfm-kernsec.bak"

// GRUBManagedBackupPath and ProxmoxManagedBackupPath store the current
// rollback snapshot format for single-cmdline boot backends. The legacy
// <source>.cfm-kernsec.bak files remain full-file backups for manual
// recovery and pre-upgrade rollback compatibility; these snapshots contain
// only pre-apply kernsec-managed tokens.
var (
	GRUBManagedBackupPath    = "/var/lib/cfm/kernsec-grub-cmdline.cfm-kernsec.bak"
	ProxmoxManagedBackupPath = "/var/lib/cfm/kernsec-proxmox-cmdline.cfm-kernsec.bak"
)

// RunRollback restores the pre-kernsec bootloader configuration from
// .cfm-kernsec.bak files and refreshes the bootloader. It is the
// operator escape hatch after a bad `cfm kernsec apply`.
//
// Per-backend behaviour:
//
//   - Legacy GRUB: removes only kernsec-managed keys from the current
//     GRUB_CMDLINE_LINUX value, restores only saved kernsec-managed values
//     when a current-format managed snapshot exists, then regenerates grub.cfg.
//     Legacy full-file backups are byte-restored only after a safe exact
//     expected-form comparison.
//   - Proxmox: removes only kernsec-managed keys from the current
//     /etc/kernel/cmdline, restores only saved kernsec-managed values when a
//     current-format managed snapshot exists, then runs proxmox-boot-tool
//     refresh. Legacy full-file backups use the same safe comparison gate.
//   - BLS / grubby: strips all managed args from every non-rescue kernel.
//     If a current-format pre-apply snapshot exists at BLSBackupPath,
//     restores only the per-kernel managed tokens saved for the matching
//     kernel path; old full-cmdline snapshots are ignored defensively.
//
// The managed sysctl file (/etc/sysctl.d/99-cfm-kernsec.conf) is
// removed so the next reboot sees kernel defaults. Live sysctl values
// persist until reboot — same semantics as `cfm kernsec disable`.
func RunRollback(w io.Writer, dryRun bool) int {
	if !dryRun && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec rollback: must run as root (use --dry-run to inspect)")
		return 1
	}

	fs := RealFS{}
	backend := DetectBackend(fs)

	fmt.Fprintln(w, "===== CFM kernsec ROLLBACK =====")
	fmt.Fprintf(w, "Backend: %s\n", backend.Label())
	if dryRun {
		fmt.Fprintln(w, "Mode:    --dry-run (no writes)")
	}
	fmt.Fprintln(w)

	rc := 0
	switch be := backend.(type) {
	case *GRUBBackend:
		rc = rollbackGRUB(w, dryRun, be.FS)
	case *ProxmoxBackend:
		rc = rollbackProxmox(w, dryRun, be.FS)
	case *BLSBackend:
		rc = rollbackBLS(w, dryRun, fs)
		_ = be
	default:
		fmt.Fprintf(w, "[!] unknown backend type %T — cannot auto-rollback\n", backend)
		return 1
	}

	if rc != 0 {
		return rc
	}

	// Remove the managed sysctl file so the next reboot reflects kernel
	// defaults. Live values persist until reboot (same as disable).
	if err := removeManagedSysctlFile(w, dryRun); err != nil {
		fmt.Fprintf(w, "[!] could not remove managed sysctl file: %v\n", err)
		rc = 1
	}

	if rc == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "[+] Rollback complete. Reboot to apply the restored cmdline.")
		fmt.Fprintln(w, "    Live sysctl values persist until reboot.")
	}
	fmt.Fprintln(w, "================================")
	return rc
}

// rollbackGRUB removes kernsec-managed args from the current
// GRUB_CMDLINE_LINUX value, restores only pre-apply managed tokens when the
// current managed snapshot exists, and regenerates grub.cfg. Legacy full-file
// backups are byte-restored only when the current file still matches the
// post-kernsec form derived from that backup.
func rollbackGRUB(w io.Writer, dryRun bool, fs FS) int {
	legacyBak := PathDefaultGrub + BackupSuffix
	snap, hasSnapshot, snapErr := readManagedBootArgSnapshot(GRUBManagedBackupPath)
	if snapErr != nil {
		fmt.Fprintf(w, "[Boot] Ignoring GRUB managed-args snapshot at %s: %v\n", GRUBManagedBackupPath, snapErr)
	}
	if !hasSnapshot {
		if _, err := os.Stat(legacyBak); os.IsNotExist(err) {
			fmt.Fprintf(w, "[!] No managed snapshot at %s and no legacy backup at %s\n", GRUBManagedBackupPath, legacyBak)
			fmt.Fprintln(w, "    cfm kernsec has not yet applied any changes to this host,")
			fmt.Fprintln(w, "    or rollback data was already restored / manually removed.")
			return 1
		}
	}

	if hasSnapshot {
		fmt.Fprintf(w, "[Boot] will remove kernsec-managed keys from %s and restore saved managed values from %s\n", PathDefaultGrub, GRUBManagedBackupPath)
	} else {
		fmt.Fprintf(w, "[Boot] no managed snapshot found; will use legacy backup %s only if current content matches kernsec's expected post-apply form\n", legacyBak)
	}
	if dryRun {
		return 0
	}

	current, err := os.ReadFile(PathDefaultGrub)
	if err != nil {
		fmt.Fprintf(w, "[!] read %s: %v\n", PathDefaultGrub, err)
		return 1
	}

	var outContent []byte
	if hasSnapshot {
		out, err := grubContentWithManagedArgs(string(current), snap.Args)
		if err != nil {
			fmt.Fprintf(w, "[!] rollback %s safely: %v\n", PathDefaultGrub, err)
			printManualGRUBRecovery(w)
			return 1
		}
		outContent = []byte(out)
	} else {
		legacy, err := os.ReadFile(legacyBak)
		if err != nil {
			fmt.Fprintf(w, "[!] read %s: %v\n", legacyBak, err)
			return 1
		}
		expected, err := expectedLegacyGRUBPostApply(string(legacy), string(current))
		if err != nil {
			fmt.Fprintf(w, "[!] inspect legacy rollback state: %v\n", err)
			printManualGRUBRecovery(w)
			return 1
		}
		if string(current) != expected {
			fmt.Fprintf(w, "[!] refusing legacy byte-restore of %s: current content no longer matches kernsec's expected post-apply form.\n", PathDefaultGrub)
			fmt.Fprintln(w, "    This usually means non-kernsec/operator boot arguments were added after apply.")
			printManualGRUBRecovery(w)
			return 1
		}
		outContent = legacy
	}

	if err := AtomicWriteFile(PathDefaultGrub, outContent, 0o644); err != nil {
		fmt.Fprintf(w, "[!] restore %s: %v\n", PathDefaultGrub, err)
		return 1
	}
	fmt.Fprintf(w, "[Boot] rolled back kernsec-managed GRUB args in %s\n", PathDefaultGrub)

	grub := &GRUBBackend{FS: fs}
	grubRefresh, grubRefreshArgs, err := grub.refreshCommand()
	if err != nil {
		fmt.Fprintf(w, "[!] %v\n", err)
		fmt.Fprintln(w, "    run the appropriate command manually to regenerate grub.cfg")
		return 1
	}
	out, err := fs.RunCapture(grubRefresh, grubRefreshArgs...)
	if err != nil {
		fmt.Fprintf(w, "[!] %s: %v: %s\n", grubRefreshDisplay(grubRefresh, grubRefreshArgs), err, out)
		return 1
	}
	fmt.Fprintf(w, "[Boot] ran %s — grub.cfg regenerated.\n", grubRefreshDisplay(grubRefresh, grubRefreshArgs))
	return 0
}

// rollbackProxmox removes kernsec-managed args from /etc/kernel/cmdline,
// restores only pre-apply managed tokens when the current managed snapshot
// exists, and refreshes proxmox-boot-tool. Legacy full-file backups are
// byte-restored only after an exact post-kernsec expected-form comparison.
func rollbackProxmox(w io.Writer, dryRun bool, fs FS) int {
	legacyBak := PathPVECmdline + BackupSuffix
	snap, hasSnapshot, snapErr := readManagedBootArgSnapshot(ProxmoxManagedBackupPath)
	if snapErr != nil {
		fmt.Fprintf(w, "[Boot] Ignoring Proxmox managed-args snapshot at %s: %v\n", ProxmoxManagedBackupPath, snapErr)
	}
	if !hasSnapshot {
		if _, err := os.Stat(legacyBak); os.IsNotExist(err) {
			fmt.Fprintf(w, "[!] No managed snapshot at %s and no legacy backup at %s\n", ProxmoxManagedBackupPath, legacyBak)
			fmt.Fprintln(w, "    cfm kernsec has not yet applied any changes to this host.")
			return 1
		}
	}

	if hasSnapshot {
		fmt.Fprintf(w, "[Boot] will remove kernsec-managed keys from %s and restore saved managed values from %s\n", PathPVECmdline, ProxmoxManagedBackupPath)
	} else {
		fmt.Fprintf(w, "[Boot] no managed snapshot found; will use legacy backup %s only if current content matches kernsec's expected post-apply form\n", legacyBak)
	}
	if dryRun {
		return 0
	}

	current, err := os.ReadFile(PathPVECmdline)
	if err != nil {
		fmt.Fprintf(w, "[!] read %s: %v\n", PathPVECmdline, err)
		return 1
	}

	var outContent []byte
	if hasSnapshot {
		tokens := rebuildManagedTokens(ParseCmdline(string(current)), snap.Args)
		outContent = []byte(strings.Join(tokens, " ") + "\n")
	} else {
		legacy, err := os.ReadFile(legacyBak)
		if err != nil {
			fmt.Fprintf(w, "[!] read %s: %v\n", legacyBak, err)
			return 1
		}
		expected := expectedLegacyCmdlinePostApply(string(legacy), string(current))
		if string(current) != expected {
			fmt.Fprintf(w, "[!] refusing legacy byte-restore of %s: current content no longer matches kernsec's expected post-apply form.\n", PathPVECmdline)
			fmt.Fprintln(w, "    This usually means non-kernsec/operator boot arguments were added after apply.")
			printManualProxmoxRecovery(w)
			return 1
		}
		outContent = legacy
	}

	if err := AtomicWriteFile(PathPVECmdline, outContent, 0o644); err != nil {
		fmt.Fprintf(w, "[!] restore %s: %v\n", PathPVECmdline, err)
		return 1
	}
	fmt.Fprintf(w, "[Boot] rolled back kernsec-managed Proxmox args in %s\n", PathPVECmdline)

	out, err := fs.RunCapture("proxmox-boot-tool", "refresh")
	if err != nil {
		fmt.Fprintf(w, "[!] proxmox-boot-tool refresh: %v: %s\n", err, out)
		return 1
	}
	fmt.Fprintln(w, "[Boot] proxmox-boot-tool refresh complete.")
	return 0
}

// rollbackBLS restores managed args on BLS hosts. It always performs the
// safest rollback operation first: strip kernsec-managed keys from every
// non-rescue kernel while leaving unmanaged args untouched. If a
// current-format snapshot exists, rollback then restores only the saved
// managed tokens for matching kernel paths. Legacy snapshots containing a
// default kernel's full cmdline are ignored rather than replayed onto every
// kernel.
func rollbackBLS(w io.Writer, dryRun bool, fs FS) int {
	bak := BLSBackupPath
	snap, hasSnapshot, snapErr := readBLSRollbackSnapshot(bak)
	if snapErr != nil {
		fmt.Fprintf(w, "[Boot] Ignoring BLS snapshot at %s: %v\n", bak, snapErr)
	}

	if hasSnapshot {
		fmt.Fprintf(w, "[Boot] BLS managed-args snapshot found at %s — will restore matching kernels.\n", bak)
	} else {
		fmt.Fprintln(w, "[Boot] No usable BLS managed-args snapshot found.")
		fmt.Fprintln(w, "       Will strip managed args only; unmanaged args stay untouched.")
	}

	if dryRun {
		return 0
	}

	out, err := fs.RunCapture("grubby", "--info=ALL")
	if err != nil {
		fmt.Fprintf(w, "[!] grubby --info=ALL: %v\n", err)
		return 1
	}
	entries := nonRecoveryKernelEntries(parseGrubbyAll(out))
	targets := kernelPaths(entries)
	if len(targets) == 0 {
		fmt.Fprintln(w, "[Boot] No non-rescue kernels found — nothing to restore.")
		return 0
	}

	// grubby's --update-kernel takes a single kernel-path (or ALL /
	// DEFAULT / TITLE=...) — comma-separated lists are rejected as an
	// invalid path. Loop once per non-rescue kernel.
	removeArg := "--remove-args=" + joinKeys(ManagedBootArgKeys, " ")
	for _, kernel := range targets {
		stripCmd := []string{"--update-kernel=" + kernel, removeArg}
		if runOut, err := fs.RunCapture("grubby", stripCmd...); err != nil {
			fmt.Fprintf(w, "[!] grubby strip %s: %v: %s\n", kernel, err, runOut)
			return 1
		}
	}
	fmt.Fprintln(w, "[Boot] grubby: managed args stripped from all non-rescue kernels.")

	if hasSnapshot {
		for _, kernel := range targets {
			managed := snap.Kernels[kernel]
			if len(managed) == 0 {
				continue
			}
			cmd := []string{"--update-kernel=" + kernel, "--args=" + strings.Join(managed, " ")}
			if runOut, err := fs.RunCapture("grubby", cmd...); err != nil {
				fmt.Fprintf(w, "[!] grubby restore %s: %v: %s\n", kernel, err, runOut)
				return 1
			}
		}
		fmt.Fprintln(w, "[Boot] pre-apply managed args restored for matching kernels.")
	}
	return 0
}

func readBLSRollbackSnapshot(path string) (blsRollbackSnapshot, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return blsRollbackSnapshot{}, false, nil
	}
	if err != nil {
		return blsRollbackSnapshot{}, false, err
	}
	var snap blsRollbackSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return blsRollbackSnapshot{}, false, fmt.Errorf("unrecognized or legacy format")
	}
	if snap.Version != blsRollbackSnapshotVersion {
		return blsRollbackSnapshot{}, false, fmt.Errorf("unsupported format version %d", snap.Version)
	}
	clean := blsRollbackSnapshot{Version: snap.Version, Kernels: map[string][]string{}}
	for kernel, tokens := range snap.Kernels {
		if kernel == "" {
			continue
		}
		managed := KeepManagedArgs(tokens)
		if len(managed) > 0 {
			clean.Kernels[kernel] = managed
		}
	}
	return clean, true, nil
}

type managedBootArgSnapshot struct {
	Version int      `json:"version"`
	Args    []string `json:"args"`
}

const managedBootArgSnapshotVersion = 1

func writeManagedBootArgSnapshot(path string, tokens []string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	snap := managedBootArgSnapshot{
		Version: managedBootArgSnapshotVersion,
		Args:    KeepManagedArgs(tokens),
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return AtomicWriteFile(path, data, 0o644)
}

func readManagedBootArgSnapshot(path string) (managedBootArgSnapshot, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return managedBootArgSnapshot{}, false, nil
	}
	if err != nil {
		return managedBootArgSnapshot{}, false, err
	}
	var snap managedBootArgSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return managedBootArgSnapshot{}, false, fmt.Errorf("unrecognized or legacy format")
	}
	if snap.Version != managedBootArgSnapshotVersion {
		return managedBootArgSnapshot{}, false, fmt.Errorf("unsupported format version %d", snap.Version)
	}
	return managedBootArgSnapshot{Version: snap.Version, Args: KeepManagedArgs(snap.Args)}, true, nil
}

func rebuildManagedTokens(currentTokens, managed []string) []string {
	out := RemoveManagedArgs(currentTokens)
	out = append(out, KeepManagedArgs(managed)...)
	return out
}

func grubContentWithManagedArgs(content string, managed []string) (string, error) {
	currentLinux, err := readGrubCmdlineLinuxForRollback(content)
	if err != nil {
		return "", err
	}
	restored := strings.Join(rebuildManagedTokens(ParseCmdline(currentLinux), managed), " ")
	encoded := encodeGrubCmdlineValueForRollback(restored)
	out, found := rewriteGrubCmdlineLinux(content, encoded)
	if !found {
		out += "\n" + grubCmdlineLineEncoded(encoded) + "\n"
	}
	return out, nil
}

func expectedLegacyGRUBPostApply(legacyContent, currentContent string) (string, error) {
	currentLinux, err := readGrubCmdlineLinuxForRollback(currentContent)
	if err != nil {
		return "", fmt.Errorf("read current GRUB_CMDLINE_LINUX: %w", err)
	}
	currentManaged := KeepManagedArgs(ParseCmdline(currentLinux))
	return grubContentWithManagedArgs(legacyContent, currentManaged)
}

func expectedLegacyCmdlinePostApply(legacyContent, currentContent string) string {
	currentManaged := KeepManagedArgs(ParseCmdline(currentContent))
	tokens := rebuildManagedTokens(ParseCmdline(legacyContent), currentManaged)
	return strings.Join(tokens, " ") + "\n"
}

func readGrubCmdlineLinuxForRollback(content string) (string, error) {
	return readGrubCmdlineVarForRollback(content, "GRUB_CMDLINE_LINUX")
}

func readGrubCmdlineVarForRollback(content, varName string) (string, error) {
	prefix := varName + "="
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, prefix) {
			continue
		}
		val := strings.TrimPrefix(t, prefix)
		decoded, err := decodeGrubCmdlineValueForRollback(val)
		if err != nil {
			return "", fmt.Errorf("%s: %s: %w", PathDefaultGrub, varName, err)
		}
		return decoded, nil
	}
	return "", nil
}

func decodeGrubCmdlineValueForRollback(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return decodeDoubleQuoted(s[1 : len(s)-1])
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1], nil
	}
	return s, nil
}

func encodeGrubCmdlineValueForRollback(inner string) string {
	escaped := strings.ReplaceAll(inner, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func printManualGRUBRecovery(w io.Writer) {
	fmt.Fprintf(w, "    Manual recovery: edit %s, remove kernsec-managed keys (%s), restore any pre-kernsec managed values you still need from %s or %s, then regenerate grub.cfg.\n",
		PathDefaultGrub, strings.Join(ManagedBootArgKeys, ", "), GRUBManagedBackupPath, PathDefaultGrub+BackupSuffix)
}

func printManualProxmoxRecovery(w io.Writer) {
	fmt.Fprintf(w, "    Manual recovery: edit %s, remove kernsec-managed keys (%s), restore any pre-kernsec managed values you still need from %s or %s, then run proxmox-boot-tool refresh.\n",
		PathPVECmdline, strings.Join(ManagedBootArgKeys, ", "), ProxmoxManagedBackupPath, PathPVECmdline+BackupSuffix)
}

// removeManagedSysctlFile removes SysctlPath so the kernel reverts
// to distro defaults at next reboot. A no-op if the file is absent.
func removeManagedSysctlFile(w io.Writer, dryRun bool) error {
	if _, err := os.Stat(SysctlPath); os.IsNotExist(err) {
		fmt.Fprintf(w, "[Sysctl] %s not present — nothing to remove.\n", SysctlPath)
		return nil
	}
	fmt.Fprintf(w, "[Sysctl] will remove %s\n", SysctlPath)
	if dryRun {
		return nil
	}
	if err := os.Remove(SysctlPath); err != nil {
		return err
	}
	fmt.Fprintf(w, "[Sysctl] removed %s.\n", SysctlPath)
	return nil
}

func joinKeys(keys []string, sep string) string {
	result := ""
	for i, k := range keys {
		if i > 0 {
			result += sep
		}
		result += k
	}
	return result
}
