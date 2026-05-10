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

// RunRollback restores the pre-kernsec bootloader configuration from
// .cfm-kernsec.bak files and refreshes the bootloader. It is the
// operator escape hatch after a bad `cfm kernsec apply`.
//
// Per-backend behaviour:
//
//   - Legacy GRUB: reads /etc/default/grub.cfm-kernsec.bak → restores
//     /etc/default/grub → runs update-grub.
//   - Proxmox: reads /etc/kernel/cmdline.cfm-kernsec.bak → restores
//     /etc/kernel/cmdline → runs proxmox-boot-tool refresh.
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
		rc = rollbackGRUB(w, dryRun)
		_ = be
	case *ProxmoxBackend:
		rc = rollbackProxmox(w, dryRun)
		_ = be
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

// rollbackGRUB restores /etc/default/grub from its .cfm-kernsec.bak
// and regenerates grub.cfg via update-grub / grub2-mkconfig.
func rollbackGRUB(w io.Writer, dryRun bool) int {
	bak := PathDefaultGrub + BackupSuffix
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		fmt.Fprintf(w, "[!] No backup found at %s\n", bak)
		fmt.Fprintln(w, "    cfm kernsec has not yet applied any changes to this host,")
		fmt.Fprintln(w, "    or the backup was already restored / manually removed.")
		return 1
	}

	fmt.Fprintf(w, "[Boot] will restore %s from %s\n", PathDefaultGrub, bak)
	if dryRun {
		return 0
	}

	data, err := os.ReadFile(bak)
	if err != nil {
		fmt.Fprintf(w, "[!] read %s: %v\n", bak, err)
		return 1
	}
	if err := AtomicWriteFile(PathDefaultGrub, data, 0o644); err != nil {
		fmt.Fprintf(w, "[!] restore %s: %v\n", PathDefaultGrub, err)
		return 1
	}
	fmt.Fprintf(w, "[Boot] restored %s\n", PathDefaultGrub)

	fs := RealFS{}
	grubRefresh := grubRefreshCmd(fs)
	if grubRefresh == "" {
		fmt.Fprintln(w, "[!] no grub config generator found (tried update-grub, grub2-mkconfig, grub-mkconfig)")
		fmt.Fprintln(w, "    run the appropriate command manually to regenerate grub.cfg")
		return 1
	}
	out, err := fs.RunCapture(grubRefresh)
	if err != nil {
		fmt.Fprintf(w, "[!] %s: %v: %s\n", grubRefresh, err, out)
		return 1
	}
	fmt.Fprintf(w, "[Boot] ran %s — grub.cfg regenerated.\n", grubRefresh)
	return 0
}

// rollbackProxmox restores /etc/kernel/cmdline from its backup and
// runs proxmox-boot-tool refresh.
func rollbackProxmox(w io.Writer, dryRun bool) int {
	bak := PathPVECmdline + BackupSuffix
	if _, err := os.Stat(bak); os.IsNotExist(err) {
		fmt.Fprintf(w, "[!] No backup found at %s\n", bak)
		fmt.Fprintln(w, "    cfm kernsec has not yet applied any changes to this host.")
		return 1
	}

	fmt.Fprintf(w, "[Boot] will restore %s from %s\n", PathPVECmdline, bak)
	if dryRun {
		return 0
	}

	data, err := os.ReadFile(bak)
	if err != nil {
		fmt.Fprintf(w, "[!] read %s: %v\n", bak, err)
		return 1
	}
	if err := AtomicWriteFile(PathPVECmdline, data, 0o644); err != nil {
		fmt.Fprintf(w, "[!] restore %s: %v\n", PathPVECmdline, err)
		return 1
	}
	fmt.Fprintf(w, "[Boot] restored %s\n", PathPVECmdline)

	fs := RealFS{}
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

	removeArg := "--remove-args=" + joinKeys(ManagedBootArgKeys, " ")
	stripCmd := []string{"--update-kernel=" + joinComma(targets), removeArg}
	if runOut, err := fs.RunCapture("grubby", stripCmd...); err != nil {
		fmt.Fprintf(w, "[!] grubby: %v: %s\n", err, runOut)
		return 1
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

// grubRefreshCmd returns the name of the grub config generator
// present on this host (update-grub, grub2-mkconfig, grub-mkconfig),
// or "" if none is found.
func grubRefreshCmd(fs FS) string {
	for _, cmd := range []string{"update-grub", "grub2-mkconfig", "grub-mkconfig"} {
		if fs.LookPath(cmd) {
			return cmd
		}
	}
	return ""
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

func joinComma(ss []string) string {
	return joinKeys(ss, ",")
}
