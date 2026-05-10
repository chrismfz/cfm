package kernsec

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ProxmoxBackend implements BootBackend for Proxmox systemd-boot /
// proxmox-boot-tool installs. The next-boot cmdline lives in
// /etc/kernel/cmdline as a single line.
type ProxmoxBackend struct {
	FS FS
}

func (p *ProxmoxBackend) Label() string {
	return "Proxmox boot tool / systemd-boot"
}

func (p *ProxmoxBackend) NextBootCmdline() (string, error) {
	b, err := p.FS.ReadFile(PathPVECmdline)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// WriteCmdline rewrites /etc/kernel/cmdline with the managed-keys
// workflow. Mirrors kspp.sh apply_boot_args_proxmox.
func (p *ProxmoxBackend) WriteCmdline(args []BootArg) error {
	current, err := p.NextBootCmdline()
	if err != nil {
		return fmt.Errorf("read %s: %w", PathPVECmdline, err)
	}
	// Best-effort pre-apply managed-args snapshot for rollback. Legacy
	// full-file backups are still written below for manual recovery.
	_ = writeManagedBootArgSnapshot(ProxmoxManagedBackupPath, ParseCmdline(current))

	tokens := rebuildManagedCmdline(ParseCmdline(current), args)
	newLine := strings.Join(tokens, " ")

	if err := BackupOnce(PathPVECmdline, PathPVECmdline+BackupSuffix); err != nil {
		return err
	}
	return AtomicWriteFile(PathPVECmdline, []byte(newLine+"\n"), 0o644)
}

// Refresh runs proxmox-boot-tool refresh so the new cmdline is picked
// up by the next boot.
func (p *ProxmoxBackend) Refresh() error {
	out, err := p.FS.RunCapture("proxmox-boot-tool", "refresh")
	if err != nil {
		return fmt.Errorf("proxmox-boot-tool refresh: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// restoreProxmoxCmdlineAfterRefreshFailure returns /etc/kernel/cmdline to a
// safe retry state after WriteCmdline succeeded but proxmox-boot-tool refresh
// failed. If the current file is still exactly kernsec's expected post-apply
// rewrite, the pre-apply full-file backup is restored byte-for-byte. If the
// current file has picked up operator/unmanaged edits, preserve those current
// unmanaged tokens and roll back only kernsec-managed keys to their pre-apply
// values from the backup.
func restoreProxmoxCmdlineAfterRefreshFailure() error {
	bak := PathPVECmdline + BackupSuffix
	if _, err := os.Stat(bak); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", bak, err)
	}

	legacy, err := os.ReadFile(bak)
	if err != nil {
		return fmt.Errorf("read %s: %w", bak, err)
	}
	current, err := os.ReadFile(PathPVECmdline)
	if err != nil {
		return fmt.Errorf("read %s: %w", PathPVECmdline, err)
	}

	outContent := legacy
	if string(current) != expectedLegacyCmdlinePostApply(string(legacy), string(current)) {
		tokens := rebuildManagedTokens(ParseCmdline(string(current)), KeepManagedArgs(ParseCmdline(string(legacy))))
		outContent = []byte(strings.Join(tokens, " ") + "\n")
	}
	if err := AtomicWriteFile(PathPVECmdline, outContent, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", PathPVECmdline, err)
	}
	return nil
}
