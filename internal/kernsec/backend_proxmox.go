package kernsec

import (
	"fmt"
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
