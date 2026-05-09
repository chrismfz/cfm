package kernsec

import "strings"

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
