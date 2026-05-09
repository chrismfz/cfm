package kernsec

import "strings"

// GRUBBackend implements BootBackend for legacy GRUB installs
// (Debian/Ubuntu and RHEL non-BLS). Reads GRUB_CMDLINE_LINUX from
// /etc/default/grub.
type GRUBBackend struct {
	FS FS
}

func (g *GRUBBackend) Label() string {
	return "Legacy GRUB"
}

func (g *GRUBBackend) NextBootCmdline() (string, error) {
	if !g.FS.Exists(PathDefaultGrub) {
		return "", nil
	}
	b, err := g.FS.ReadFile(PathDefaultGrub)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "GRUB_CMDLINE_LINUX=") {
			continue
		}
		val := strings.TrimPrefix(t, "GRUB_CMDLINE_LINUX=")
		val = strings.Trim(val, `"`)
		return val, nil
	}
	return "", nil
}
