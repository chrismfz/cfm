package kernsec

import "strings"

// Paths used by backend detection. Variables (not constants) so tests
// can override them if needed; production code uses the defaults.
var (
	PathPVECmdline   = "/etc/kernel/cmdline"
	PathProcCmdline  = "/proc/cmdline"
	PathBLSEntries   = "/boot/loader/entries"
	PathDefaultGrub  = "/etc/default/grub"
	PathGrub2Cfg     = "/boot/grub2/grub.cfg"
	PathGrubCfg      = "/boot/grub/grub.cfg"
	PathEFIGrubGlob  = "/boot/efi/EFI"
)

// DetectBackend selects a BootBackend based on the host's filesystem
// and installed tools. Order: Proxmox boot tool, BLS / grubby, then
// legacy GRUB as fallback. Mirrors kspp.sh boot_backend.
func DetectBackend(fs FS) BootBackend {
	if isProxmoxBootTool(fs) {
		return &ProxmoxBackend{FS: fs}
	}
	if isBLS(fs) {
		return &BLSBackend{FS: fs}
	}
	return &GRUBBackend{FS: fs}
}

// isProxmoxBootTool mirrors kspp.sh is_proxmox_boot_tool.
//
// Requires proxmox-boot-tool in $PATH and /etc/kernel/cmdline present,
// plus one of: current /proc/cmdline references the Proxmox EFI initrd,
// or proxmox-boot-tool status mentions configured / esp / proxmox /
// systemd-boot.
func isProxmoxBootTool(fs FS) bool {
	if !fs.LookPath("proxmox-boot-tool") {
		return false
	}
	if !fs.Exists(PathPVECmdline) {
		return false
	}

	if b, err := fs.ReadFile(PathProcCmdline); err == nil {
		line := string(b)
		// kspp.sh: grep -qE '(^| )initrd=\\EFI\\proxmox\\'
		if strings.Contains(line, `initrd=\EFI\proxmox\`) ||
			strings.Contains(line, ` initrd=\EFI\proxmox\`) {
			return true
		}
	}

	if out, err := fs.RunCapture("proxmox-boot-tool", "status"); err == nil {
		low := strings.ToLower(out)
		for _, needle := range []string{"configured", "esp", "proxmox", "systemd-boot"} {
			if strings.Contains(low, needle) {
				return true
			}
		}
	}
	return false
}

// isBLS mirrors kspp.sh is_bls.
//
// Requires /boot/loader/entries to exist as a directory and grubby in
// $PATH. If GRUB_ENABLE_BLSCFG is explicitly false, BLS is rejected
// even if entries exist. Otherwise active GRUB config must reference
// blscfg, or GRUB_ENABLE_BLSCFG must be explicitly true.
func isBLS(fs FS) bool {
	if !fs.IsDir(PathBLSEntries) {
		return false
	}
	if !fs.LookPath("grubby") {
		return false
	}

	// Explicit disable wins.
	if fs.Exists(PathDefaultGrub) {
		if b, err := fs.ReadFile(PathDefaultGrub); err == nil {
			if grubVarMatches(string(b), "GRUB_ENABLE_BLSCFG", "false") {
				return false
			}
		}
	}

	// Strong evidence: blscfg referenced in active GRUB config.
	for _, p := range []string{PathGrub2Cfg, PathGrubCfg} {
		if !fs.Exists(p) {
			continue
		}
		if b, err := fs.ReadFile(p); err == nil {
			if strings.Contains(string(b), "blscfg") {
				return true
			}
		}
	}

	// Fallback: explicitly enabled.
	if fs.Exists(PathDefaultGrub) {
		if b, err := fs.ReadFile(PathDefaultGrub); err == nil {
			if grubVarMatches(string(b), "GRUB_ENABLE_BLSCFG", "true") {
				return true
			}
		}
	}
	return false
}

// grubVarMatches reports whether a /etc/default/grub style file contains
// `VAR=want` or `VAR="want"` on its own line. Mirrors kspp.sh's
// `grep -qE '^GRUB_ENABLE_BLSCFG="?true"?'` checks.
func grubVarMatches(content, name, want string) bool {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, name+"=") {
			continue
		}
		val := strings.TrimPrefix(t, name+"=")
		val = strings.Trim(val, `"`)
		if val == want {
			return true
		}
	}
	return false
}
