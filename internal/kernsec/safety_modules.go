package kernsec

import (
	"fmt"
	"strings"
)

// dangerousModulePatterns is the deny-list of module-name patterns
// that MUST NOT be in any kernsec blacklist rule. Pattern matching
// is case-sensitive prefix or exact-name (no globbing) — a pattern
// of `nvme` matches `nvme`, `nvme_core`, `nvme_tcp` etc.
//
// Why a deny-list at all: kernsec's current Tier 1 + Tier 2 module
// rule data (modules.go) is curated to avoid storage / network /
// console / filesystem drivers. But future PRs adding modules
// must not break this invariant. dracut's host-only mode (default
// on RHEL/Alma/Rocky/CentOS) embeds /etc/modprobe.d/*.conf into
// the initramfs at the next kernel package update. A blacklist on
// the running root filesystem driver therefore becomes a brick at
// the NEXT reboot after a kernel upgrade — not the immediate
// reboot — which is the worst possible failure mode (remote
// install + automatic kernel updates + delayed brick).
//
// The guard runs at applyCore time before any writes happen and at
// rule-registration time via TestNoDangerousModulesInRegistry.
// Either path failing means an operator never ships a brick.
//
// Patterns chosen to cover the canonical drivers a typical Linux
// host needs to BOOT (mount /, bring up the console enough to see
// grub or login prompt, optionally bring up the boot-time network
// for iSCSI / NFS roots):
//
//   - storage:     nvme*, ahci, sd_mod, sr_mod, scsi_mod, libata,
//                  *_storage, mptsas, megaraid*, hpsa, mpt3sas,
//                  virtio_blk, virtio_scsi, dm_*, md_mod, raid*,
//                  xhci_*, ehci_*, uhci_*, ohci_*
//   - filesystem:  xfs, ext2, ext3, ext4, btrfs, vfat, fat,
//                  iso9660, squashfs, overlay, fuse
//   - network:     e1000*, igb, ixgbe, vmxnet3, virtio_net,
//                  bnx2*, tg3, r8169, mlx4_*, mlx5_*, i40e, ice
//   - console:     vga*, drm, drm_kms_helper, i915, nouveau,
//                  amdgpu, radeon, fbcon, framebuffer
//
// Patterns are intentionally aggressive on the side of safety:
// false positives (legitimate kernsec-suitable rules being
// rejected) are easy to fix by editing the deny-list; false
// negatives (a brick) cannot be fixed remotely.
var dangerousModulePatterns = []string{
	// Storage controllers + USB controllers (USB carries some boot media)
	"nvme", "ahci", "sd_mod", "sr_mod", "scsi_mod", "libata",
	"mptsas", "megaraid", "hpsa", "mpt3sas",
	"virtio_blk", "virtio_scsi",
	"dm_", "md_mod", "raid",
	"xhci_", "ehci_", "uhci_", "ohci_",
	"usb_storage", "usb-storage",
	// Filesystems
	"xfs", "ext2", "ext3", "ext4", "btrfs",
	"vfat", "fat", "iso9660", "squashfs",
	"overlay", "fuse",
	// Boot-time networks
	"e1000", "igb", "ixgbe", "vmxnet3", "virtio_net",
	"bnx2", "tg3", "r8169", "mlx4_", "mlx5_", "i40e", "ice",
	// Console / video
	"vga", "drm", "drm_kms_helper", "i915", "nouveau",
	"amdgpu", "radeon", "fbcon", "framebuffer",
}

// IsDangerousModule reports whether name matches any
// dangerousModulePatterns prefix. Used by both pre-apply guard
// (applyCore refuses to write) and a registry-data sanity test
// (TestNoDangerousModulesInRegistry) so the guarantee is enforced
// at compile-time-test AND at apply-time.
func IsDangerousModule(name string) bool {
	for _, pat := range dangerousModulePatterns {
		if name == pat || strings.HasPrefix(name, pat) {
			return true
		}
	}
	return false
}

// CheckSafeModuleRules returns a non-nil error naming every rule
// whose module Name matches a dangerous pattern. Empty rule set →
// nil. Multiple offenders are all named (operator gets the full
// picture in one error rather than hunting one at a time).
func CheckSafeModuleRules(rules []ModuleRule) error {
	var bad []string
	for _, r := range rules {
		if IsDangerousModule(r.Name) {
			bad = append(bad, fmt.Sprintf("  %s (rule %s) — matches dangerous pattern; would risk bricking boot", r.Name, r.ID))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf(
		"kernsec apply: refusing to blacklist storage/filesystem/network/console drivers — operator-risk to next-boot:\n%s\n"+
			"if you really mean it, edit internal/kernsec/safety_modules.go::dangerousModulePatterns and rebuild",
		strings.Join(bad, "\n"))
}
