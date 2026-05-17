package kernsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var hostProfileProbeRoot = ""

func hostProfilePath(path string) string {
	if hostProfileProbeRoot == "" || !strings.HasPrefix(path, "/") {
		return path
	}
	if path == hostProfileProbeRoot || strings.HasPrefix(path, hostProfileProbeRoot+string(os.PathSeparator)) {
		return path
	}
	return filepath.Join(hostProfileProbeRoot, strings.TrimPrefix(path, "/"))
}

func anyPathExists(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(hostProfilePath(p)); err == nil {
			return true
		}
	}
	return false
}

func anyGlobMatches(patterns ...string) bool {
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(hostProfilePath(pattern))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

// HostProfile captures the runtime characteristics of the current host
// that affect which rules should be applied. Auto-skipped rules render
// as `SKIP (host profile: <reason>)` in audit output. Operators
// override per-rule with `state = force` in kernsec.conf.
type HostProfile struct {
	IsKVMHost                bool   `json:"is_kvm_host"`                           // kvm_intel / kvm_amd loaded → KVM hypervisor host
	HasLibvirt               bool   `json:"has_libvirt"`                           // libvirtd socket / unit present → libvirt-managed KVM/QEMU host
	HasContainers            bool   `json:"has_containers"`                        // runc / containerd / lxc / podman process running → don't kill userns
	HasActiveUserNamespaces  bool   `json:"has_active_user_namespaces"`            // at least one process lives in a non-init user namespace right now (Chromium sandbox, bwrap, rootless podman, …) → don't kill userns
	ActiveUserNamespacesNote string `json:"active_user_namespaces_note,omitempty"` // human-readable summary surfaced as the SkipByHostProfile reason
	UsesBridge               bool   `json:"uses_bridge"`                           // in-kernel bridge in use (docker0, br-*, virbr*, vmbr*, manual brctl) → llc/llc2 are required
	HasIPsec                 bool   `json:"has_ipsec"`                             // `ip xfrm policy` non-empty → don't blacklist IPsec modules
	HasDKMS                  bool   `json:"has_dkms"`                              // out-of-tree module evidence detected
	HasBluetoothHardware     bool   `json:"has_bluetooth_hardware"`                // /sys/class/bluetooth non-empty → don't blacklist Bluetooth modules
	HasThunderbolt           bool   `json:"has_thunderbolt"`                       // /sys/bus/thunderbolt/devices non-empty → don't blacklist thunderbolt
	HasNFS                   bool   `json:"has_nfs"`                               // active NFS mounts → keep NFS untouched (already excluded by policy)
	IsEFIBoot                bool   `json:"is_efi_boot"`                           // /sys/firmware/efi present → EFI boot; efi= boot args are meaningful
	IsCPanel                 bool   `json:"is_cpanel"`                             // /usr/local/cpanel exists → cPanel/WHM host
	IsDirectAdmin            bool   `json:"is_directadmin"`                        // /usr/local/directadmin exists → DirectAdmin host
	HasCloudLinuxLVE         bool   `json:"has_cloudlinux_lve"`                    // /proc/lve or loaded lve/kmodlve → CloudLinux LVE host
	HasCageFS                bool   `json:"has_cagefs"`                            // /etc/cagefs or cagefsctl → CageFS host
	HasImunify360            bool   `json:"has_imunify360"`                        // Imunify360 service/package/path indicators
	HasKernelCare            bool   `json:"has_kernelcare"`                        // KernelCare live-patching indicators
	HasKsplice               bool   `json:"has_ksplice"`                           // Ksplice live-patching indicators
	HasLivePatchingModules   bool   `json:"has_live_patching_modules"`             // loaded live-patching modules
	IsProxmox                bool   `json:"is_proxmox"`                            // Proxmox paths or proxmox-boot-tool present
	HasZFS                   bool   `json:"has_zfs"`                               // loaded zfs or ZFS path indicators
	HasNVIDIA                bool   `json:"has_nvidia"`                            // loaded NVIDIA modules
	HasBackupWorkload        bool   `json:"has_backup_workload"`                   // common backup agents/services present
	HasMonitoringWorkload    bool   `json:"has_monitoring_workload"`               // common monitoring/crash-diagnostic agents present
	HasKdump                 bool   `json:"has_kdump"`                             // kdump configured (crashkernel= reserved OR kdump.service active) → kexec_load_disabled would break crash-dump capability
	HasHostingPanelWorkload  bool   `json:"has_hosting_panel_workload"`            // cPanel/DirectAdmin/CloudLinux/CageFS/Imunify360 aggregate
	Reason                   string `json:"reason,omitempty"`                      // freeform note used in --check output
}

// DetectHostProfile runs the cheap probes (~few hundred ms total).
// Pure: returns a value, no side effects on disk or kernel state.
func DetectHostProfile() HostProfile {
	p := HostProfile{
		IsKVMHost:              anyModuleLoaded("kvm_intel", "kvm_amd"),
		HasLibvirt:             detectLibvirt(),
		HasContainers:          defaultContainerProbe().detect(),
		UsesBridge:             detectInKernelBridge(),
		HasIPsec:               hasIPsecPolicies(),
		HasBluetoothHardware:   dirHasEntries("/sys/class/bluetooth"),
		HasThunderbolt:         dirHasEntries("/sys/bus/thunderbolt/devices"),
		HasNFS:                 procMountsHasFS("nfs", "nfs4"),
		IsEFIBoot:              isEFIBoot(),
		IsCPanel:               detectCPanel(),
		IsDirectAdmin:          detectDirectAdmin(),
		HasCloudLinuxLVE:       detectCloudLinuxLVE(),
		HasCageFS:              detectCageFS(),
		HasImunify360:          detectImunify360(),
		HasKernelCare:          detectKernelCare(),
		HasKsplice:             detectKsplice(),
		HasLivePatchingModules: detectLivePatchingModules(),
		IsProxmox:              detectProxmox(),
		HasZFS:                 detectZFS(),
		HasNVIDIA:              detectNVIDIA(),
		HasBackupWorkload:      detectBackupWorkload(),
		HasMonitoringWorkload:  detectMonitoringWorkload(),
		HasKdump:               detectKdump(),
	}
	p.HasHostingPanelWorkload = p.IsCPanel || p.IsDirectAdmin || p.HasCloudLinuxLVE || p.HasCageFS || p.HasImunify360
	p.HasDKMS = hasOutOfTreeModuleEvidence(p)
	p.HasActiveUserNamespaces, p.ActiveUserNamespacesNote = defaultUsernsProbe().detect()
	return p
}

// isEFIBoot reports whether the system booted via EFI. The kernel
// exposes /sys/firmware/efi only on EFI-booted systems; its absence
// means BIOS/legacy-boot and any efi= kernel parameter is a no-op.
func isEFIBoot() bool {
	_, err := os.Stat(hostProfilePath("/sys/firmware/efi"))
	return err == nil
}

// hasOutOfTreeModuleEvidence is the layered out-of-tree module probe.
// The previous narrow check was loaded-modules-only (zfs / nvidia); keep
// broader host inventory coverage for audit output:
//
//   - DKMS modules INSTALLED but not yet LOADED (e.g. zfs root not
//     yet imported, nvidia not yet pulled in by display manager,
//     virtualbox-modules pre-VM-launch).
//   - akmod (ELRepo on AlmaLinux/Rocky) kABI-tracking modules.
//   - Out-of-tree modules in /lib/modules/$(uname -r)/extra or
//     /lib/modules/$(uname -r)/updates.
//   - Live-kernel-patching modules (KernelCare / Ksplice).
//
// Any single layer hitting means the host has out-of-tree module evidence.
func hasOutOfTreeModuleEvidence(profile HostProfile) bool {
	if profile.HasZFS || profile.HasNVIDIA || profile.HasKernelCare || profile.HasKsplice || profile.HasLivePatchingModules || profile.HasCloudLinuxLVE {
		return true
	}
	// /var/lib/dkms holds (re)built DKMS modules. Non-empty means
	// the operator has installed at least one DKMS source package
	// regardless of whether it's currently loaded.
	if dirHasEntries("/var/lib/dkms") {
		return true
	}
	// akmods binary: hint that the host pulls in akmod-* packages
	// from ELRepo/RPMFusion. Absence of /usr/bin/akmods on a
	// minimal install means no akmod path; presence is enough to
	// gate.
	for _, p := range []string{"/usr/bin/akmods", "/usr/sbin/akmods"} {
		if _, err := os.Stat(hostProfilePath(p)); err == nil {
			return true
		}
	}
	// KernelCare (TuxCare) — module-based live kernel patching.
	// Common on cPanel/RHEL-family hosting. Detect via its CLI,
	// install dir, sysconfig file, or systemd unit.
	for _, p := range []string{
		"/usr/bin/kcarectl",
		"/usr/sbin/kcarectl",
		"/usr/lib/kernelcare",
		"/var/cache/kcare",
		"/etc/sysconfig/kcare",
		"/usr/lib/systemd/system/kcare.service",
		"/lib/systemd/system/kcare.service",
	} {
		if _, err := os.Stat(hostProfilePath(p)); err == nil {
			return true
		}
	}
	// Ksplice (Oracle) — same family, different vendor.
	for _, p := range []string{
		"/usr/sbin/uptrack-upgrade",
		"/var/lib/uptrack",
		"/etc/uptrack",
	} {
		if _, err := os.Stat(hostProfilePath(p)); err == nil {
			return true
		}
	}
	// /usr/src/*-dkms* — DKMS source trees per the dkms package
	// convention. Glob-cheap relative to the rest of the apply
	// path.
	if matches, _ := filepath.Glob(hostProfilePath("/usr/src/*-dkms*")); len(matches) > 0 {
		return true
	}
	// /lib/modules/$(uname -r)/{extra,updates} — out-of-tree
	// module install dirs. Non-empty means modules outside the
	// distro kernel tree exist on this host.
	for _, sub := range []string{"extra", "updates"} {
		matches, _ := filepath.Glob(hostProfilePath(filepath.Join("/lib/modules/*", sub)))
		for _, m := range matches {
			if dirHasEntries(m) {
				return true
			}
		}
	}
	return false
}

func detectCPanel() bool {
	return anyPathExists("/usr/local/cpanel")
}

func detectDirectAdmin() bool {
	return anyPathExists("/usr/local/directadmin")
}

func detectCloudLinuxLVE() bool {
	return anyPathExists("/proc/lve") || anyModuleLoaded("lve", "kmodlve")
}

func detectCageFS() bool {
	return anyPathExists("/etc/cagefs", "/usr/sbin/cagefsctl")
}

func detectImunify360() bool {
	return anyPathExists(
		"/usr/bin/imunify360-agent",
		"/usr/sbin/imunify360-agent",
		"/usr/lib/systemd/system/imunify360.service",
		"/lib/systemd/system/imunify360.service",
		"/etc/sysconfig/imunify360",
		"/etc/imunify360",
		"/var/imunify360",
		"/var/lib/imunify360",
		"/etc/yum.repos.d/imunify360.repo",
	) || anyGlobMatches(
		"/var/lib/dpkg/info/imunify360*.list",
		"/var/lib/rpm/*imunify360*",
	)
}

func detectKernelCare() bool {
	return anyPathExists(
		"/usr/bin/kcarectl",
		"/usr/sbin/kcarectl",
		"/usr/lib/kernelcare",
		"/var/cache/kcare",
		"/etc/sysconfig/kcare",
		"/usr/lib/systemd/system/kcare.service",
		"/lib/systemd/system/kcare.service",
	)
}

func detectKsplice() bool {
	return anyPathExists(
		"/usr/sbin/uptrack-upgrade",
		"/usr/bin/uptrack-upgrade",
		"/var/lib/uptrack",
		"/etc/uptrack",
		"/usr/lib/systemd/system/uptrack.service",
		"/lib/systemd/system/uptrack.service",
	)
}

func detectLivePatchingModules() bool {
	return anyModuleLoaded("kcare", "kpatch", "kgraft", "uptrack", "ksplice") || anyModuleLoadedWithPrefix("livepatch", "kpatch_", "ksplice_")
}

// detectKdump reports whether kdump (the kernel-crash-dump pipeline)
// is configured on this host. Used by KSEC-SCT-kspp.kexec-001
// (kernel.kexec_load_disabled=1) to auto-skip on hosts where the
// sysctl would break crash-dump preloading.
//
// Three signals — any one is sufficient evidence that the operator
// wants kdump usable:
//
//   - crashkernel= in /proc/cmdline. kdump requires a reserved memory
//     region for the crash kernel; the boot arg is the bootloader's
//     side of that contract. Present even on freshly-booted hosts
//     where the kdump userspace hasn't been started yet.
//   - /sys/kernel/kexec_crash_loaded reports 1. The kernel sets this
//     to 1 exactly when a crash kernel image has been loaded via
//     kexec_load(KEXEC_ON_CRASH); it's the definitive runtime signal
//     that kdump is armed right now. Catches operator-driven
//     `kexec -p` invocations that bypass the unit file entirely.
//   - kdump.service / kdump-tools.service installed AND not masked.
//     We don't check is-active because operators routinely keep the
//     service installed-but-stopped while debugging an unrelated
//     issue; the unit file's existence already signals intent. We DO
//     filter out masked units (symlink → /dev/null) because a masked
//     unit is the operator explicitly disabling kdump — gating the
//     sysctl on a disabled-but-package-installed kdump-tools would
//     be the wrong direction.
//
// Layered probe so we err on the side of caution — the cost of
// false-positive "kdump present" is one skipped sysctl with a clear
// audit line, vs. the cost of false-negative "no kdump" is silently
// breaking the operator's crash-dump capability.
func detectKdump() bool {
	// crashkernel= boot arg → kdump memory was reserved at boot.
	if cmdline, err := os.ReadFile(hostProfilePath("/proc/cmdline")); err == nil {
		for _, tok := range strings.Fields(string(cmdline)) {
			if tok == "crashkernel" || strings.HasPrefix(tok, "crashkernel=") {
				return true
			}
		}
	}
	// /sys/kernel/kexec_crash_loaded == "1" → a crash kernel is
	// loaded into the kexec slot right now. Definitive runtime
	// signal, independent of unit-file presence.
	if b, err := os.ReadFile(hostProfilePath("/sys/kernel/kexec_crash_loaded")); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return true
		}
	}
	// kdump service / unit file present (RHEL: kdump.service, Debian/
	// Ubuntu: kdump-tools.service). Masked units (symlink → /dev/null)
	// are an explicit operator disable and don't count.
	for _, p := range []string{
		"/usr/lib/systemd/system/kdump.service",
		"/lib/systemd/system/kdump.service",
		"/etc/systemd/system/kdump.service",
		"/usr/lib/systemd/system/kdump-tools.service",
		"/lib/systemd/system/kdump-tools.service",
		"/etc/systemd/system/kdump-tools.service",
	} {
		if unitFilePresentAndNotMasked(p) {
			return true
		}
	}
	return false
}

// unitFilePresentAndNotMasked reports whether a systemd unit-file path
// exists and is NOT masked. systemd masks a unit by replacing it with a
// symlink to /dev/null; the file is "present" by Stat but represents
// the operator's explicit intent to disable the service. Treating a
// masked kdump-tools.service as "kdump configured" would gate the
// kexec sysctl exactly where the operator told us not to.
func unitFilePresentAndNotMasked(unitPath string) bool {
	resolved := hostProfilePath(unitPath)
	info, err := os.Lstat(resolved)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, lerr := os.Readlink(resolved)
		if lerr == nil && (target == "/dev/null" || target == os.DevNull) {
			return false
		}
	}
	return true
}

// detectLibvirt reports whether libvirt is installed/running on this
// host. libvirt drives QEMU/KVM via its own virbr* bridges and depends
// on the in-kernel bridge module the same way Docker / Proxmox / LXC
// do. Layered probe so a stopped-but-installed libvirtd still gates
// (it'll start back up and try to bring up virbr0).
func detectLibvirt() bool {
	return anyPathExists(
		"/var/run/libvirt/libvirt-sock",
		"/run/libvirt/libvirt-sock",
		"/var/run/libvirt/libvirt-sock-ro",
		"/run/libvirt/libvirt-sock-ro",
		"/usr/sbin/libvirtd",
		"/usr/bin/virsh",
		"/etc/libvirt",
		"/usr/lib/systemd/system/libvirtd.service",
		"/lib/systemd/system/libvirtd.service",
	)
}

// detectInKernelBridge reports whether the host currently has any
// in-kernel bridge interface. This catches every userland that uses
// the `bridge` module: Docker (docker0, br-*), libvirt (virbr*),
// Proxmox (vmbr*), LXC/LXD, K8s CNIs, manual `brctl`/`ip link add type
// bridge`. The signal is a sysfs directory: /sys/class/net/<iface>/bridge
// exists iff <iface> is a kernel bridge.
//
// Blacklisting the bridge module's hard dependencies (llc, llc2) on
// such a host breaks bridging the next time the module reloads
// (kernel update, reboot, manual rmmod/modprobe).
func detectInKernelBridge() bool {
	entries, err := os.ReadDir(hostProfilePath("/sys/class/net"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(hostProfilePath("/sys/class/net"), e.Name(), "bridge")); err == nil {
			return true
		}
	}
	return false
}

func detectProxmox() bool {
	return anyPathExists(
		"/etc/pve",
		"/etc/kernel/proxmox-boot-uuids",
		"/usr/sbin/proxmox-boot-tool",
		"/usr/bin/proxmox-boot-tool",
		"/boot/efi/EFI/proxmox",
	)
}

func detectZFS() bool {
	return anyModuleLoaded("zfs") || anyPathExists("/sys/module/zfs", "/etc/zfs", "/usr/sbin/zpool", "/usr/bin/zpool")
}

func detectNVIDIA() bool {
	return anyModuleLoaded("nvidia", "nvidia_drm", "nvidia_modeset", "nvidia_uvm")
}

func detectBackupWorkload() bool {
	return anyPathExists(
		"/opt/veeam",
		"/usr/bin/veeam",
		"/usr/sbin/veeam",
		"/usr/lib/systemd/system/veeamservice.service",
		"/usr/lib/systemd/system/veeamtransport.service",
		"/usr/lib/systemd/system/acronis_mms.service",
		"/usr/lib/Acronis",
		"/opt/Acronis",
		"/opt/cpanel/jetbackup",
		"/usr/bin/jetbackup",
		"/usr/local/jetapps",
		"/usr/lib/systemd/system/bareos-fd.service",
		"/usr/lib/systemd/system/bacula-fd.service",
		"/usr/lib/systemd/system/urbackupclientbackend.service",
	) || anyGlobMatches(
		"/etc/systemd/system/*backup*.service",
		"/usr/lib/systemd/system/*backup*.service",
		"/lib/systemd/system/*backup*.service",
	)
}

func detectMonitoringWorkload() bool {
	return anyPathExists(
		"/usr/bin/node_exporter",
		"/usr/local/bin/node_exporter",
		"/usr/lib/systemd/system/node_exporter.service",
		"/usr/lib/systemd/system/zabbix-agent.service",
		"/usr/lib/systemd/system/zabbix-agent2.service",
		"/usr/sbin/zabbix_agentd",
		"/usr/bin/datadog-agent",
		"/etc/datadog-agent",
		"/opt/datadog-agent",
		"/opt/elastic-agent",
		"/usr/bin/telegraf",
		"/usr/lib/systemd/system/telegraf.service",
		"/usr/lib/systemd/system/abrt-ccpp.service",
		"/usr/lib/systemd/system/apport.service",
		"/usr/lib/systemd/system/systemd-coredump.socket",
	)
}

func (p HostProfile) hostingPanelReason() string {
	switch {
	case p.IsCPanel:
		return "cPanel/WHM detected (/usr/local/cpanel)"
	case p.IsDirectAdmin:
		return "DirectAdmin detected (/usr/local/directadmin)"
	case p.HasCloudLinuxLVE:
		return "CloudLinux LVE detected (/proc/lve or lve/kmodlve module)"
	case p.HasCageFS:
		return "CageFS detected (/etc/cagefs or cagefsctl)"
	case p.HasImunify360:
		return "Imunify360 detected (service/package/path indicator)"
	case p.HasHostingPanelWorkload:
		return "hosting panel workload detected"
	}
	return ""
}

// SkipReason returns a non-empty explanation if the rule with the given
// group should be auto-skipped on this host, or "" if it should apply.
//
// The set of skip rules here is intentionally conservative: we only
// skip when running the rule would clearly break something the operator
// is using. Operators can override per-rule with `state = force` in
// kernsec.conf.
func (p HostProfile) SkipReason(group string) string {
	switch group {
	case "modules.ipsec":
		if p.HasIPsec {
			return "host has active IPsec policies (ip xfrm policy non-empty)"
		}
	case "modules.net.virt":
		// vsock has two faces: guest-side (vmw_vsock_*_transport) and
		// host-side (vhost_vsock). On a KVM hypervisor the host module
		// is a legitimate channel for guest↔host comms, so we skip
		// the blacklist there. Bare-metal hosting boxes have no such
		// use case → default-blacklist remains.
		if p.IsKVMHost {
			return "KVM hypervisor — vhost_vsock may be in use for guest↔host comms"
		}
	case "modules.fs.container":
		// erofs is used by some container image formats (and Android
		// system images). Skip the blacklist if the host actually
		// runs containers; everywhere else it has no use case.
		if p.HasContainers {
			return "host runs containers — erofs may back container image layers"
		}
	case "modules.net.legacy.llc":
		// llc / llc2 are hard dependencies of the in-kernel `bridge`
		// module (bridge → stp → llc). Blacklisting them on any host
		// that uses bridges breaks the bridge driver the next time it
		// reloads: Docker (docker0), Podman, libvirt/KVM (virbr*),
		// Proxmox (vmbr*), LXC/LXD, K8s CNIs, OpenStack Neutron,
		// manual brctl. UsesBridge is the catch-all sysfs probe; the
		// other signals provide better skip-reason text and catch
		// installed-but-not-yet-running cases.
		if p.UsesBridge {
			return "in-kernel bridge interface present (/sys/class/net/*/bridge) — `bridge` module requires llc"
		}
		if p.HasContainers {
			return "container runtime active (Docker / Podman / LXC) — needs the `bridge` module which requires llc"
		}
		if p.IsKVMHost {
			return "KVM hypervisor — libvirt/QEMU bridges need the `bridge` module which requires llc"
		}
		if p.HasLibvirt {
			return "libvirt installed — virbr* bridges need the `bridge` module which requires llc"
		}
		if p.IsProxmox {
			return "Proxmox host — vmbr* bridges need the `bridge` module which requires llc"
		}
	case "modules.bus.bluetooth":
		// Blacklisting bluetooth/btusb/bnep/hci_uart on a host with
		// real Bluetooth hardware would break paired keyboards / mice
		// / audio. The previous single `modules.bus` group lumped
		// unrelated drivers (firewire, floppy) under the same skip;
		// the four-way split lets BT-only gating work.
		if p.HasBluetoothHardware {
			return "host has Bluetooth hardware (/sys/class/bluetooth non-empty)"
		}
	case "modules.bus.thunderbolt":
		// Thunderbolt blacklist on a host with TB hardware breaks
		// docks / external GPUs / TB networking. KVM hosts almost
		// never have it; bare-metal workstations / laptops do.
		if p.HasThunderbolt {
			return "host has Thunderbolt hardware (/sys/bus/thunderbolt/devices non-empty)"
		}
	case "tier2.namespace":
		// user.max_user_namespaces=0 / kernel.unprivileged_userns_clone=0
		// break Chromium sandbox, bwrap, rootless podman, cPanel jails,
		// CloudLinux/CageFS isolation, and hosting panel workloads. The
		// active-userns probe is the strongest signal — it catches
		// userns consumers the daemon-name probe misses (Chromium
		// renderer, bwrap, flatpak, sshd-sandboxed children, …).
		if p.HasActiveUserNamespaces {
			if p.ActiveUserNamespacesNote != "" {
				return "active user namespace workload — " + p.ActiveUserNamespacesNote
			}
			return "host has processes in non-init user namespaces"
		}
		if p.HasContainers {
			return "host has containers running (runc / containerd / lxc / podman)"
		}
		if reason := p.hostingPanelReason(); reason != "" {
			return "hosting panel namespace workload: " + reason
		}
	case "boot.dma":
		// efi=disable_early_pci_dma is an EFI-specific boot parameter;
		// on BIOS/legacy-boot systems the kernel ignores it entirely so
		// writing it to the cmdline would be a no-op but confuse operators.
		if !p.IsEFIBoot {
			return "non-EFI boot — efi=disable_early_pci_dma is a no-op on BIOS/legacy-boot systems"
		}
	case "sysctl.kernel.kexec":
		// kernel.kexec_load_disabled=1 locks out kexec_load(2) and
		// kexec_file_load(2) — closes a rootkit-persistence path
		// (load a replacement kernel post-boot) but breaks kdump,
		// which preloads a crash kernel via the same syscall.
		//
		// KernelCare / Ksplice live-patch through kernel modules,
		// not kexec, so they are NOT a conflict here — only kdump
		// gates the rule.
		if p.HasKdump {
			return "kdump configured (crashkernel= in cmdline OR kdump.service installed) — kexec_load_disabled=1 would prevent crash-kernel preloading"
		}
	case "sysctl.kernel.coredump":
		// kernel.core_pattern=|/bin/false disables coredumps globally.
		// kdump (kexec/vmcore) is independent of core_pattern, so it
		// does not gate this rule — the remaining checks cover the
		// userspace-coredump-consuming workloads (hosting panels,
		// backup/monitoring agents, multi-tenant diagnostics).
		if reason := p.hostingPanelReason(); reason != "" {
			return "hosting panel/vendor diagnostics may require coredumps: " + reason
		}
		if p.HasBackupWorkload {
			return "backup workload detected — preserve global coredump handling for vendor diagnostics"
		}
		if p.HasMonitoringWorkload {
			return "monitoring/crash-diagnostic workload detected — preserve global coredump handling"
		}
		// Multi-tenant diagnostics: on KVM hosts (libvirt-managed
		// QEMU writes guest cores via core_pattern) and container
		// hosts (in-container crashes can escape to the host pattern
		// for CI/image-build debugging), suppressing core_pattern
		// silently loses post-mortem evidence.
		if p.IsKVMHost || p.HasLibvirt {
			return "KVM / libvirt host — QEMU guest coredumps go through kernel.core_pattern"
		}
		if p.HasContainers {
			return "container runtime active — in-container coredumps may route through host kernel.core_pattern"
		}
	case "tier2.oops":
		// kernel.panic_on_oops=1 + kernel.panic=10 + oops=panic turn
		// any kernel oops/WARN into a reboot. On a multi-tenant host
		// (KVM hypervisor, libvirt, Docker / container engine) that
		// single oops can take down every guest / container at once.
		// Tier 2 still applies on single-tenant boxes where the
		// fail-closed-on-oops trade is defensible.
		if p.IsKVMHost {
			return "KVM hypervisor — a kernel oops here would reboot every guest at once"
		}
		if p.HasLibvirt {
			return "libvirt host — a kernel oops here would reboot every libvirt-managed guest at once"
		}
		if p.IsProxmox {
			return "Proxmox host — a kernel oops here would reboot every VM/CT at once"
		}
		if p.HasContainers {
			return "container runtime active — a kernel oops here would reboot every running container at once"
		}
	}
	return ""
}

// anyModuleLoaded returns true if any of the named modules is in
// /proc/modules.
func anyModuleLoaded(names ...string) bool {
	mods := readProcModules()
	if len(mods) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	for _, m := range mods {
		if _, ok := want[m]; ok {
			return true
		}
	}
	return false
}

func anyModuleLoadedWithPrefix(prefixes ...string) bool {
	for _, m := range readProcModules() {
		for _, prefix := range prefixes {
			if strings.HasPrefix(m, prefix) {
				return true
			}
		}
	}
	return false
}

func readProcModules() []string {
	b, err := os.ReadFile(hostProfilePath("/proc/modules"))
	if err != nil {
		return nil
	}
	var mods []string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			mods = append(mods, fields[0])
		}
	}
	return mods
}

// containerProbe holds the file paths consulted to detect whether the
// host is currently running containers — meaning Tier 2 namespace-kill
// rules would break workloads. Layered (any layer hits → host is a
// container host) so socket-activated daemons and short-lived shims
// both register.
//
// False-positive bias is intentional: missing detection silently
// breaks rootless containers / k8s nodes (no rollback path until
// reboot once the sysctl is loaded); over-detection skips Tier 2
// namespace kill on hosts that don't run containers (operator can
// re-enable per-rule with `state = force` in kernsec.conf).
type containerProbe struct {
	procDir   string   // /proc — read /proc/<pid>/comm for daemon names
	sockets   []string // daemon control sockets (docker, crio, containerd, podman)
	nspawnDir string   // /run/systemd/nspawn — non-empty iff machines registered
}

// containerDaemonNames is the exact-match set: long-lived daemons (and
// `runc` itself, which is short-lived but exact-named) whose presence
// in /proc means the host is actively running containers.
var containerDaemonNames = []string{
	"containerd",
	"dockerd",
	"crio",
	"conmon",
	"lxd",
	"lxc-start",
	"podman",
	"kubelet",
	"systemd-nspawn",
	"kata-runtime",
	"runsc",
	"runc",
}

// containerShimPrefixes match version-suffixed shim processes:
// `containerd-shim-runc-v2`, `containerd-shim-runhcs-v1`, etc.
// Prefixes only — exact names like `runc` go in containerDaemonNames
// to avoid false positives on short prefix collisions.
var containerShimPrefixes = []string{
	"containerd-shim",
}

// defaultContainerProbe returns the containerProbe pointed at the real
// host paths. Constructor (not a global var) so tests can build their
// own with a temp-dir-backed procDir / sockets / nspawnDir without
// mutating package state.
func defaultContainerProbe() containerProbe {
	return containerProbe{
		procDir: hostProfilePath("/proc"),
		sockets: []string{
			hostProfilePath("/var/run/docker.sock"),
			hostProfilePath("/run/docker.sock"),
			hostProfilePath("/var/run/crio/crio.sock"),
			hostProfilePath("/run/containerd/containerd.sock"),
			hostProfilePath("/run/podman/podman.sock"),
		},
		nspawnDir: hostProfilePath("/run/systemd/nspawn"),
	}
}

// detect runs the layered probe.
func (p containerProbe) detect() bool {
	if p.anyProcessMatches() {
		return true
	}
	for _, sock := range p.sockets {
		if _, err := os.Stat(sock); err == nil {
			return true
		}
	}
	if dirHasEntries(p.nspawnDir) {
		return true
	}
	return false
}

// anyProcessMatches walks p.procDir/<pid>/comm and reports whether any
// running process matches a container daemon (exact match) or shim
// (prefix match). Skips read errors silently — an unreadable /proc
// entry is the kernel cleaning up a dead pid, not a probe failure.
func (p containerProbe) anyProcessMatches() bool {
	entries, err := os.ReadDir(p.procDir)
	if err != nil {
		return false
	}
	daemons := make(map[string]struct{}, len(containerDaemonNames))
	for _, n := range containerDaemonNames {
		daemons[n] = struct{}{}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconvAtoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.procDir, e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(b))
		if _, ok := daemons[comm]; ok {
			return true
		}
		for _, prefix := range containerShimPrefixes {
			if strings.HasPrefix(comm, prefix) {
				return true
			}
		}
	}
	return false
}

// strconvAtoi is a small avoid-import for the /proc PID filter; many
// /proc entries are non-numeric (cmdline, sys, etc.) and we just want
// to skip them.
func strconvAtoi(s string) (int, error) {
	if s == "" {
		return 0, errNotInt
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errNotInt
		}
	}
	return 0, nil // we only care that it's all-digit, not the value
}

var errNotInt = &profileProbeErr{"not int"}

type profileProbeErr struct{ s string }

func (e *profileProbeErr) Error() string { return e.s }

// hasIPsecPolicies returns true if /proc/net/xfrm_policy or
// /proc/net/pfkey indicate an active IPsec / xfrm policy. Cheap and
// doesn't shell out.
func hasIPsecPolicies() bool {
	for _, p := range []string{"/proc/net/xfrm_policy", "/proc/net/pfkey"} {
		if b, err := os.ReadFile(hostProfilePath(p)); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return true
		}
	}
	return false
}

// dirHasEntries returns true if dir exists and contains at least one
// non-"." / ".." entry.
func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(hostProfilePath(dir))
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// usernsProbe walks /proc/<pid>/ns/user symlinks and reports whether any
// running process lives in a user namespace other than init's. This is
// the cheapest possible "is something actually using namespaces right
// now" signal — same flavour as `lsns -t user` and the kernel-bridge
// probe from PR 891. It catches userns consumers the container-daemon
// probe misses on its own: Chromium sandbox, bwrap, flatpak, rootless
// podman, sshd-sandboxed children, CageFS jails.
//
// Inode comparison is via symlink target ("user:[4026531837]") rather
// than stat — readlink works without CAP_SYS_PTRACE for symlinks the
// caller can see, and the package-test harness can build a fake /proc
// out of plain symlinks.
type usernsProbe struct {
	procDir string
	initPID string
}

func defaultUsernsProbe() usernsProbe {
	return usernsProbe{
		procDir: hostProfilePath("/proc"),
		initPID: "1",
	}
}

// detect returns (hasNonInit, summary). summary is empty when no
// non-init userns are observed; otherwise it carries a short
// human-readable note (count + a few comm names) suitable for the
// SkipByHostProfile reason rendered in the audit row.
//
// Probe failure (unreadable /proc, missing /proc/1/ns/user — common in
// fakeroot test harnesses without symlinks) is treated as "no signal",
// not as "active": false-negative bias matches the rest of the
// host-profile probe set, and the resolver's other signals
// (HasContainers, hosting-panel) still gate the rule when this one
// can't see anything.
func (p usernsProbe) detect() (bool, string) {
	initTarget, err := os.Readlink(filepath.Join(p.procDir, p.initPID, "ns", "user"))
	if err != nil {
		return false, ""
	}
	entries, err := os.ReadDir(p.procDir)
	if err != nil {
		return false, ""
	}
	seenNS := map[string]struct{}{}
	var sampleNames []string
	totalProcs := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconvAtoi(e.Name()); err != nil {
			continue
		}
		if e.Name() == p.initPID {
			continue
		}
		tgt, err := os.Readlink(filepath.Join(p.procDir, e.Name(), "ns", "user"))
		if err != nil {
			continue
		}
		if tgt == initTarget {
			continue
		}
		totalProcs++
		if _, ok := seenNS[tgt]; ok {
			continue
		}
		seenNS[tgt] = struct{}{}
		if len(sampleNames) < 3 {
			name := e.Name()
			if b, err := os.ReadFile(filepath.Join(p.procDir, e.Name(), "comm")); err == nil {
				if c := strings.TrimSpace(string(b)); c != "" {
					name = c
				}
			}
			sampleNames = append(sampleNames, name)
		}
	}
	if len(seenNS) == 0 {
		return false, ""
	}
	suffix := ""
	if len(seenNS) > len(sampleNames) {
		suffix = ", …"
	}
	return true, fmt.Sprintf("%d non-init user namespace(s), %d process(es) (e.g. %s%s)",
		len(seenNS), totalProcs, strings.Join(sampleNames, ", "), suffix)
}

// procMountsHasFS returns true if /proc/mounts lists any mount whose
// fs type matches one of the names.
func procMountsHasFS(types ...string) bool {
	b, err := os.ReadFile(hostProfilePath("/proc/mounts"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		fstype := fields[2]
		for _, t := range types {
			if fstype == t {
				return true
			}
		}
	}
	return false
}
