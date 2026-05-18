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
	HasMCTPInBand            bool   `json:"has_mctp_in_band"`                      // in-band MCTP endpoint registered (OpenBMC, NVMe-MI) → don't blacklist mctp modules
	HasSCTPWorkload          bool   `json:"has_sctp_workload"`                     // sctp module loaded / /proc/net/sctp populated / sctp_darn / Nagios check_sctp / *sctp*.service → don't blacklist sctp modules
	HasTIPCWorkload          bool   `json:"has_tipc_workload"`                     // tipc loaded / /proc/net/tipc / tipc-config / *tipc*.service → don't blacklist tipc (Pacemaker/Corosync HA, Erlang OTP)
	HasAFS                   bool   `json:"has_afs"`                               // rxrpc or kafs loaded / /proc/net/rxrpc / /afs mount / /etc/openafs → don't blacklist rxrpc (AFS clients)
	HasL2TPWorkload          bool   `json:"has_l2tp_workload"`                     // xl2tpd / kl2tpd / accel-pptp / /proc/net/l2tp* → don't blacklist l2tp_* family
	HasPPTPWorkload          bool   `json:"has_pptp_workload"`                     // pptpd / /etc/pptpd.conf / /proc/net/pptp / accel-pptp → don't blacklist pptp
	HasRDSWorkload           bool   `json:"has_rds_workload"`                      // rds loaded / /proc/net/rds* / Oracle DB indicators → don't blacklist rds (Oracle RAC interconnect)
	HasMountedDeadFS         bool   `json:"has_mounted_dead_fs"`                   // any modules.fs.unused FS actually mounted (/proc/mounts) or in /etc/fstab → don't blacklist the group
	MountedDeadFSDetail      string `json:"mounted_dead_fs_detail,omitempty"`      // which FS triggered HasMountedDeadFS — surfaced in the skip reason
	HasFirewireHardware      bool   `json:"has_firewire_hardware"`                 // /sys/bus/firewire/devices non-empty → don't blacklist firewire-* modules
	HasKSMBDServer           bool   `json:"has_ksmbd_server"`                      // kernel SMB server in use: /sys/class/ksmbd, ksmbd.mountd process, ksmbd-tools installed → don't blacklist ksmbd
	HasDevTools              bool   `json:"has_dev_tools"`                         // gdb / strace / py-spy / bpftrace / bcc-tools installed → soft advisory for yama.ptrace_scope and unprivileged_bpf_disabled
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
		HasMCTPInBand:          detectMCTPInBand(),
		HasSCTPWorkload:        detectSCTPWorkload(),
		HasTIPCWorkload:        detectTIPCWorkload(),
		HasAFS:                 detectAFS(),
		HasL2TPWorkload:        detectL2TPWorkload(),
		HasPPTPWorkload:        detectPPTPWorkload(),
		HasRDSWorkload:         detectRDSWorkload(),
		HasFirewireHardware:    dirHasEntries("/sys/bus/firewire/devices"),
		HasKSMBDServer:         detectKSMBDServer(),
		HasDevTools:            detectDevTools(),
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
	p.HasMountedDeadFS, p.MountedDeadFSDetail = detectMountedDeadFS()
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
//     kexec_load(2) / kexec_file_load(2) with the KEXEC_ON_CRASH
//     flag; it's the definitive runtime signal that kdump is armed
//     right now. Catches operator-driven `kexec -p` invocations that
//     bypass the unit file entirely.
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
		if lerr == nil && target == "/dev/null" {
			return false
		}
	}
	return true
}

// detectSCTPWorkload reports whether the host has any evidence of SCTP
// being used right now. The kernel sctp module is essentially only
// needed by telecom signalling stacks (SS7 / Diameter / M3UA — Asterisk
// chan_ss7, Kamailio sctp, FreeSWITCH SIGTRAN, freeDiameter, MME / HSS),
// by Kubernetes Services explicitly using protocol: SCTP, and by
// lksctp-tools-based health probes. Standard hosting (Apache / Nginx /
// Exim / Postfix / Dovecot / BIND / mail filters / cPanel / DA /
// Virtualmin / Imunify360) does not.
//
// Notably this does NOT include WebRTC data channels: usrsctp runs in
// userspace inside Chromium / Firefox / libwebrtc / pion / Jitsi /
// Janus / mediasoup and never touches the kernel module.
//
// Six layered signals — any one is sufficient to skip the modules.sctp
// blacklist on this host:
//
//   - sctp loaded in /proc/modules.
//   - /proc/net/sctp present (sctp procfs is created when the module
//     loads; presence alone signals the kernel is in the SCTP business).
//   - /sys/module/sctp present (belt-and-suspenders).
//   - sctp.service / sctp_darn.service / sctp_darn binary present.
//   - Nagios check_sctp plugin present (RHEL / Debian paths).
//   - Any *sctp*.service unit file installed.
//
// Bias toward false-positive: incorrectly skipping the blacklist on a
// hosting box is a no-op (the module simply stays loadable); incorrectly
// applying it on a Diameter / SS7 / K8s-SCTP host would break signalling.
func detectSCTPWorkload() bool {
	if anyModuleLoaded("sctp") || anyPathExists("/proc/net/sctp", "/sys/module/sctp") {
		return true
	}
	if anyPathExists(
		"/usr/lib/systemd/system/sctp.service",
		"/usr/lib/systemd/system/sctp_darn.service",
		"/lib/systemd/system/sctp.service",
		"/lib/systemd/system/sctp_darn.service",
		"/usr/bin/sctp_darn",
		"/usr/bin/check_sctp",
		"/usr/lib/nagios/plugins/check_sctp",
		"/usr/lib64/nagios/plugins/check_sctp",
	) {
		return true
	}
	return anyGlobMatches(
		"/etc/systemd/system/*sctp*.service",
		"/usr/lib/systemd/system/*sctp*.service",
		"/lib/systemd/system/*sctp*.service",
	)
}

// detectDevTools reports whether common developer / observability
// binaries are installed. Used only by the advisory system (not by
// SkipReason): rules like yama.ptrace_scope=2 and
// unprivileged_bpf_disabled=2 still apply, but the audit/preview
// surfaces a soft note when these tools are present so the operator
// knows their interactive workflows (gdb --attach, strace -p,
// bpftrace -p) will need sudo afterward.
func detectDevTools() bool {
	// /usr/bin/perf is intentionally NOT in this list: it ships in
	// linux-tools-* / perf packages that are installed by default on
	// many cloud-vendor base images (AWS Linux 2, Ubuntu cloud-init,
	// OpenShift workers). Including it would fire the advisory on a
	// large fraction of fleets and defeat the "no noise on clean
	// fleets" goal. The remaining signals are interactive debuggers
	// the operator deliberately installed.
	return anyPathExists(
		"/usr/bin/gdb",
		"/usr/bin/strace",
		"/usr/bin/ltrace",
		"/usr/bin/py-spy",
		"/usr/local/bin/py-spy",
		"/usr/bin/bpftrace",
		"/usr/sbin/bpftrace",
		"/usr/share/bcc/tools",
		"/usr/share/bcc-tools",
	)
}

// detectKSMBDServer reports whether the host is deliberately running
// the kernel SMB server (ksmbd). cPanel / DirectAdmin / Virtualmin /
// stock hosting boxes never use it — but a handful of operators run
// ksmbd as a faster Samba replacement for internal file shares, and
// blacklisting the module there would silently break those shares the
// next reboot. Layered probe: the loaded-module check fires while
// shares are active; the binary / package / unit-file checks catch the
// installed-but-not-yet-started window.
func detectKSMBDServer() bool {
	if anyModuleLoaded("ksmbd") {
		return true
	}
	if dirHasEntries("/sys/class/ksmbd") {
		return true
	}
	return anyPathExists(
		"/usr/sbin/ksmbd.mountd",
		"/usr/sbin/ksmbd.addshare",
		"/usr/sbin/ksmbd.adduser",
		"/usr/sbin/ksmbd.control",
		"/usr/bin/ksmbd.mountd",
		"/etc/ksmbd",
		"/usr/lib/systemd/system/ksmbd.service",
		"/lib/systemd/system/ksmbd.service",
	)
}

// detectTIPCWorkload reports whether the host has any evidence of TIPC
// (Transparent Inter-Process Communication) being used. TIPC is rare on
// hosting but real on Pacemaker / Corosync HA clusters, Erlang/OTP
// distributed setups, and a handful of OpenStack HA configurations.
func detectTIPCWorkload() bool {
	if anyModuleLoaded("tipc") || anyPathExists("/proc/net/tipc", "/sys/module/tipc") {
		return true
	}
	if anyPathExists(
		"/usr/bin/tipc",
		"/usr/sbin/tipc",
		"/usr/bin/tipc-config",
		"/usr/sbin/tipc-config",
		"/usr/lib/systemd/system/tipc.service",
		"/lib/systemd/system/tipc.service",
	) {
		return true
	}
	return anyGlobMatches(
		"/etc/systemd/system/*tipc*.service",
		"/usr/lib/systemd/system/*tipc*.service",
		"/lib/systemd/system/*tipc*.service",
	)
}

// detectAFS reports whether the host runs an AFS client. rxrpc is the
// kernel-side RPC stack AFS rides on; kafs is the in-tree AFS client,
// openafs is the third-party one. Either client mounting /afs is the
// strongest signal; the rest cover installed-but-not-yet-mounted cases.
func detectAFS() bool {
	if anyModuleLoaded("rxrpc", "kafs", "openafs") || anyPathExists("/proc/net/rxrpc", "/sys/module/rxrpc") {
		return true
	}
	if procMountsHasFS("afs") {
		return true
	}
	// /afs is intentionally NOT in this list: the Debian openafs-client
	// package creates an empty /afs stub directory at install time, so
	// mere existence is a false-positive signal. procMountsHasFS("afs")
	// above already catches the only case that matters — a real AFS
	// cell mounted there.
	return anyPathExists(
		"/etc/openafs",
		"/usr/vice/etc",
		"/usr/afs",
		"/usr/bin/fs",
		"/usr/bin/pts",
		"/usr/bin/vos",
		"/usr/lib/systemd/system/openafs-client.service",
		"/lib/systemd/system/openafs-client.service",
	)
}

// detectL2TPWorkload reports whether the host terminates L2TP tunnels.
// Covers both userspace daemons (xl2tpd, kl2tpd, accel-ppp's accel-pppd)
// and the kernel-side L2TPv3 data path.
func detectL2TPWorkload() bool {
	if anyModuleLoadedWithPrefix("l2tp_") || anyPathExists("/proc/net/l2tp", "/sys/module/l2tp_core") {
		return true
	}
	if anyGlobMatches("/proc/net/l2tp*") {
		return true
	}
	return anyPathExists(
		"/usr/sbin/xl2tpd",
		"/usr/bin/xl2tpd",
		"/etc/xl2tpd",
		"/usr/sbin/kl2tpd",
		"/usr/sbin/accel-pppd",
		"/etc/accel-ppp.conf",
		"/usr/lib/systemd/system/xl2tpd.service",
		"/lib/systemd/system/xl2tpd.service",
		"/usr/lib/systemd/system/accel-ppp.service",
		"/lib/systemd/system/accel-ppp.service",
	)
}

// detectPPTPWorkload reports whether the host terminates PPTP tunnels.
// Yes, this still happens — Mikrotik fleets, legacy site-to-site, ISP
// helpdesks. Either kernel module loaded or a pptpd / accel-ppp install
// counts.
func detectPPTPWorkload() bool {
	if anyModuleLoaded("pptp", "pptp_gre") || anyPathExists("/proc/net/pptp", "/sys/module/pptp") {
		return true
	}
	return anyPathExists(
		"/usr/sbin/pptpd",
		"/usr/sbin/pptp",
		"/usr/bin/pptp",
		"/etc/pptpd.conf",
		"/etc/ppp/pptpd-options",
		"/usr/sbin/accel-pppd",
		"/usr/lib/systemd/system/pptpd.service",
		"/lib/systemd/system/pptpd.service",
	)
}

// detectRDSWorkload reports whether the host runs Oracle Database
// (RDS — Reliable Datagram Sockets — is Oracle's RAC interconnect
// transport) or anything else linking against rds_tools. False
// positives are cheap: the alternate consumers of rds are essentially
// zero outside Oracle.
func detectRDSWorkload() bool {
	if anyModuleLoaded("rds", "rds_tcp", "rds_rdma") || anyPathExists("/proc/net/rds", "/sys/module/rds") {
		return true
	}
	if anyGlobMatches("/proc/net/rds*") {
		return true
	}
	return anyPathExists(
		"/u01/app/oracle",
		"/u01/oracle",
		"/etc/oratab",
		"/usr/bin/lsnrctl",
		"/usr/local/bin/lsnrctl",
		"/usr/lib/oracle",
		"/opt/oracle",
		"/usr/bin/rds-info",
		"/usr/bin/rds-ping",
	)
}

// deadFSNames returns the set of filesystem names that ship in the
// modules.fs.unused group. The dead-FS gate (HasMountedDeadFS) derives
// its watchlist from this so the rule list and the probe stay in sync —
// adding a new dead FS to Tier1Modules automatically extends the gate.
func deadFSNames() []string {
	var names []string
	seen := map[string]struct{}{}
	for _, r := range Tier1Modules {
		if r.Group != "modules.fs.unused" {
			continue
		}
		if _, dup := seen[r.Name]; dup {
			continue
		}
		seen[r.Name] = struct{}{}
		names = append(names, r.Name)
	}
	return names
}

// detectMountedDeadFS scans /proc/mounts and /etc/fstab for any of the
// filesystems shipped in the modules.fs.unused blacklist. A single hit
// in either source skips the whole group — the cost of keeping cramfs
// or hfs+ loadable is trivial compared to silently breaking a backup
// pipeline that mounts UDF for archive recovery, or a 2014-era JFS
// partition that nobody cleaned up. Returns the FS name (for the skip
// reason) plus the bool.
func detectMountedDeadFS() (bool, string) {
	watch := make(map[string]struct{})
	for _, name := range deadFSNames() {
		watch[name] = struct{}{}
	}
	if len(watch) == 0 {
		return false, ""
	}
	if hit := firstMatchingFSFromMounts(watch); hit != "" {
		return true, hit + " mounted (/proc/mounts)"
	}
	if hit := firstMatchingFSFromFstab(watch); hit != "" {
		return true, hit + " listed in /etc/fstab"
	}
	return false, ""
}

func firstMatchingFSFromMounts(watch map[string]struct{}) string {
	b, err := os.ReadFile(hostProfilePath("/proc/mounts"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if _, ok := watch[fields[2]]; ok {
			return fields[2]
		}
	}
	return ""
}

func firstMatchingFSFromFstab(watch map[string]struct{}) string {
	b, err := os.ReadFile(hostProfilePath("/etc/fstab"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		if _, ok := watch[fields[2]]; !ok {
			continue
		}
		// Skip entries the operator keeps for documentation but isn't
		// actually mounting at boot — `noauto` means systemd / mount -a
		// don't pick it up, so blacklisting the FS doesn't break
		// anything in practice. The options column is fstab field 4.
		if len(fields) >= 4 {
			opts := strings.Split(fields[3], ",")
			hasNoauto := false
			for _, opt := range opts {
				if strings.TrimSpace(opt) == "noauto" {
					hasNoauto = true
					break
				}
			}
			if hasNoauto {
				continue
			}
		}
		return fields[2]
	}
	return ""
}

// detectMCTPInBand reports whether the kernel's in-band MCTP stack has
// at least one registered endpoint. Out-of-band BMC paths used by
// Supermicro IPMI and Dell iDRAC ride their own NIC and do not touch
// this stack; the in-band MCTP modules are only relevant on OpenBMC
// platforms (Supermicro H13SRD-F MicroCloud, AMI MegaRAC OpenBMC nodes)
// and on hosts using NVMe-MI / PCIe VDM MCTP transports.
//
// Three layered signals — any one is sufficient evidence to skip the
// modules.mctp blacklist on this host:
//
//   - /sys/bus/mctp/devices/ non-empty: the kernel mctp bus has
//     registered endpoints right now.
//   - /sys/class/mctp/ non-empty: older kernels expose endpoints via
//     the class device tree before the bus directory existed.
//   - Any netdev under /sys/class/net/<iface>/type reading "290"
//     (ARPHRD_MCTP). Catches platforms where the mctp transport
//     drivers register a netdev but the bus directory is empty.
//
// Bias toward false-positive ("MCTP present") rather than
// false-negative — incorrectly skipping the blacklist on a hosting box
// is a no-op (the modules just stay loadable); incorrectly applying it
// on an OpenBMC node would break IPMI/sensor sideband.
func detectMCTPInBand() bool {
	if dirHasEntries("/sys/bus/mctp/devices") {
		return true
	}
	if dirHasEntries("/sys/class/mctp") {
		return true
	}
	entries, err := os.ReadDir(hostProfilePath("/sys/class/net"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(hostProfilePath("/sys/class/net"), e.Name(), "type"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == "290" {
			return true
		}
	}
	return false
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

// Advisories returns soft-warning notes for a rule that is going to
// apply on this host. Unlike SkipReason, these do NOT change the
// decision — the rule still applies — they surface in the audit /
// preview / TUI as informational "heads up" notes so the operator
// knows about workload impact they might not otherwise notice. Use
// for cases like "rule applies safely, but tooling X needs sudo
// afterward" or "rule stacks perf cost on top of subsystem Y".
//
// Each rule has its own targeted advisory keyed by ID — group-level
// advisories don't fit when a group like kspp.kernel contains rules
// with very different operational impact.
func (p HostProfile) Advisories(id, _ string) []string {
	var out []string
	switch id {
	case "KSEC-SCT-kspp.kernel-003":
		// unprivileged_bpf_disabled=2 — root BPF (bpftrace, bcc, Cilium)
		// is unaffected, but the operator should know unprivileged
		// eBPF and non-root bpftool are now blocked.
		if p.HasDevTools {
			out = append(out, "developer tooling detected (gdb / strace / bpftrace / bcc / perf) — these run as root and remain functional; unprivileged eBPF and non-root bpftool are blocked")
		}
	case "KSEC-SCT-kspp.kernel-006":
		// yama.ptrace_scope=2 — same-uid debugger attach now needs sudo.
		if p.HasDevTools {
			out = append(out, "developer tooling detected (gdb / strace / py-spy / bpftrace) — `gdb --attach`, `strace -p`, `py-spy`, `bpftrace -p` against your own processes will need sudo")
		}
	case "KSEC-SCT-kspp.kexec-001":
		// kexec_load_disabled=1 — live-patching does not use kexec, so
		// no conflict, but the operator should know this rule does not
		// add to live-patching's existing protection.
		if p.HasLivePatchingModules || p.HasKernelCare || p.HasKsplice {
			out = append(out, "live-patching active (KernelCare / Ksplice / kpatch) — kexec_load_disabled is compatible (live-patches don't use kexec) but does not add to live-patching's protection")
		}
	case "KSEC-BOOT-tier3.mempaint-001":
		// init_on_free=1 — stacks alloc cost on subsystems that
		// already have heavy memory traffic.
		if p.HasZFS {
			out = append(out, "ZFS detected — init_on_free=1 may add measurable alloc cost stacked on top of ZFS ARC overhead; benchmark before production")
		}
		if p.HasNVIDIA {
			out = append(out, "NVIDIA driver detected — init_on_free=1 may add measurable alloc cost on GPU memory hot paths; benchmark if the workload is GPU-intensive")
		}
	}
	return out
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
	case "modules.mctp":
		// In-band MCTP is relevant only on OpenBMC platforms (e.g.
		// Supermicro H13SRD-F MicroCloud nodes), NVMe-MI hosts, and
		// PCIe VDM sideband. Classic Supermicro IPMI / Dell iDRAC use
		// their own dedicated NIC and never touch this stack, so the
		// default on hosting is blacklist. The probe auto-skips when
		// the kernel mctp bus or class has registered endpoints.
		if p.HasMCTPInBand {
			return "host has in-band MCTP endpoints (OpenBMC / NVMe-MI / PCIe VDM) — /sys/bus/mctp or /sys/class/mctp non-empty"
		}
	case "modules.recent_cves.ksmbd":
		// ksmbd is shipped in modules.recent_cves because of its 2023-25
		// LPE history, but a handful of operators run it deliberately as
		// a kernel-fast Samba replacement for internal file shares.
		// Blacklisting it on those hosts would silently break the
		// shares; skip when the userspace tooling, sysfs class, or
		// loaded module says it's in use.
		if p.HasKSMBDServer {
			return "ksmbd in use — kernel module loaded, /sys/class/ksmbd populated, or ksmbd-tools (ksmbd.mountd / /etc/ksmbd) installed"
		}
	case "modules.net.legacy.tipc":
		// TIPC has had LPEs and zero use on web hosting, but it's the
		// transport some HA-cluster stacks ride on. Skip when there's
		// any sign of TIPC use so we don't break Pacemaker/Corosync
		// fabrics or Erlang/OTP distribution.
		if p.HasTIPCWorkload {
			return "TIPC workload detected — tipc module loaded, /proc/net/tipc, tipc tooling, or *tipc*.service installed"
		}
	case "modules.net.legacy.rxrpc":
		// rxrpc is the AFS RPC transport. If anything on the host
		// (kafs / openafs / a mounted /afs cell) is using it, skip
		// the blacklist — same flavour as the bridge / llc gate.
		if p.HasAFS {
			return "AFS client detected — rxrpc / kafs / openafs loaded, /afs mounted, or OpenAFS tooling installed"
		}
	case "modules.net.legacy.l2tp":
		// l2tp_* covers the kernel data path for L2TPv2 + L2TPv3.
		// Userspace can still terminate L2TP via xl2tpd / kl2tpd /
		// accel-ppp — if any of that is present, the operator has
		// L2TP plans and we should not silently disable the kernel
		// transport.
		if p.HasL2TPWorkload {
			return "L2TP workload detected — l2tp_* module loaded, /proc/net/l2tp*, or xl2tpd / kl2tpd / accel-ppp installed"
		}
	case "modules.net.legacy.pptp":
		if p.HasPPTPWorkload {
			return "PPTP workload detected — pptp module loaded, /proc/net/pptp, or pptpd / accel-ppp installed"
		}
	case "modules.net.legacy.ppp":
		// slhc (VJ header compression) is pulled in by ppp_async,
		// pptp, and l2tp_ppp. Skip the blacklist whenever PPP-family
		// VPN termination is detected, since slhc is on that data
		// path even if generic PPP itself isn't blacklisted.
		if p.HasL2TPWorkload {
			return "L2TP workload detected — slhc is pulled in by l2tp_ppp's PPP CCP path"
		}
		if p.HasPPTPWorkload {
			return "PPTP workload detected — slhc is pulled in by pptp's PPP CCP path"
		}
	case "modules.net.legacy.rds":
		// rds is Oracle's RAC interconnect. False-positive risk is
		// essentially zero — almost nothing else uses RDS.
		if p.HasRDSWorkload {
			return "Oracle / RDS workload detected — rds module loaded, /proc/net/rds*, or Oracle DB indicators (oratab, lsnrctl, /u01/app/oracle) present"
		}
	case "modules.fs.unused":
		// One hit in /proc/mounts or /etc/fstab covers the whole
		// group: the cost of keeping cramfs / hfs+ / etc. loadable is
		// trivial compared to breaking a backup pipeline that mounts
		// UDF, or a legacy JFS partition nobody migrated. Same
		// flavour as the llc / Docker bridge gate.
		if p.HasMountedDeadFS {
			detail := p.MountedDeadFSDetail
			if detail == "" {
				detail = "filesystem from modules.fs.unused is in use"
			}
			return "dead-FS in use — " + detail
		}
	case "modules.bus.firewire":
		// Symmetric with modules.bus.thunderbolt — if the host has
		// FireWire hardware, blacklisting firewire-* breaks the
		// transport. Rare on servers but real on older bare-metal
		// audio / video workstations occasionally repurposed.
		if p.HasFirewireHardware {
			return "host has FireWire hardware (/sys/bus/firewire/devices non-empty)"
		}
	case "modules.net.legacy.sctp":
		// sctp / sctp_diag are blacklisted by default — no LPE-class
		// CVE-prone protocol with zero use on standard hosting (httpd /
		// nginx / lshttpd / exim / postfix / dovecot / bind / cPanel /
		// DA / Virtualmin / CloudLinux) should stay loaded. But
		// telecom signalling stacks (SS7 / Diameter / M3UA), K8s
		// Services with protocol: SCTP, and lksctp-tools-based
		// monitoring DO need it — auto-skip on any host that shows
		// signs of those workloads. WebRTC's usrsctp lives in
		// userspace and is intentionally NOT a gate signal.
		if p.HasSCTPWorkload {
			return "SCTP workload detected — sctp module loaded, /proc/net/sctp present, or SCTP-aware service/binary installed"
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
		// (KVM hypervisor, libvirt, Docker / container engine, cPanel /
		// DA / Virtualmin / CloudLinux box) that single oops can take
		// down every guest / container / tenant at once. Live-patching
		// hosts are also out: KernelCare / Ksplice are explicit
		// uptime-priority signals and reboot-on-oops is antithetical to
		// what live-patching is for.
		//
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
		if p.HasLivePatchingModules || p.HasKernelCare || p.HasKsplice {
			return "live-patching active (KernelCare / Ksplice / kpatch / kgraft) — operator priority is uptime; reboot-on-oops is antithetical"
		}
		if reason := p.hostingPanelReason(); reason != "" {
			return "multi-tenant hosting panel — a kernel oops here would reboot every tenant at once: " + reason
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
