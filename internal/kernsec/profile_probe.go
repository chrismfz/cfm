package kernsec

import (
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
	IsKVMHost               bool   `json:"is_kvm_host"`                // kvm_intel / kvm_amd loaded → KVM hypervisor host
	HasContainers           bool   `json:"has_containers"`             // runc / containerd / lxc / podman process running → don't kill userns
	HasIPsec                bool   `json:"has_ipsec"`                  // `ip xfrm policy` non-empty → don't blacklist IPsec modules
	HasDKMS                 bool   `json:"has_dkms"`                   // out-of-tree module evidence detected
	HasKdump                bool   `json:"has_kdump"`                  // kdump enabled → keep coredump gates conservative
	HasBluetoothHardware    bool   `json:"has_bluetooth_hardware"`     // /sys/class/bluetooth non-empty → don't blacklist Bluetooth modules
	HasThunderbolt          bool   `json:"has_thunderbolt"`            // /sys/bus/thunderbolt/devices non-empty → don't blacklist thunderbolt
	HasNFS                  bool   `json:"has_nfs"`                    // active NFS mounts → keep NFS untouched (already excluded by policy)
	IsEFIBoot               bool   `json:"is_efi_boot"`                // /sys/firmware/efi present → EFI boot; efi= boot args are meaningful
	IsCPanel                bool   `json:"is_cpanel"`                  // /usr/local/cpanel exists → cPanel/WHM host
	IsDirectAdmin           bool   `json:"is_directadmin"`             // /usr/local/directadmin exists → DirectAdmin host
	HasCloudLinuxLVE        bool   `json:"has_cloudlinux_lve"`         // /proc/lve or loaded lve/kmodlve → CloudLinux LVE host
	HasCageFS               bool   `json:"has_cagefs"`                 // /etc/cagefs or cagefsctl → CageFS host
	HasImunify360           bool   `json:"has_imunify360"`             // Imunify360 service/package/path indicators
	HasKernelCare           bool   `json:"has_kernelcare"`             // KernelCare live-patching indicators
	HasKsplice              bool   `json:"has_ksplice"`                // Ksplice live-patching indicators
	HasLivePatchingModules  bool   `json:"has_live_patching_modules"`  // loaded live-patching modules
	IsProxmox               bool   `json:"is_proxmox"`                 // Proxmox paths or proxmox-boot-tool present
	HasZFS                  bool   `json:"has_zfs"`                    // loaded zfs or ZFS path indicators
	HasNVIDIA               bool   `json:"has_nvidia"`                 // loaded NVIDIA modules
	HasBackupWorkload       bool   `json:"has_backup_workload"`        // common backup agents/services present
	HasMonitoringWorkload   bool   `json:"has_monitoring_workload"`    // common monitoring/crash-diagnostic agents present
	HasHostingPanelWorkload bool   `json:"has_hosting_panel_workload"` // cPanel/DirectAdmin/CloudLinux/CageFS/Imunify360 aggregate
	Reason                  string `json:"reason,omitempty"`           // freeform note used in --check output
}

// DetectHostProfile runs the cheap probes (~few hundred ms total).
// Pure: returns a value, no side effects on disk or kernel state.
func DetectHostProfile() HostProfile {
	p := HostProfile{
		IsKVMHost:              anyModuleLoaded("kvm_intel", "kvm_amd"),
		HasContainers:          defaultContainerProbe().detect(),
		HasIPsec:               hasIPsecPolicies(),
		HasKdump:               hasKdump(),
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
	}
	p.HasHostingPanelWorkload = p.IsCPanel || p.IsDirectAdmin || p.HasCloudLinuxLVE || p.HasCageFS || p.HasImunify360
	p.HasDKMS = hasOutOfTreeModuleEvidence(p)
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
	case "tier2.ssbd":
		if p.HasContainers || p.IsProxmox {
			return "seccomp-heavy container/Proxmox workload detected — SSBD seccomp mode may add measurable syscall overhead"
		}
		if reason := p.hostingPanelReason(); reason != "" {
			return "hosting panel seccomp workload: " + reason
		}
		if p.HasBackupWorkload {
			return "backup workload detected — avoid adding syscall overhead unless explicitly approved"
		}
		if p.HasMonitoringWorkload {
			return "monitoring workload detected — avoid adding syscall overhead unless explicitly approved"
		}
	case "tier2.namespace":
		// user.max_user_namespaces=0 / kernel.unprivileged_userns_clone=0
		// break Chromium sandbox, bwrap, rootless podman, cPanel jails,
		// CloudLinux/CageFS isolation, and hosting panel workloads.
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
	case "sysctl.kernel.coredump":
		// kernel.core_pattern=|/bin/false disables coredumps globally.
		// kdump relies on crash dumps captured via kexec; suppressing
		// core_pattern would silently break crash capture.
		if p.HasKdump {
			return "host has kdump enabled — kernel.core_pattern must remain writable for crash capture"
		}
		if reason := p.hostingPanelReason(); reason != "" {
			return "hosting panel/vendor diagnostics may require coredumps: " + reason
		}
		if p.HasBackupWorkload {
			return "backup workload detected — preserve global coredump handling for vendor diagnostics"
		}
		if p.HasMonitoringWorkload {
			return "monitoring/crash-diagnostic workload detected — preserve global coredump handling"
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

// hasKdump looks for kdump indicators across distros. Layered so a
// kdump-equipped host that hasn't yet armed (kexec_crash_loaded=0
// because the service hasn't run since last boot) still registers
// via the config-file / unit paths.
//
// Audit found `/etc/sysconfig/kdump` (RHEL family) was missing from
// the original probe — added here, plus a `systemctl is-enabled
// kdump.service` style check via the unit-file presence in standard
// systemd dirs (cheaper than shelling out).
func hasKdump() bool {
	// 1. Kernel-side indicator — set when crashkernel= reservation
	// happened AND `kdumpctl start` (or equivalent) loaded the
	// crash kernel. False on freshly-rebooted host; defensive
	// because the file-based checks below cover that.
	if b, err := os.ReadFile(hostProfilePath("/sys/kernel/kexec_crash_loaded")); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			return true
		}
	}
	// 2. Distro config files. RHEL / Alma / Rocky / CentOS use
	// `/etc/sysconfig/kdump` (default install) and `/etc/kdump.conf`
	// (configuration). Debian / Ubuntu use `kdump-tools`.
	for _, p := range []string{
		"/etc/kdump.conf",
		"/etc/sysconfig/kdump",
		"/etc/default/kdump-tools",
	} {
		if _, err := os.Stat(hostProfilePath(p)); err == nil {
			return true
		}
	}
	// 3. Unit-file presence (the service may not be enabled but
	// presence shows the operator chose to install kdump). Cheap
	// lookup vs shelling out to systemctl.
	for _, p := range []string{
		"/usr/lib/systemd/system/kdump.service",
		"/lib/systemd/system/kdump.service",
		"/usr/lib/systemd/system/kdump-tools.service",
		"/lib/systemd/system/kdump-tools.service",
	} {
		if _, err := os.Stat(hostProfilePath(p)); err == nil {
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
