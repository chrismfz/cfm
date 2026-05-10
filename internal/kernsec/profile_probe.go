package kernsec

import (
	"os"
	"path/filepath"
	"strings"
)

// HostProfile captures the runtime characteristics of the current host
// that affect which rules should be applied. Auto-skipped rules render
// as `SKIP (host profile: <reason>)` in audit output. Operators
// override per-rule with `state = force` in kernsec.conf.
type HostProfile struct {
	IsKVMHost            bool   // kvm_intel / kvm_amd loaded → KVM hypervisor host
	HasContainers        bool   // runc / containerd / lxc / podman process running → don't kill userns
	HasIPsec             bool   // `ip xfrm policy` non-empty → don't blacklist IPsec modules
	HasDKMS              bool   // any out-of-tree module evidence (loaded zfs/nvidia, /var/lib/dkms non-empty, akmods, /usr/src/*-dkms*) → don't enforce module sig / lockdown=integrity
	HasKdump             bool   // kdump enabled → don't disable kexec / lockdown
	HasBluetoothHardware bool   // /sys/class/bluetooth non-empty → don't blacklist Bluetooth modules
	HasThunderbolt       bool   // /sys/bus/thunderbolt/devices non-empty → don't blacklist thunderbolt
	HasNFS               bool   // active NFS mounts → keep NFS untouched (already excluded by policy)
	IsEFIBoot            bool   // /sys/firmware/efi present → EFI boot; efi= boot args are meaningful
	Reason               string // freeform note used in --check output
}

// DetectHostProfile runs the cheap probes (~few hundred ms total).
// Pure: returns a value, no side effects on disk or kernel state.
func DetectHostProfile() HostProfile {
	return HostProfile{
		IsKVMHost:            anyModuleLoaded("kvm_intel", "kvm_amd"),
		HasContainers:        defaultContainerProbe().detect(),
		HasIPsec:             hasIPsecPolicies(),
		HasDKMS:              hasOutOfTreeModuleEvidence(),
		HasKdump:             hasKdump(),
		HasBluetoothHardware: dirHasEntries("/sys/class/bluetooth"),
		HasThunderbolt:       dirHasEntries("/sys/bus/thunderbolt/devices"),
		HasNFS:               procMountsHasFS("nfs", "nfs4"),
		IsEFIBoot:            isEFIBoot(),
	}
}

// isEFIBoot reports whether the system booted via EFI. The kernel
// exposes /sys/firmware/efi only on EFI-booted systems; its absence
// means BIOS/legacy-boot and any efi= kernel parameter is a no-op.
func isEFIBoot() bool {
	_, err := os.Stat("/sys/firmware/efi")
	return err == nil
}

// hasOutOfTreeModuleEvidence is the layered "are there modules
// kernel-lockdown / module.sig_enforce would brick?" probe. The
// previous narrow check was loaded-modules-only (zfs / nvidia) —
// audit found multiple false-negative paths that would brick a
// real host:
//
//   - DKMS modules INSTALLED but not yet LOADED (e.g. zfs root not
//     yet imported, nvidia not yet pulled in by display manager,
//     virtualbox-modules pre-VM-launch).
//   - akmod (ELRepo on AlmaLinux/Rocky) — kABI-tracking precompiled
//     but not signed by the distro's kernel key.
//   - Out-of-tree modules in /lib/modules/$(uname -r)/extra or
//     /lib/modules/$(uname -r)/updates.
//   - Live-kernel-patching modules (KernelCare / Ksplice). These
//     load patch modules signed by the vendor's key, NOT the
//     distro's. lockdown=integrity / module.sig_enforce=1 would
//     block subsequent patches → host stops receiving CVE
//     coverage that the operator paid for. Especially relevant
//     on hosting platforms (cPanel ships KernelCare integration).
//
// Any single layer hitting → assume the host has unsigned/out-of-tree
// modules. False-positive bias intentional: skipping
// lockdown=integrity / module.sig_enforce is recoverable
// (operator can `state = force` per-rule); applying them on a host
// that needs an unsigned root-fs driver / a paid-for live-patcher
// is not.
func hasOutOfTreeModuleEvidence() bool {
	if anyModuleLoaded("zfs", "nvidia", "nvidia_drm", "nvidia_modeset") {
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
		if _, err := os.Stat(p); err == nil {
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
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// Ksplice (Oracle) — same family, different vendor.
	for _, p := range []string{
		"/usr/sbin/uptrack-upgrade",
		"/var/lib/uptrack",
		"/etc/uptrack",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// /usr/src/*-dkms* — DKMS source trees per the dkms package
	// convention. Glob-cheap relative to the rest of the apply
	// path.
	if matches, _ := filepath.Glob("/usr/src/*-dkms*"); len(matches) > 0 {
		return true
	}
	// /lib/modules/$(uname -r)/{extra,updates} — out-of-tree
	// module install dirs. Non-empty means modules outside the
	// distro kernel tree exist on this host.
	for _, sub := range []string{"extra", "updates"} {
		matches, _ := filepath.Glob(filepath.Join("/lib/modules/*", sub))
		for _, m := range matches {
			if dirHasEntries(m) {
				return true
			}
		}
	}
	return false
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
	case "boot.lockdown", "tier2.lockdown":
		// lockdown=integrity blocks unsigned module load and also
		// closes a number of kexec / /dev/mem / kdump primitives.
		// Skip on (a) hosts with DKMS / out-of-tree modules and
		// (b) hosts with kdump enabled — kdump uses kexec which
		// integrity lockdown restricts.
		if p.HasDKMS {
			return "host has DKMS / out-of-tree modules — lockdown=integrity would block them"
		}
		if p.HasKdump {
			return "host has kdump enabled — lockdown=integrity restricts kexec primitives kdump relies on"
		}
	case "tier2.module-sig-enforce":
		// module.sig_enforce=1 also breaks DKMS / out-of-tree
		// modules — it requires every module to be kernel-signed
		// and DKMS / akmod / custom-built modules usually aren't
		// signed by the distro.
		if p.HasDKMS {
			return "host has DKMS / out-of-tree modules — module.sig_enforce would block them"
		}
	case "tier2.namespace":
		// user.max_user_namespaces=0 / kernel.unprivileged_userns_clone=0
		// break Chromium sandbox, bwrap, rootless podman, some
		// cPanel jail variants. Skip when containers are running.
		if p.HasContainers {
			return "host has containers running (runc / containerd / lxc / podman)"
		}
	case "boot.kexec", "sysctl.kernel.kexec":
		if p.HasKdump {
			return "host has kdump enabled — kexec_load_disabled would break it"
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
	}
	return ""
}

// anyModuleLoaded returns true if any of the named modules is in
// /proc/modules.
func anyModuleLoaded(names ...string) bool {
	for _, n := range names {
		if ModuleLoaded(n) {
			return true
		}
	}
	return false
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
		procDir: "/proc",
		sockets: []string{
			"/var/run/docker.sock",
			"/run/docker.sock",
			"/var/run/crio/crio.sock",
			"/run/containerd/containerd.sock",
			"/run/podman/podman.sock",
		},
		nspawnDir: "/run/systemd/nspawn",
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
		if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) > 0 {
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
	if b, err := os.ReadFile("/sys/kernel/kexec_crash_loaded"); err == nil {
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
		if _, err := os.Stat(p); err == nil {
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
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// dirHasEntries returns true if dir exists and contains at least one
// non-"." / ".." entry.
func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// procMountsHasFS returns true if /proc/mounts lists any mount whose
// fs type matches one of the names.
func procMountsHasFS(types ...string) bool {
	b, err := os.ReadFile("/proc/mounts")
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
