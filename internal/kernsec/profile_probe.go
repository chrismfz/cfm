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
	HasWifi              bool   // cfg80211 loaded or wifi hardware → flag (no wifi rules ship today)
	HasDKMS              bool   // zfs / nvidia / DKMS modules → don't enforce module sig
	HasKdump             bool   // kdump enabled → don't disable kexec
	HasBluetoothHardware bool   // /sys/class/bluetooth non-empty → don't blacklist Bluetooth modules
	HasThunderbolt       bool   // /sys/bus/thunderbolt/devices non-empty → don't blacklist thunderbolt
	HasNFS               bool   // active NFS mounts → keep NFS untouched (already excluded by policy)
	Reason               string // freeform note used in --check output
}

// DetectHostProfile runs the cheap probes (~few hundred ms total).
// Pure: returns a value, no side effects on disk or kernel state.
func DetectHostProfile() HostProfile {
	return HostProfile{
		IsKVMHost:            anyModuleLoaded("kvm_intel", "kvm_amd"),
		HasContainers:        defaultContainerProbe().detect(),
		HasIPsec:             hasIPsecPolicies(),
		HasWifi:              ModuleLoaded("cfg80211") || hasWifiHardware(),
		HasDKMS:              anyModuleLoaded("zfs", "nvidia", "nvidia_drm", "nvidia_modeset"),
		HasKdump:             hasKdump(),
		HasBluetoothHardware: dirHasEntries("/sys/class/bluetooth"),
		HasThunderbolt:       dirHasEntries("/sys/bus/thunderbolt/devices"),
		HasNFS:               procMountsHasFS("nfs", "nfs4"),
	}
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
		// lockdown=integrity blocks unsigned module load.
		if p.HasDKMS {
			return "host has DKMS modules loaded (zfs / nvidia) — lockdown=integrity would block them"
		}
	case "tier2.module-sig-enforce":
		// module.sig_enforce=1 also breaks DKMS modules — it
		// requires every module to be kernel-signed and DKMS
		// modules are usually not signed by the distro.
		if p.HasDKMS {
			return "host has DKMS modules loaded (zfs / nvidia) — module.sig_enforce would block them"
		}
	case "tier2.namespace":
		// user.max_user_namespaces=0 / kernel.unprivileged_userns_clone=0
		// break Chromium sandbox, bwrap, rootless podman, some
		// cPanel jail variants. Skip when containers are running.
		if p.HasContainers {
			return "host has containers running (runc / containerd / lxc / podman)"
		}
	case "boot.kexec":
		if p.HasKdump {
			return "host has kdump enabled — kexec_load_disabled would break it"
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

// hasWifiHardware looks for /sys/class/net/* whose wireless attribute
// directory exists. No exec, no shell.
func hasWifiHardware() bool {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}
	for _, e := range entries {
		st, err := os.Stat(filepath.Join("/sys/class/net", e.Name(), "wireless"))
		if err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

// hasKdump looks for the kdump-tools / kexec-tools service-state file
// or an active kdump.service unit file.
func hasKdump() bool {
	for _, p := range []string{
		"/sys/kernel/kexec_crash_loaded",
	} {
		if b, err := os.ReadFile(p); err == nil {
			if strings.TrimSpace(string(b)) == "1" {
				return true
			}
		}
	}
	for _, p := range []string{
		"/etc/kdump.conf",
		"/etc/default/kdump-tools",
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
