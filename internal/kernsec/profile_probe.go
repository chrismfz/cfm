package kernsec

import (
	"os"
	"path/filepath"
	"strings"
)

// HostProfile captures the runtime characteristics of the current host
// that affect which rules should be applied. Auto-skipped rules render
// as `SKIP (host profile: <reason>)` in audit output. Operators
// override with `--force-id KSEC-...` if needed.
type HostProfile struct {
	IsKVMHost            bool   // kvm_intel / kvm_amd loaded → KVM hypervisor host
	HasContainers        bool   // runc / containerd / lxc / podman process running → don't kill userns
	HasIPsec             bool   // `ip xfrm policy` non-empty → don't blacklist IPsec modules
	HasWifi              bool   // cfg80211 loaded or wifi hardware → don't blacklist wireless
	HasDKMS              bool   // zfs / nvidia / DKMS modules → don't enforce module sig
	HasKdump             bool   // kdump enabled → don't disable kexec
	HasBluetoothHardware bool   // /sys/class/bluetooth populated → flag (still blacklist)
	HasNFS               bool   // active NFS mounts → keep NFS untouched (already excluded by policy)
	Reason               string // freeform note used in --check output
}

// DetectHostProfile runs the cheap probes (~few hundred ms total).
// Pure: returns a value, no side effects on disk or kernel state.
func DetectHostProfile() HostProfile {
	return HostProfile{
		IsKVMHost:            anyModuleLoaded("kvm_intel", "kvm_amd"),
		HasContainers:        anyProcessRunning("runc", "containerd", "lxc-start", "podman"),
		HasIPsec:             hasIPsecPolicies(),
		HasWifi:              ModuleLoaded("cfg80211") || hasWifiHardware(),
		HasDKMS:              anyModuleLoaded("zfs", "nvidia", "nvidia_drm", "nvidia_modeset"),
		HasKdump:             hasKdump(),
		HasBluetoothHardware: dirHasEntries("/sys/class/bluetooth"),
		HasNFS:               procMountsHasFS("nfs", "nfs4"),
	}
}

// SkipReason returns a non-empty explanation if the rule with the given
// group should be auto-skipped on this host, or "" if it should apply.
//
// The set of skip rules here is intentionally conservative: we only
// skip when running the rule would clearly break something the operator
// is using. Operators can `--force-id` to override.
func (p HostProfile) SkipReason(group string) string {
	switch group {
	case "modules.ipsec":
		if p.HasIPsec {
			return "host has active IPsec policies (ip xfrm policy non-empty)"
		}
	case "modules.wifi":
		if p.HasWifi {
			return "host has wifi hardware or cfg80211 loaded"
		}
	case "boot.lockdown":
		// module.sig_enforce=1 breaks DKMS modules.
		if p.HasDKMS {
			return "host has DKMS modules loaded (zfs / nvidia)"
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

// anyProcessRunning returns true if any of the named processes is
// currently running (cheap exact-name match against /proc/<pid>/comm).
func anyProcessRunning(names ...string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	wanted := make(map[string]struct{}, len(names))
	for _, n := range names {
		wanted[n] = struct{}{}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconvAtoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(b))
		if _, ok := wanted[comm]; ok {
			return true
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
