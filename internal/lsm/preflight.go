package lsm

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Preflight paths. Declared as vars so tests can redirect them to
// fixtures in t.TempDir().
var (
	preflightProcVersionPath  = "/proc/version"
	preflightProcConfigGzPath = "/proc/config.gz"
	preflightBootConfigDir    = "/boot"
	preflightLSMListPath      = "/sys/kernel/security/lsm"
	preflightBTFPath          = "/sys/kernel/btf/vmlinux"
	preflightProcSelfStatus   = "/proc/self/status"
	preflightBPFFSPath        = "/sys/fs/bpf"
	preflightProcMounts       = "/proc/mounts"
)

// minKernelMajor / minKernelMinor pin the earliest kernel that
// supports BPF LSM (merged in 5.7).
const (
	minKernelMajor = 5
	minKernelMinor = 7
)

// CheckStatus is the result of one preflight check.
type CheckStatus int

const (
	// CheckPass means the check confirmed the requirement is met.
	CheckPass CheckStatus = iota
	// CheckFail means the requirement is not met. The host cannot
	// load BPF LSM programs until the operator fixes whatever Detail
	// describes.
	CheckFail
	// CheckUnknown means the check could not run conclusively (e.g.
	// /proc/config.gz absent and no /boot/config-* readable). The
	// requirement may or may not be met; the operator has to verify
	// manually.
	CheckUnknown
)

// String renders the status as it appears in `cfm lsm status` text
// output.
func (s CheckStatus) String() string {
	switch s {
	case CheckPass:
		return "PASS"
	case CheckFail:
		return "FAIL"
	}
	return "UNKNOWN"
}

// CheckResult is one preflight check's outcome.
type CheckResult struct {
	// Name is a short identifier shown in status output, e.g.
	// "kernel-version".
	Name string
	// Description is the human-readable explanation of what the check
	// verifies, shown alongside the status.
	Description string
	// Status is the outcome.
	Status CheckStatus
	// Detail is a one-line specific finding (the value seen, the file
	// that was missing, etc.). Always non-empty.
	Detail string
	// Remediation is operator-facing guidance for fixing a FAIL. Empty
	// for PASS / UNKNOWN.
	Remediation string
}

// Preflight is the aggregate preflight result.
type Preflight struct {
	// Checks are the individual check results in display order.
	Checks []CheckResult
	// OK is true iff every check passed. UNKNOWN counts as not-OK
	// because we cannot confirm the host can load BPF LSM programs.
	OK bool
}

// RunPreflight runs all six kernel checks and returns the aggregate
// result. Pure: reads only from /proc and /sys; never writes anything.
func RunPreflight() Preflight {
	checks := []CheckResult{
		checkKernelVersion(),
		checkBPFLSMConfig(),
		checkBPFInLSMList(),
		checkBTFAvailable(),
		checkCapabilities(),
		checkBPFFSMounted(),
	}
	ok := true
	for _, c := range checks {
		if c.Status != CheckPass {
			ok = false
			break
		}
	}
	return Preflight{Checks: checks, OK: ok}
}

// checkKernelVersion verifies that the running kernel is ≥ 5.7,
// which is when BPF LSM was merged upstream.
func checkKernelVersion() CheckResult {
	res := CheckResult{
		Name:        "kernel-version",
		Description: fmt.Sprintf("Kernel ≥ %d.%d (BPF LSM merged in 5.7)", minKernelMajor, minKernelMinor),
	}
	b, err := os.ReadFile(preflightProcVersionPath)
	if err != nil {
		res.Status = CheckUnknown
		res.Detail = fmt.Sprintf("cannot read %s: %v", preflightProcVersionPath, err)
		return res
	}
	major, minor, raw, err := parseKernelVersion(string(b))
	if err != nil {
		res.Status = CheckUnknown
		res.Detail = fmt.Sprintf("cannot parse %s: %v", preflightProcVersionPath, err)
		return res
	}
	res.Detail = fmt.Sprintf("running kernel %s", raw)
	if major > minKernelMajor || (major == minKernelMajor && minor >= minKernelMinor) {
		res.Status = CheckPass
		return res
	}
	res.Status = CheckFail
	res.Remediation = fmt.Sprintf(
		"running kernel %d.%d is too old; upgrade to ≥ %d.%d (EL9 / Debian 12 / Ubuntu 22.04 ship a supported kernel)",
		major, minor, minKernelMajor, minKernelMinor,
	)
	return res
}

// checkBPFLSMConfig verifies CONFIG_BPF_LSM=y in the running kernel
// config. Tries /proc/config.gz first (CONFIG_IKCONFIG_PROC=y), falls
// back to /boot/config-<release>.
func checkBPFLSMConfig() CheckResult {
	res := CheckResult{
		Name:        "kernel-config",
		Description: "CONFIG_BPF_LSM=y in running kernel",
	}
	body, source, err := readKernelConfig()
	if err != nil {
		res.Status = CheckUnknown
		res.Detail = err.Error()
		res.Remediation = "verify CONFIG_BPF_LSM=y in the running kernel config (zcat /proc/config.gz | grep BPF_LSM, or grep BPF_LSM /boot/config-$(uname -r))"
		return res
	}
	val, ok := findKConfigValue(body, "CONFIG_BPF_LSM")
	res.Detail = fmt.Sprintf("read from %s", source)
	if !ok {
		res.Status = CheckFail
		res.Detail = fmt.Sprintf("CONFIG_BPF_LSM not set in %s", source)
		res.Remediation = "kernel was built without BPF LSM support; use a distro kernel ≥ EL9 / Debian 12 / Ubuntu 22.04 (or rebuild with CONFIG_BPF_LSM=y)"
		return res
	}
	if val == "y" {
		res.Status = CheckPass
		res.Detail = fmt.Sprintf("CONFIG_BPF_LSM=y (%s)", source)
		return res
	}
	res.Status = CheckFail
	res.Detail = fmt.Sprintf("CONFIG_BPF_LSM=%s in %s (need y)", val, source)
	res.Remediation = "rebuild the kernel with CONFIG_BPF_LSM=y, or switch to a distro kernel that ships it"
	return res
}

// checkBPFInLSMList verifies that the running kernel has the BPF LSM
// enabled in /sys/kernel/security/lsm. Most distros build with
// CONFIG_BPF_LSM=y but do not include "bpf" in the default LSM list,
// so this is usually the operator's first blocker.
func checkBPFInLSMList() CheckResult {
	res := CheckResult{
		Name:        "bpf-in-lsm-list",
		Description: "`bpf` enabled in /sys/kernel/security/lsm",
	}
	b, err := os.ReadFile(preflightLSMListPath)
	if err != nil {
		res.Status = CheckUnknown
		res.Detail = fmt.Sprintf("cannot read %s: %v", preflightLSMListPath, err)
		res.Remediation = "verify /sys/kernel/security/lsm exists; if not, the kernel was built without security= support"
		return res
	}
	list := strings.TrimSpace(string(b))
	res.Detail = fmt.Sprintf("/sys/kernel/security/lsm = %s", list)
	if hasLSM(list, "bpf") {
		res.Status = CheckPass
		return res
	}
	res.Status = CheckFail
	res.Remediation = fmt.Sprintf(
		"add `bpf` to the kernel cmdline; e.g. append `lsm=%s,bpf` to GRUB_CMDLINE_LINUX in /etc/default/grub, run `update-grub` (Debian/Ubuntu) or `grub2-mkconfig -o /boot/grub2/grub.cfg` (EL), and reboot",
		list,
	)
	return res
}

// checkBTFAvailable verifies that /sys/kernel/btf/vmlinux exists,
// which is required for CO-RE relocation.
func checkBTFAvailable() CheckResult {
	res := CheckResult{
		Name:        "btf-available",
		Description: "/sys/kernel/btf/vmlinux present (required for CO-RE)",
	}
	fi, err := os.Stat(preflightBTFPath)
	if err != nil {
		res.Status = CheckFail
		res.Detail = fmt.Sprintf("%s: %v", preflightBTFPath, err)
		res.Remediation = "kernel was built without CONFIG_DEBUG_INFO_BTF=y; cfm-lsm requires CO-RE BTF (use a distro kernel ≥ EL9 / Debian 12 / Ubuntu 22.04)"
		return res
	}
	res.Status = CheckPass
	res.Detail = fmt.Sprintf("%s present (%d bytes)", preflightBTFPath, fi.Size())
	return res
}

// checkCapabilities verifies that the current process has the
// capabilities required to load and attach BPF LSM programs. Reads
// CapEff from /proc/self/status; a process that holds CAP_SYS_ADMIN
// implicitly satisfies the BPF cap requirement on every supported
// kernel, but newer kernels also accept the finer-grained CAP_BPF +
// CAP_PERFMON pair, so we accept either combination.
func checkCapabilities() CheckResult {
	res := CheckResult{
		Name:        "capabilities",
		Description: "process has CAP_SYS_ADMIN (or CAP_BPF + CAP_PERFMON)",
	}
	body, err := os.ReadFile(preflightProcSelfStatus)
	if err != nil {
		res.Status = CheckUnknown
		res.Detail = fmt.Sprintf("cannot read %s: %v", preflightProcSelfStatus, err)
		return res
	}
	capEff, ok := extractCapEff(string(body))
	if !ok {
		res.Status = CheckUnknown
		res.Detail = "CapEff line missing from /proc/self/status"
		return res
	}
	hasSysAdmin := capHas(capEff, capSysAdmin)
	hasBPF := capHas(capEff, capBPF)
	hasPerfmon := capHas(capEff, capPerfmon)
	res.Detail = fmt.Sprintf("CapEff=%016x SYS_ADMIN=%t BPF=%t PERFMON=%t",
		capEff, hasSysAdmin, hasBPF, hasPerfmon)
	if hasSysAdmin || (hasBPF && hasPerfmon) {
		res.Status = CheckPass
		return res
	}
	res.Status = CheckFail
	res.Remediation = "run cfm as root or grant CAP_SYS_ADMIN (or both CAP_BPF and CAP_PERFMON) via systemd's AmbientCapabilities="
	return res
}

// checkBPFFSMounted verifies that /sys/fs/bpf is mounted with type
// `bpf`. The bpffs is required to pin BPF programs and maps so they
// survive the loading process exiting — without it, `cfm lsm enable`
// would attach programs that immediately detach the moment the CLI
// exits.
//
// Systemd has mounted bpffs by default since 2015 (v229), so this
// check passes everywhere CFM is actually deployed. The check exists
// to give a clear remediation message on the rare stripped-down or
// containerised host where it is missing.
func checkBPFFSMounted() CheckResult {
	res := CheckResult{
		Name:        "bpffs-mounted",
		Description: "/sys/fs/bpf is a mounted bpf filesystem",
	}
	body, err := os.ReadFile(preflightProcMounts)
	if err != nil {
		res.Status = CheckUnknown
		res.Detail = fmt.Sprintf("cannot read %s: %v", preflightProcMounts, err)
		return res
	}
	if procMountsHasBPFFS(string(body), preflightBPFFSPath) {
		res.Status = CheckPass
		res.Detail = preflightBPFFSPath + " is a bpf filesystem"
		return res
	}
	res.Status = CheckFail
	res.Detail = preflightBPFFSPath + " is not mounted as type bpf"
	res.Remediation = "mount the BPF filesystem: `mount -t bpf bpf " + preflightBPFFSPath +
		"`; for a persistent mount add `bpf " + preflightBPFFSPath +
		" bpf defaults 0 0` to /etc/fstab (systemd-mounted by default on EL9+, Debian 11+, Ubuntu 20.04+)"
	return res
}

// procMountsHasBPFFS scans a /proc/mounts payload for an entry where
// the mountpoint matches path AND the filesystem type is "bpf". A
// match means bpffs is ready for pinning.
func procMountsHasBPFFS(mounts, path string) bool {
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// /proc/mounts columns: device mountpoint fstype options dump pass
		if fields[1] == path && fields[2] == "bpf" {
			return true
		}
	}
	return false
}

// readKernelConfig returns the kernel config body and a description of
// where it came from. Tries /proc/config.gz (gzipped), then
// /boot/config-<uname -r>.
func readKernelConfig() (string, string, error) {
	if b, err := os.ReadFile(preflightProcConfigGzPath); err == nil {
		gz, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return "", "", fmt.Errorf("cannot decompress %s: %v", preflightProcConfigGzPath, err)
		}
		defer gz.Close()
		decoded, err := io.ReadAll(gz)
		if err != nil {
			return "", "", fmt.Errorf("cannot read %s: %v", preflightProcConfigGzPath, err)
		}
		return string(decoded), preflightProcConfigGzPath, nil
	}
	release, err := readKernelRelease()
	if err != nil {
		return "", "", fmt.Errorf("cannot determine kernel release: %v", err)
	}
	bootConfig := preflightBootConfigDir + "/config-" + release
	b, err := os.ReadFile(bootConfig)
	if err != nil {
		return "", "", fmt.Errorf("neither %s nor %s is readable", preflightProcConfigGzPath, bootConfig)
	}
	return string(b), bootConfig, nil
}

// readKernelRelease extracts the kernel release ("5.15.0-78-generic")
// from /proc/version. Avoids the `uname` syscall to keep the package
// pure-Go and trivially testable via the preflightProcVersionPath
// override.
func readKernelRelease() (string, error) {
	b, err := os.ReadFile(preflightProcVersionPath)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return "", fmt.Errorf("unexpected /proc/version: %q", string(b))
	}
	return fields[2], nil
}

func findKConfigValue(body, key string) (string, bool) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if eq := strings.IndexByte(line, '='); eq > 0 && line[:eq] == key {
			return strings.TrimSpace(line[eq+1:]), true
		}
	}
	return "", false
}

// parseKernelVersion extracts (major, minor, raw) from a /proc/version
// line like "Linux version 5.15.0-78-generic (...)" → 5, 15, "5.15.0-78-generic".
func parseKernelVersion(s string) (int, int, string, error) {
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return 0, 0, "", fmt.Errorf("unexpected /proc/version format")
	}
	raw := fields[2]
	// Trim release suffix at the first non-version char to get x.y.z.
	core := raw
	for i, r := range core {
		if !(r >= '0' && r <= '9') && r != '.' {
			core = core[:i]
			break
		}
	}
	parts := strings.SplitN(core, ".", 3)
	if len(parts) < 2 {
		return 0, 0, raw, fmt.Errorf("version %q lacks a minor component", raw)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, raw, fmt.Errorf("major %q is not a number", parts[0])
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, raw, fmt.Errorf("minor %q is not a number", parts[1])
	}
	return maj, min, raw, nil
}

// hasLSM reports whether name appears in a comma-separated LSM list.
// The list at /sys/kernel/security/lsm uses commas, e.g.
// "lockdown,capability,landlock,yama,bpf".
func hasLSM(list, name string) bool {
	for _, p := range strings.Split(list, ",") {
		if strings.TrimSpace(p) == name {
			return true
		}
	}
	return false
}

// capability bit positions (see linux/capability.h).
const (
	capSysAdmin uint64 = 21
	capBPF      uint64 = 39
	capPerfmon  uint64 = 38
)

func capHas(eff uint64, bit uint64) bool {
	return eff&(1<<bit) != 0
}

// extractCapEff parses the CapEff field from /proc/self/status.
// Format: "CapEff:\t0000003fffffffff".
func extractCapEff(status string) (uint64, bool) {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		n, err := strconv.ParseUint(val, 16, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
