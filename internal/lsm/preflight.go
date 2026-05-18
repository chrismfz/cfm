package lsm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
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
	preflightProcKallsyms     = "/proc/kallsyms"
)

// preflightProgramTypeProbe is the function used by
// checkBPFLSMProgramType to verify that the running kernel accepts
// BPF_PROG_TYPE_LSM at the bpf() syscall layer. Declared as a var so
// tests can stub it out without performing a real syscall. The
// default delegates to cilium/ebpf's feature probe, which attempts a
// minimal LSM program load against the file_mprotect hook.
var preflightProgramTypeProbe = func() error {
	return features.HaveProgramType(ebpf.LSM)
}

// upstreamBPFLSMMajor / upstreamBPFLSMMinor record the upstream
// kernel version where BPF LSM was merged. The numbers are used only
// in informational output: RHEL-family vendor kernels (AlmaLinux 8.6+,
// CloudLinux 9, etc.) backport BPF LSM to 4.18, so a uname-based
// comparison is the wrong proxy for capability. The bpf-lsm-program-type
// runtime probe is the authoritative gate.
const (
	upstreamBPFLSMMajor = 5
	upstreamBPFLSMMinor = 7
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
type PolicyAvailability struct {
	PolicyID  PolicyID
	Available bool
	Reason    string
}

type Preflight struct {
	// Checks are the individual check results in display order.
	Checks []CheckResult
	// PolicyAvailability reports per-policy optional attachment
	// prerequisites. An unavailable optional policy does not make OK
	// false; the loader will attach the rest of cfm-lsm in partial mode.
	PolicyAvailability []PolicyAvailability
	// OK is true iff every component-wide check passed. UNKNOWN counts
	// as not-OK because we cannot confirm the host can load BPF LSM
	// programs. Optional per-policy availability is reported separately.
	OK bool
}

// RunPreflight runs all kernel checks and returns the aggregate
// result. Reads from /proc and /sys, and performs one tiny bpf()
// syscall via checkBPFLSMProgramType to feature-probe the verifier;
// no writes are made.
func RunPreflight() Preflight {
	checks := []CheckResult{
		checkKernelVersion(),
		checkBPFLSMConfig(),
		checkBPFInLSMList(),
		checkBTFAvailable(),
		checkCapabilities(),
		checkBPFFSMounted(),
		checkBPFLSMProgramType(),
	}
	ok := true
	for _, c := range checks {
		if c.Status != CheckPass {
			ok = false
			break
		}
	}
	return Preflight{Checks: checks, PolicyAvailability: checkPolicyAvailability(), OK: ok}
}

func checkPolicyAvailability() []PolicyAvailability {
	return []PolicyAvailability{
		checkDirectCredInstallAvailability(),
		checkKexecLoadAvailability(),
	}
}

// checkKexecLoadAvailability reports whether the kexec syscall tracepoints
// are exposed by the running kernel. Both kexec_load (CONFIG_KEXEC) and
// kexec_file_load (CONFIG_KEXEC_FILE) are independent build-time options;
// RHEL 10 ships CONFIG_KEXEC=n. CFML-EXEC-008 attaches to whichever subset
// is present and is unavailable only when both are missing.
func checkKexecLoadAvailability() PolicyAvailability {
	pa := PolicyAvailability{PolicyID: PolicyKexecLoad, Available: true}
	have := []string{}
	missing := []string{}
	if tracepointAvailable("syscalls", "sys_enter_kexec_load") {
		have = append(have, "kexec_load")
	} else {
		missing = append(missing, "kexec_load")
	}
	if tracepointAvailable("syscalls", "sys_enter_kexec_file_load") {
		have = append(have, "kexec_file_load")
	} else {
		missing = append(missing, "kexec_file_load")
	}
	switch {
	case len(have) == 0:
		pa.Available = false
		pa.Reason = "neither sys_enter_kexec_load nor sys_enter_kexec_file_load exposed in tracefs (kernel built without CONFIG_KEXEC and CONFIG_KEXEC_FILE)"
	case len(missing) == 0:
		pa.Reason = "both kexec_load and kexec_file_load tracepoints present"
	default:
		pa.Reason = fmt.Sprintf("partial coverage — present: %s; missing: %s (kernel-config-gated)", strings.Join(have, ","), strings.Join(missing, ","))
	}
	return pa
}

func checkDirectCredInstallAvailability() PolicyAvailability {
	pa := PolicyAvailability{PolicyID: PolicyDirectCredInstall, Available: true}
	body, err := os.ReadFile(preflightProcKallsyms)
	if err != nil {
		pa.Available = false
		pa.Reason = fmt.Sprintf("cannot read %s to confirm commit_creds fentry target: %v", preflightProcKallsyms, err)
		return pa
	}
	if !kallsymsHasSymbol(string(body), "commit_creds") {
		pa.Available = false
		pa.Reason = "commit_creds is not visible in /proc/kallsyms; CFML-CRED-003 fentry telemetry unavailable"
		return pa
	}
	pa.Reason = "commit_creds fentry target visible in /proc/kallsyms"
	return pa
}

// checkKernelVersion reports the running kernel version. It is
// informational: BPF LSM availability is decided by the
// bpf-lsm-program-type probe, not by uname. RHEL-family vendor
// kernels backport BPF LSM to 4.18 (verified on AlmaLinux 8.10), so
// a version comparison would wrongly reject hosts that actually
// support the feature.
func checkKernelVersion() CheckResult {
	res := CheckResult{
		Name:        "kernel-version",
		Description: "running kernel (informational; capability is probed separately)",
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
	res.Status = CheckPass
	if major < upstreamBPFLSMMajor || (major == upstreamBPFLSMMajor && minor < upstreamBPFLSMMinor) {
		res.Detail = fmt.Sprintf("running kernel %s (older than upstream %d.%d; vendor backports decide capability — see bpf-lsm-program-type)", raw, upstreamBPFLSMMajor, upstreamBPFLSMMinor)
	} else {
		res.Detail = fmt.Sprintf("running kernel %s", raw)
	}
	return res
}

// checkBPFLSMProgramType is the authoritative gate for "can this
// kernel load BPF LSM programs at all". It attempts a tiny no-op LSM
// program load via cilium/ebpf's features.HaveProgramType, which
// makes a real bpf(BPF_PROG_LOAD, …) syscall against the file_mprotect
// hook. The kernel responds in one of three ways:
//
//   - nil → verifier engaged → BPF_PROG_TYPE_LSM is supported (PASS).
//   - ebpf.ErrNotSupported → bpf() dispatch rejected the program type
//     at the EINVAL/E2BIG layer → kernel does not expose BPF LSM to
//     userspace, even if CONFIG_BPF_LSM=y is set (FAIL).
//   - any other error → ambiguous (UNKNOWN), typically EPERM when
//     the process lacks caps, or transient kernel/library state.
//
// The CONFIG_BPF_LSM=y check is a useful diagnostic signal but is
// not sufficient on its own: some vendor kernels (CloudLinux 8 lve
// kernels observed in the wild) set the config flag for the kernel-
// internal subsystem but leave the userspace-loadable program type
// unwired. This probe distinguishes those hosts from AlmaLinux 8.6+,
// AlmaLinux 9+, AlmaLinux 10, CloudLinux 9+, RHEL 9+, Debian 12+,
// and Ubuntu 22.04+, which all accept the program type.
func checkBPFLSMProgramType() CheckResult {
	res := CheckResult{
		Name:        "bpf-lsm-program-type",
		Description: "kernel accepts BPF_PROG_TYPE_LSM via bpf() syscall",
	}
	err := preflightProgramTypeProbe()
	if err == nil {
		res.Status = CheckPass
		res.Detail = "BPF_PROG_TYPE_LSM accepted (file_mprotect attach probe loaded)"
		return res
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		res.Status = CheckFail
		res.Detail = "kernel rejected BPF_PROG_TYPE_LSM at bpf() syscall"
		res.Remediation = "the running kernel does not expose BPF LSM program loading to userspace. " +
			"Observed on CloudLinux 8 (lve) kernels which ship CONFIG_BPF_LSM=y for the internal " +
			"subsystem only. Supported targets: AlmaLinux 8.6+ / 9+ / 10, CloudLinux 9+, RHEL 9+, " +
			"Debian 12+, Ubuntu 22.04+."
		return res
	}
	res.Status = CheckUnknown
	res.Detail = fmt.Sprintf("program-type probe inconclusive: %v", err)
	res.Remediation = "ensure /sys/fs/bpf is mounted and the process has CAP_SYS_ADMIN " +
		"(or CAP_BPF + CAP_PERFMON); rerun `cfm lsm status`"
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
		res.Remediation = "kernel was built without BPF LSM support; use a distro kernel that ships CONFIG_BPF_LSM=y (AlmaLinux 8.6+ / 9+ / 10, CloudLinux 9+, RHEL 9+, Debian 12+, Ubuntu 22.04+) or rebuild with CONFIG_BPF_LSM=y"
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
		res.Remediation = "kernel was built without CONFIG_DEBUG_INFO_BTF=y; cfm-lsm requires CO-RE BTF (available on AlmaLinux 8.6+, RHEL 9+, Debian 12+, Ubuntu 22.04+, and newer)"
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

func kallsymsHasSymbol(kallsyms, symbol string) bool {
	for _, line := range strings.Split(kallsyms, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == symbol {
			return true
		}
	}
	return false
}
