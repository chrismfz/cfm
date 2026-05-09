package kernsec

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ReadKernelConfig returns the kernel build config text for the
// running kernel. Tries /boot/config-$(uname -r) first, then
// /proc/config.gz. Returns ("", false) if neither is readable.
func ReadKernelConfig() (string, bool) {
	rel := unameRelease()
	if rel != "" {
		if b, err := os.ReadFile("/boot/config-" + rel); err == nil {
			return string(b), true
		}
	}
	if f, err := os.Open("/proc/config.gz"); err == nil {
		defer f.Close()
		if zr, zerr := gzip.NewReader(f); zerr == nil {
			defer zr.Close()
			if b, rerr := io.ReadAll(zr); rerr == nil {
				return string(b), true
			}
		}
	}
	return "", false
}

// HasKernelConfig reports whether the kernel was built with the named
// CONFIG_* option set to "y". Loads the config text on each call;
// callers doing many checks should call ReadKernelConfig once and use
// HasKernelConfigIn.
func HasKernelConfig(name string) (set, available bool) {
	cfg, ok := ReadKernelConfig()
	if !ok {
		return false, false
	}
	return HasKernelConfigIn(cfg, name), true
}

// HasKernelConfigIn reports whether config text has CONFIG_<name>=y.
func HasKernelConfigIn(cfg, name string) bool {
	needle := "CONFIG_" + name + "=y"
	for _, line := range strings.Split(cfg, "\n") {
		if strings.TrimSpace(line) == needle {
			return true
		}
	}
	return false
}

// PageAllocShuffleState reads /sys/module/page_alloc/parameters/shuffle.
// Returns (rawValue, true) if readable, ("", false) if not present.
func PageAllocShuffleState() (string, bool) {
	b, err := os.ReadFile("/sys/module/page_alloc/parameters/shuffle")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// IsPageAllocShuffleOn reports whether the raw shuffle parameter
// value indicates active shuffling. Mirrors kspp.sh's case match
// against 1|Y|y|on|true.
func IsPageAllocShuffleOn(raw string) bool {
	switch raw {
	case "1", "Y", "y", "on", "true":
		return true
	}
	return false
}

// ReadKernelLog returns recent kernel-log text. Tries journalctl first
// (current boot, no metadata), then dmesg.
func ReadKernelLog() string {
	if out, err := exec.Command("journalctl", "-k", "-b", "-o", "cat").Output(); err == nil {
		return string(out)
	}
	if out, err := exec.Command("dmesg").Output(); err == nil {
		return string(out)
	}
	return ""
}

// MemAutoInitLine returns the most recent "mem auto-init: ... heap alloc:..."
// line from the kernel log, or "" if not found.
func MemAutoInitLine(log string) string {
	var last string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "mem auto-init:") && strings.Contains(line, "heap alloc:") {
			last = line
		}
	}
	return last
}

// IsInitOnAllocActive reports whether a mem auto-init line indicates
// init_on_alloc is on. Mirrors kspp.sh's grep for "heap alloc:on".
func IsInitOnAllocActive(line string) bool {
	return strings.Contains(line, "heap alloc:on")
}

// UnknownArgWarnings returns kernel-log lines that look like
// "Unknown kernel command line parameters" / "unknown parameter" /
// "invalid parameter" / "Malformed early option", filtered to those
// mentioning at least one of the managed keys. Empty slice if none.
func UnknownArgWarnings(log string, managed []string) []string {
	var matched []string
	for _, line := range strings.Split(log, "\n") {
		if !looksLikeUnknownArgWarning(line) {
			continue
		}
		for _, k := range managed {
			if strings.Contains(line, k) {
				matched = append(matched, line)
				break
			}
		}
	}
	return matched
}

func looksLikeUnknownArgWarning(line string) bool {
	low := strings.ToLower(line)
	for _, needle := range []string{
		"unknown kernel command line parameters",
		"unknown parameter",
		"invalid parameter",
		"malformed early option",
	} {
		if strings.Contains(low, needle) {
			return true
		}
	}
	return false
}

// AFAlgBindResult is the outcome of one AF_ALG bind probe.
type AFAlgBindResult struct {
	Type   string // e.g. "aead"
	Name   string // e.g. "authencesn(hmac(sha256),cbc(aes))"
	Bound  bool   // true if bind succeeded (mitigation NOT effective)
	ErrStr string // syscall error text if bind failed
}

// AFAlgProbes is the default set of AF_ALG bind probes Phase 1 runs.
// kspp.sh probes only the AEAD case used by the Copy Fail mitigation;
// kernsec adds hash, skcipher, rng, akcipher to surface the broader
// algif_* userspace API state.
var AFAlgProbes = []struct{ Type, Name string }{
	{"aead", "authencesn(hmac(sha256),cbc(aes))"},
	{"hash", "sha256"},
	{"skcipher", "cbc(aes)"},
	{"rng", "stdrng"},
	{"akcipher", "rsa"},
}

// ProbeAllAFAlg runs every probe in AFAlgProbes.
func ProbeAllAFAlg() []AFAlgBindResult {
	out := make([]AFAlgBindResult, 0, len(AFAlgProbes))
	for _, p := range AFAlgProbes {
		out = append(out, ProbeAFAlg(p.Type, p.Name))
	}
	return out
}

// ModuleLoaded reports whether name appears in /proc/modules.
// Mirrors a basic lsmod check; does not consult modinfo.
func ModuleLoaded(name string) bool {
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	prefix := name + " "
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// FormatAFAlg renders an AF_ALG probe result as a status line.
func FormatAFAlg(r AFAlgBindResult) string {
	if r.Bound {
		return fmt.Sprintf("WARN  AF_ALG %s %q bind succeeded — mitigation NOT effective", r.Type, r.Name)
	}
	if r.ErrStr == "" {
		return fmt.Sprintf("OK    AF_ALG %s %q bind failed", r.Type, r.Name)
	}
	return fmt.Sprintf("OK    AF_ALG %s %q bind failed: %s", r.Type, r.Name, r.ErrStr)
}
