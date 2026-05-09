package kernsec

import (
	"os"
	"strings"
)

// SysctlProcPath returns the /proc/sys path for a dotted sysctl key.
// "kernel.kptr_restrict" -> "/proc/sys/kernel/kptr_restrict".
func SysctlProcPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

// ReadSysctl reads the runtime value of a dotted sysctl key.
// Returns (value, present). Trims trailing whitespace.
func ReadSysctl(key string) (string, bool) {
	b, err := os.ReadFile(SysctlProcPath(key))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// SysctlState describes the runtime state of one expected sysctl rule.
type SysctlState int

const (
	// SysctlOK means /proc/sys exposes the key with the expected value.
	SysctlOK SysctlState = iota
	// SysctlMismatch means the key exists but has a different value.
	SysctlMismatch
	// SysctlMissing means the key is not exposed by this kernel.
	SysctlMissing
)

// CheckSysctl reports the state of one expected SysctlRule.
// foundValue is the live value if present, else "".
func CheckSysctl(rule SysctlRule) (state SysctlState, foundValue string) {
	v, ok := ReadSysctl(rule.Key)
	if !ok {
		return SysctlMissing, ""
	}
	if v == rule.Value {
		return SysctlOK, v
	}
	return SysctlMismatch, v
}
