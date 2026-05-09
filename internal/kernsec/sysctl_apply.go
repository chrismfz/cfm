package kernsec

import (
	"fmt"
	"os/exec"
	"strings"
)

// SysctlPath is where kernsec persists the sysctl rule set. Number 99
// keeps it last in /etc/sysctl.d processing order — anything else
// distros put in /etc/sysctl.d gets overridden by us.
const SysctlPath = "/etc/sysctl.d/99-cfm-kernsec.conf"

// RenderSysctlFile produces the content of /etc/sysctl.d/99-cfm-kernsec.conf
// for the given rule set. Rules whose key is not exposed by the
// running kernel are emitted as commented-out skip lines so the file
// stays a faithful record of operator intent (and a future kernel
// upgrade picks them up automatically).
//
// Mirrors kspp.sh write_sysctl_file.
func RenderSysctlFile(rules []SysctlRule) []byte {
	var b strings.Builder
	b.WriteString("# Managed by cfm kernsec — do not edit by hand.\n")
	b.WriteString("# Generated from /etc/cfm/kernsec.conf.\n")
	b.WriteString("# See docs/kernsec.md for the rule set and rationale.\n")
	b.WriteString("\n")

	if len(rules) == 0 {
		b.WriteString("# (no sysctl rules selected by current tier / overrides)\n")
		return []byte(b.String())
	}

	for _, r := range rules {
		if !sysctlExists(r.Key) {
			fmt.Fprintf(&b, "# skipped (%s not exposed by this kernel): %s = %s\n",
				r.Key, r.Key, r.Value)
			continue
		}
		fmt.Fprintf(&b, "%s = %s\n", r.Key, r.Value)
	}
	return []byte(b.String())
}

// sysctlExists reports whether /proc/sys/<key> is present on the
// running kernel. Cheap; used to skip rules that won't apply.
func sysctlExists(key string) bool {
	r := RealFS{}
	return r.Exists(SysctlProcPath(key))
}

// WriteSysctlFile writes the rendered sysctl content to SysctlPath
// atomically, taking a one-shot backup of any prior version first.
func WriteSysctlFile(content []byte) error {
	if err := BackupOnce(SysctlPath, SysctlPath+BackupSuffix); err != nil {
		return err
	}
	return AtomicWriteFile(SysctlPath, content, 0o644)
}

// LoadSysctl invokes `sysctl --load=<SysctlPath>` so the new values
// take effect immediately (no reboot needed for sysctl rules).
func LoadSysctl() error {
	out, err := exec.Command("sysctl", "--load="+SysctlPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl --load=%s: %v: %s",
			SysctlPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}
