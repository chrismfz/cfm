package kernsec

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// SysctlPath is where kernsec persists the sysctl rule set. Number 99
// keeps it last in /etc/sysctl.d processing order — anything else
// distros put in /etc/sysctl.d gets overridden by us.
//
// Declared as var (not const) so tests can redirect it to t.TempDir().
var SysctlPath = "/etc/sysctl.d/99-cfm-kernsec.conf"

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
// atomically. Two-tier backup:
//
//  1. One-shot `<path>.cfm-kernsec.bak` of the very first version
//     kernsec ever sees (typically distro-shipped or empty).
//  2. Per-run timestamped `<path>.cfm-kernsec.bak.<TS>` whenever the
//     existing file contains lines that aren't in the rendered set —
//     i.e. the operator edited a managed file. Apply still proceeds
//     (idempotent), but the operator's edits are preserved and a
//     warning is emitted to w.
//
// w is the writer used for the unmanaged-line warning. Pass io.Discard
// when warnings shouldn't surface (tests, programmatic callers).
func WriteSysctlFile(w io.Writer, content []byte) error {
	if err := BackupOnce(SysctlPath, SysctlPath+BackupSuffix); err != nil {
		return err
	}
	if _, err := preserveAndWarnOnExtras(w, SysctlPath, content, "sysctl drop-in"); err != nil {
		return err
	}
	return AtomicWriteFile(SysctlPath, content, 0o644)
}

// LoadSysctl applies every key=value line in SysctlPath via per-key
// `sysctl -w` calls. Continue-on-error: a single bad key (kernel
// rejects the value, key was removed by module unload between render
// and load, lockdown blocks the write) does not stop subsequent keys
// from being applied. All per-key failures are accumulated and
// returned as a single error naming each rejected key plus the
// kernel's response.
//
// Replaces a previous `sysctl --load=<file>` invocation that had two
// problems:
//
//  1. Atomicity lie. The kernel applies sysctls one at a time, but
//     the single fork-exec made it look as if all keys succeeded or
//     all failed; in reality some keys were live and others weren't,
//     and the operator had no way to tell which.
//  2. Diagnostic loss. When `sysctl --load` exited non-zero the
//     operator got the *last* error message, not a per-key
//     accounting. Diagnosing "which sysctl did the kernel reject"
//     required re-running each line manually.
//
// Per-key apply is fork-heavier (~13 forks vs 1) but for a
// once-per-apply operation that's negligible. The operator-facing
// error names every rejected key with file:line context.
func LoadSysctl() error {
	content, err := os.ReadFile(SysctlPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", SysctlPath, err)
	}
	var failures []string
	for lineno, line := range strings.Split(string(content), "\n") {
		raw := line
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			// Malformed line — sysctl --load would have skipped this
			// silently too. Best-effort.
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}
		if out, err := sysctlSetCommand(key, val); err != nil {
			failures = append(failures, fmt.Sprintf(
				"  %s:%d  %s=%s: %v: %s",
				SysctlPath, lineno+1, key, val, err, strings.TrimSpace(string(out))))
			_ = raw
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("sysctl: %d key(s) rejected by kernel:\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
	return nil
}

// sysctlSetCommand applies one sysctl key/value via `sysctl -w`. var,
// not function, so tests can substitute a deterministic stub.
var sysctlSetCommand = func(key, value string) ([]byte, error) {
	return exec.Command("sysctl", "-w", key+"="+value).CombinedOutput()
}
