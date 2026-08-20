package kernsec

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// readLiveSysctl is the indirection point for reading /proc/sys values
// from the sticky-lock advisory path. var, not function, so tests can
// substitute a deterministic stub without touching real /proc.
var readLiveSysctl = ReadSysctl

// stickyOneWaySysctls is the set of sysctl keys that the kernel locks
// the moment the live value leaves 0 — every subsequent runtime write
// returns EPERM, even from root with CAP_SYS_ADMIN. The kernel BPF
// subsystem enforces this on kernel.unprivileged_bpf_disabled so that
// a kernel CVE or a compromised root process cannot re-enable
// unprivileged BPF after the operator chose to disable it; the side
// effect is that distros built with CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
// (RHEL / Alma 9-10, recent stable kernels) boot the knob already at
// 1 and the only way to land on 2 is the paired boot arg.
//
// LoadSysctl checks this map when a write fails: if the key is in
// here and the live /proc/sys value is already non-zero, the write
// could not possibly have succeeded — kernsec demotes the failure
// from a hard rejection to an advisory so `cfm kernsec apply` does
// not return rc=1 for an OS-level invariant the operator can only fix
// by rebooting onto the paired boot arg.
var stickyOneWaySysctls = map[string]bool{
	"kernel.unprivileged_bpf_disabled": true,
	// kexec_load_disabled is also one-way sticky: once non-zero, the
	// kernel refuses every subsequent write with EPERM until reboot.
	// Without this registration, the second `cfm kernsec apply` after
	// the first successful one would fail rc=1 trying to re-write the
	// same value we already set.
	"kernel.kexec_load_disabled": true,
}

// stickyAdvisoryBootArg names the matching boot arg an operator
// should look for in the next-boot cmdline to actually land on the
// desired sysctl value after reboot. Used purely for the human-
// readable advisory text emitted by LoadSysctl.
var stickyAdvisoryBootArg = map[string]string{
	"kernel.unprivileged_bpf_disabled": "unprivileged_bpf_disabled=2",
}

// stickyAcceptValues mirrors the AcceptValues field of the SysctlRule
// for sticky one-way knobs in a key-indexed form, so the runtime
// loader (which parses the rendered drop-in line-by-line, not the
// rule struct) can ask "is this live value already acceptable, even
// if it isn't the target?" without re-resolving the profile. Kept
// next to stickyOneWaySysctls so any future sticky knob added to one
// must be added to the other.
var stickyAcceptValues = map[string][]string{
	"kernel.unprivileged_bpf_disabled": {"1"},
	// kexec_load_disabled accepts only the sticky target value (1) as
	// already-acceptable. No alternative value can land at runtime
	// (writes after the first one return EPERM).
	"kernel.kexec_load_disabled": {"1"},
}

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
// and load, or a security module blocks the write) does not stop subsequent keys
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
//
// LoadSysctl discards advisory text (sticky-lock notices); the
// `cfm kernsec apply` code path uses LoadSysctlTo to surface them.
func LoadSysctl() error {
	return LoadSysctlTo(io.Discard)
}

// LoadSysctlTo is LoadSysctl with an explicit writer for human-
// readable diagnostics about per-key outcomes that aren't true
// failures. Currently used to surface sticky-knob advisories
// (see stickyOneWaySysctls): a write that the kernel refuses because
// the knob is locked at boot is NOT a hard failure — there is
// nothing runtime can do about it, the operator has to reboot onto
// the paired boot arg. Demoting it from "1 key rejected by kernel"
// (rc=1 from apply) to an advisory line on w preserves the diagnostic
// without making apply look like it failed for an OS invariant.
func LoadSysctlTo(w io.Writer) error {
	content, err := os.ReadFile(SysctlPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", SysctlPath, err)
	}
	var failures []string
	var advisories []string
	for lineno, line := range strings.Split(string(content), "\n") {
		// parseSysctlAssignment is the single shared sysctl-line parser
		// (see foreign_sysctl.go): it skips blank/comment/malformed lines
		// and normalises the key, so this loader and the foreign-drop-in
		// reconcile can never drift on how a line is read. ok==false for
		// anything sysctl --load would also skip silently.
		key, val, ok := parseSysctlAssignment(line)
		if !ok {
			continue
		}
		// Sticky one-way knobs (see stickyOneWaySysctls): if the live
		// value is already the target OR an explicitly accepted
		// variant, skip the runtime write. The kernel would EPERM on
		// the same-value write (locked knobs refuse every write once
		// non-zero, regardless of the value being written), and that
		// EPERM carries no information — the desired stance is already
		// in place. Skipping prevents the apply step from emitting
		// scary "1 key rejected" output for a non-problem.
		if stickyOneWaySysctls[key] {
			if live, ok := readLiveSysctl(key); ok && isAcceptable(live, val, stickyAcceptValues[key]) {
				continue
			}
		}
		out, runErr := sysctlSetCommand(key, val)
		if runErr == nil {
			continue
		}
		response := strings.TrimSpace(string(out))
		if adv, ok := stickyLockAdvisory(key, val, response, lineno+1); ok {
			advisories = append(advisories, adv)
			continue
		}
		failures = append(failures, fmt.Sprintf(
			"  %s:%d  %s=%s: %v: %s",
			SysctlPath, lineno+1, key, val, runErr, response))
	}
	if len(advisories) > 0 {
		fmt.Fprintf(w, "[Sysctl] %d key(s) locked by kernel at boot — runtime apply impossible, reboot required:\n",
			len(advisories))
		for _, a := range advisories {
			fmt.Fprintln(w, a)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("sysctl: %d key(s) rejected by kernel:\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
	return nil
}

// isAcceptable reports whether the live sysctl value is already in
// the set kernsec considers OK for a sticky one-way knob: the target
// value itself plus any explicit AcceptValues. Used by the runtime
// loader to short-circuit kernel-locked writes that would EPERM with
// no information gain.
func isAcceptable(live, target string, accept []string) bool {
	if live == target {
		return true
	}
	for _, v := range accept {
		if live == v {
			return true
		}
	}
	return false
}

// stickyLockAdvisory recognises the documented kernel behaviour where
// certain sysctl knobs are one-way: once the live value leaves 0 the
// kernel refuses every later write with EPERM. When the failing key
// matches that pattern AND the live /proc/sys value is already
// non-zero, this is not a kernsec bug, an operator mistake, or a
// transient — there is no runtime path to the desired value. Return
// a human-readable advisory and let the caller treat it as a non-
// failure. ok is false for any other situation, including EPERM on a
// sticky key whose live value is still 0 (that would be a genuine
// failure worth reporting).
func stickyLockAdvisory(key, want, response string, lineno int) (string, bool) {
	if !stickyOneWaySysctls[key] {
		return "", false
	}
	live, ok := readLiveSysctl(key)
	if !ok {
		return "", false
	}
	if live == "0" || live == "" {
		return "", false
	}
	if live == want {
		// Already at the desired value; the EPERM on write is
		// effectively a same-value no-op — surface as advisory so the
		// operator sees the knob is fine.
		return fmt.Sprintf(
			"  %s:%d  %s=%s already live (kernel locked at %s; sysctl -w rejected: %s)",
			SysctlPath, lineno, key, want, live, response), true
	}
	hint := ""
	if arg := stickyAdvisoryBootArg[key]; arg != "" {
		hint = fmt.Sprintf(
			"\n              fix: add `%s` to the kernel cmdline and reboot. The matching boot arg is part of the kernsec profile (cfm kernsec apply writes it); inspect with `cfm kernsec status`.",
			arg)
	}
	return fmt.Sprintf(
		"  %s:%d  %s=%s rejected: kernel locked at %s (sysctl -w: %s).%s",
		SysctlPath, lineno, key, want, live, response, hint), true
}

// sysctlSetCommand applies one sysctl key/value via `sysctl -w`. var,
// not function, so tests can substitute a deterministic stub.
var sysctlSetCommand = func(key, value string) ([]byte, error) {
	return exec.Command("sysctl", "-w", key+"="+value).CombinedOutput()
}
