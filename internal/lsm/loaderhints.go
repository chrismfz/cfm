//go:build linux

package lsm

import (
	"fmt"
	"io"
	"strings"
)

// emitLoadFailureHint inspects a load-side error and prints the most
// useful human-readable hint about *why* the kernel refused the BPF
// load. Called from `cfm lsm probe` and `cfm lsm enable` after a
// failure wrapped in ErrBPFLSMUnavailable.
//
// The hints are pattern-matched against the verifier's error string
// because cilium/ebpf surfaces it as a plain message; we get one shot
// at categorising it before the operator dives into audit.log.
func emitLoadFailureHint(w io.Writer, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "doesn't have ") && strings.Contains(msg, "argument"):
		// The verifier rejected a BPF LSM program because its
		// declared arg count doesn't match the kernel's trampoline.
		// Almost always a kernel LSM hook arity drift the loader
		// didn't anticipate — see internal/lsm/btfprobe.go.
		fmt.Fprintln(w, "The kernel exposes an LSM hook with a different arity than the BPF")
		fmt.Fprintln(w, "program was compiled for. This is a cfm bug (a missing BTF-probe entry")
		fmt.Fprintln(w, "in internal/lsm/btfprobe.go), not an audit-policy denial.")
		fmt.Fprintln(w, "Please report the failing hook name, your kernel version, and the output of:")
		fmt.Fprintln(w, "    bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A2 'bpf_lsm_'")

	case strings.Contains(msg, "probe LSM hook signatures"):
		fmt.Fprintln(w, "Could not read kernel BTF to choose the correct LSM program variant.")
		fmt.Fprintln(w, "Ensure /sys/kernel/btf/vmlinux is readable (CONFIG_DEBUG_INFO_BTF=y).")

	default:
		fmt.Fprintln(w, "Preflight passed but the kernel still refused the BPF load.")
		fmt.Fprintln(w, "This usually means SELinux/AppArmor denied bpf() — check audit.log.")
	}
}
