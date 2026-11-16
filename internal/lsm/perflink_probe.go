package lsm

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Pinnable tracepoint links.
//
// CFML-BPF-001, CFML-EXEC-007 and CFML-EXEC-008 attach to syscall
// tracepoints (link.Tracepoint). cilium/ebpf attaches those through a
// BPF_LINK_TYPE_PERF_EVENT link when the kernel has one (upstream 5.15;
// EL9's 5.14 backports it) and otherwise falls back to the legacy
// PERF_EVENT_IOC_SET_BPF ioctl. The ioctl "link" cannot be pinned to
// bpffs (`perf event ioctl pin: not supported`), and every enable path
// pins (the daemon adopts the pins across restarts, the CLI exits after
// enabling). So on a kernel without perf links — CloudLinux 8's lve 4.18 —
// the pin of the first tracepoint link failed the WHOLE load and the host
// ran no cfm-lsm policy at all (fleet: earth/mars/orion/virgo, retrying
// every 30 min). The fix reports these three policies as unavailable, as
// CRED-002/003 already are there, and loads the rest.

// tracepointPolicies are the policies whose programs attach only to
// tracepoints. Keep in sync with programsFor (tracepointProgramEntry*).
var tracepointPolicies = []PolicyID{PolicyUnexpectedBPF, PolicyKernelModuleLoad, PolicyKexecLoad}

func isTracepointPolicy(id PolicyID) bool {
	for _, p := range tracepointPolicies {
		if p == id {
			return true
		}
	}
	return false
}

// perfLinkUnavailableReason is the PolicyAvailability / attach-failure
// reason for a tracepoint policy on a kernel without perf links.
const perfLinkUnavailableReason = "kernel lacks BPF perf-event links (BPF_LINK_TYPE_PERF_EVENT, upstream 5.15) — e.g. CloudLinux 8 lve 4.18; a tracepoint attach cannot be pinned, so this policy is skipped and the rest of cfm-lsm loads"

// preflightPerfLinkProbe reports whether the kernel supports
// BPF_LINK_TYPE_PERF_EVENT. nil = supported, an error wrapping
// ebpf.ErrNotSupported = not supported, any other error = inconclusive
// (treated as available; the loader's pin is then the final word).
// Declared as a var so tests can stub it without a syscall.
var preflightPerfLinkProbe = probePerfEventLink

// bpfAttrLinkCreatePerfEvent is the BPF_LINK_CREATE prefix of union
// bpf_attr used for a perf_event link (prog_fd, target_fd, attach_type,
// flags, perf_event.bpf_cookie).
type bpfAttrLinkCreatePerfEvent struct {
	progFD     uint32
	targetFD   uint32
	attachType uint32
	flags      uint32
	bpfCookie  uint64
}

const (
	bpfCmdLinkCreate  = 28 // BPF_LINK_CREATE
	bpfAttachPerfEvnt = 41 // BPF_PERF_EVENT
)

// probePerfEventLink mirrors cilium/ebpf's internal haveBPFLinkPerfEvent
// (not exported in v0.22): load a trivial kprobe program and ask for a
// BPF_PERF_EVENT link against fd 0, which is not a perf event. A kernel
// that knows the attach type gets as far as resolving the target and
// returns EBADF; one that does not rejects the attach type with EINVAL.
func probePerfEventLink() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "cfm_probe_pflnk",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		return fmt.Errorf("load probe program: %w", err)
	}
	defer prog.Close()

	attr := bpfAttrLinkCreatePerfEvent{
		progFD:     uint32(prog.FD()),
		attachType: bpfAttachPerfEvnt,
	}
	r, _, errno := unix.Syscall(unix.SYS_BPF, bpfCmdLinkCreate,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno == 0 {
		// Unexpected: fd 0 accepted as a perf event. It is a link we
		// own either way; close it and call the feature present.
		_ = unix.Close(int(r))
		return nil
	}
	switch {
	case errors.Is(errno, unix.EBADF):
		return nil
	case errors.Is(errno, unix.EINVAL):
		return fmt.Errorf("BPF_LINK_CREATE BPF_PERF_EVENT: %w", ebpf.ErrNotSupported)
	default:
		return fmt.Errorf("BPF_LINK_CREATE BPF_PERF_EVENT: %w", errno)
	}
}

// perfLinkUnsupported is true only for a definite "not supported".
func perfLinkUnsupported() bool {
	return errors.Is(preflightPerfLinkProbe(), ebpf.ErrNotSupported)
}

// applyPerfLinkAvailability marks the tracepoint policies unavailable
// when the kernel has no perf links. An entry that is already
// unavailable (e.g. EXEC-008 with no kexec tracepoints) keeps its own
// reason.
func applyPerfLinkAvailability(pas []PolicyAvailability) []PolicyAvailability {
	if !perfLinkUnsupported() {
		return pas
	}
	seen := map[PolicyID]bool{}
	for i := range pas {
		if !isTracepointPolicy(pas[i].PolicyID) {
			continue
		}
		seen[pas[i].PolicyID] = true
		if pas[i].Available {
			pas[i].Available = false
			pas[i].Reason = perfLinkUnavailableReason
		}
	}
	for _, id := range tracepointPolicies {
		if !seen[id] {
			pas = append(pas, PolicyAvailability{PolicyID: id, Reason: perfLinkUnavailableReason})
		}
	}
	return pas
}
