package lsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// On-wire event policy IDs. Must stay in sync with
// internal/lsm/bpf/common.bpf.h's enum cfm_lsm_policy_id.
const (
	bpfPolicyMemfdExec           uint32 = 1
	bpfPolicyReverseShell        uint32 = 3
	bpfPolicyDeletedFileExec     uint32 = 4
	bpfPolicySensitiveWrite      uint32 = 5
	bpfPolicyInterpreterNetStdio uint32 = 6
	bpfPolicyCredEscal           uint32 = 7
	bpfPolicyDirectCred          uint32 = 9
	bpfPolicyUnexpectedBPF       uint32 = 10
	bpfPolicyFdCredMismatch      uint32 = 11
	bpfPolicyEphemeralExec       uint32 = 12
	bpfPolicyPrivInstall         uint32 = 13
	bpfPolicyKernelModuleLoad    uint32 = 14
)

// On-wire FS operation byte for CFML-FS-005. Must stay in sync with
// internal/lsm/bpf/common.bpf.h's enum cfm_fs_op.
const (
	bpfFSOpNone       uint8 = 0
	bpfFSOpSetattr    uint8 = 1
	bpfFSOpCreate     uint8 = 2
	bpfFSOpUnlink     uint8 = 3
	bpfFSOpLink       uint8 = 4
	bpfFSOpRename     uint8 = 5
	bpfFSOpSetxattr   uint8 = 6
	bpfBPFOpMapCreate uint8 = 20
	bpfBPFOpProgLoad  uint8 = 21
	bpfKmodOpInit     uint8 = 30
	bpfKmodOpFinit    uint8 = 31
)

// FSOp is the Go-side label for the file-system operation that
// triggered a CFML-FS-005 event. Zero (FSOpNone) means "not an FS
// event" — non-FS policies always emit FSOpNone.
type FSOp uint8

const (
	FSOpNone       FSOp = 0
	FSOpSetattr    FSOp = 1
	FSOpCreate     FSOp = 2
	FSOpUnlink     FSOp = 3
	FSOpLink       FSOp = 4
	FSOpRename     FSOp = 5
	FSOpSetxattr   FSOp = 6
	BPFOpMapCreate FSOp = 20
	BPFOpProgLoad  FSOp = 21
	KmodOpInit     FSOp = 30
	KmodOpFinit    FSOp = 31
)

// String renders the operation as a short token suitable for logs
// and dmesg lines.
func (o FSOp) String() string {
	switch o {
	case FSOpSetattr:
		return "setattr"
	case FSOpCreate:
		return "create"
	case FSOpUnlink:
		return "unlink"
	case FSOpLink:
		return "link"
	case FSOpRename:
		return "rename"
	case FSOpSetxattr:
		return "setxattr"
	case BPFOpMapCreate:
		return "bpf_map_create"
	case BPFOpProgLoad:
		return "bpf_prog_load"
	case KmodOpInit:
		return "init_module"
	case KmodOpFinit:
		return "finit_module"
	}
	return "none"
}

// Sizes of the inline char arrays in the BPF event struct. Must stay
// in sync with CFM_TASK_COMM_LEN / CFM_FILENAME_LEN in common.bpf.h.
const (
	bpfTaskCommLen = 16
	bpfFilenameLen = 64
)

const (
	EventFlagWebOrigin            uint8 = 1 << 0
	EventFlagDirectCredInstall    uint8 = 1 << 1
	EventFlagUnlinkedInode        uint8 = 1 << 2
	EventFlagUnhashedDentry       uint8 = 1 << 3
	EventFlagRevshellStrict       uint8 = 1 << 4
	EventFlagInterpreterStdioWeak uint8 = 1 << 5
	EventFlagStdioOneRemote       uint8 = 1 << 6
	EventFlagStdioTwoRemote       uint8 = 1 << 7

	// EventFlagTmpfsBacked and EventFlagEphemeralDir distinguish how
	// CFML-EXEC-006 matched the execve. The two bits share numeric
	// values with the stdio-remote flags above; PolicyID disambiguates
	// per event. TmpfsBacked means the superblock magic was TMPFS_MAGIC
	// (/dev/shm, /run/user/, distro /tmp on tmpfs); EphemeralDir means
	// the dentry walk matched /tmp/ or /var/tmp/ on a non-tmpfs (EL9
	// default). Both bits may coexist if a future kernel exposes both
	// signals simultaneously.
	EventFlagTmpfsBacked  uint8 = 1 << 6
	EventFlagEphemeralDir uint8 = 1 << 7

	// CFML-FS-007 — which privilege primitive the watched uid was
	// installing. Bits 4-6 are reused from the stdio/EXEC-006 flag
	// bits at the same numeric positions; PolicyID disambiguates per
	// event. SUID and SGID may coexist on a single chmod 6755; FILECAP
	// is mutually exclusive with the chmod bits because it arrives
	// via a different LSM hook (setxattr).
	EventFlagPrivSUID    uint8 = 1 << 4
	EventFlagPrivSGID    uint8 = 1 << 5
	EventFlagPrivFileCap uint8 = 1 << 6
)

// Event is the Go-side projection of struct cfm_lsm_event emitted by
// the BPF programs over the ring buffer. The binary layout is
// position-fixed: any change to the struct on the BPF side requires
// a matching change here and a regeneration of the .o objects.
type Event struct {
	// TimestampNS is bpf_ktime_get_ns() at the moment of detection.
	// Monotonic clock; convert to wall time at the call site via the
	// known boot time if needed.
	TimestampNS uint64

	// PolicyID identifies which BPF policy emitted this event.
	PolicyID PolicyID

	// PID / TGID / UID / GID are the standard process identifiers
	// of the task whose action was intercepted.
	PID  uint32
	TGID uint32
	UID  uint32
	GID  uint32

	// Op identifies the specific FS operation for CFML-FS-005 events
	// (setattr / create / unlink / link / rename / setxattr).
	// FSOpNone for events from other policies.
	Op FSOp

	// Flags carries per-policy semantics. For CFML-FS-005 and
	// CFML-BPF-001, bit 0 means the match involved a web/panel-origin
	// uid or origin signal. For EXEC stdio detectors, bits 4-7 distinguish
	// strict all-three-fd reverse shells from weak one/two-fd interpreter
	// telemetry.
	Flags uint8

	// Comm is the task's 16-byte command name (TASK_COMM_LEN).
	Comm string

	// Filename is the policy-specific context payload. For
	// CFML-EXEC-001 this is the memfd's d_name. For CFML-EXEC-003
	// and CFML-EXEC-005 the binary being exec'd. For CFML-EXEC-004
	// this is the deleted/unlinked executable dentry name. For CFML-FS-005 the
	// watched file's name. For CFML-CRED-002 the offending executable's
	// name. For CFML-BPF-001 this is the bpf() command label.
	Filename string
}

// Time returns the event's timestamp converted to wall time relative
// to the provided boot time. Pass the host's boot time (read once at
// daemon start) to anchor the monotonic ts_ns value to UTC.
func (e Event) Time(bootTime time.Time) time.Time {
	return bootTime.Add(time.Duration(e.TimestampNS))
}

// PrivInstallPrimitive renders the CFML-FS-007 privilege primitive bits
// encoded in Event.Flags as a short token suitable for log lines.
// Returns empty for events from other policies (the same numeric bits
// belong to other detectors' flag fields — PolicyID disambiguates).
func (e Event) PrivInstallPrimitive() string {
	if e.PolicyID != PolicyPrivInstall {
		return ""
	}
	if e.Flags&EventFlagPrivFileCap != 0 {
		return "file_cap"
	}
	suid := e.Flags&EventFlagPrivSUID != 0
	sgid := e.Flags&EventFlagPrivSGID != 0
	switch {
	case suid && sgid:
		return "suid+sgid"
	case suid:
		return "suid"
	case sgid:
		return "sgid"
	}
	return ""
}

// ExecStdioSignal renders the EXEC-003/EXEC-005 stdio signal encoded in
// Event.Flags. Empty means the event is not from an exec stdio detector or
// carries no stdio signal bits.
//
// Gated on PolicyID because bits 4-7 are reused across detectors with
// different semantics: FS-007 uses the same numeric positions for
// PRIV_SUID / PRIV_SGID / PRIV_FILECAP, EXEC-006 for TMPFS_BACKED /
// EPHEMERAL_DIR. Without the gate, a FS-007 event with PRIV_SUID
// would be mis-rendered as a reverse-shell-strict stdio signal.
func (e Event) ExecStdioSignal() string {
	if e.PolicyID != PolicyReverseShell && e.PolicyID != PolicyInterpreterNetStdio {
		return ""
	}
	if e.Flags&EventFlagRevshellStrict != 0 {
		return "strict_all_stdio_remote"
	}
	if e.Flags&EventFlagInterpreterStdioWeak == 0 {
		return ""
	}
	if e.Flags&EventFlagStdioTwoRemote != 0 {
		return "weak_two_stdio_remote"
	}
	if e.Flags&EventFlagStdioOneRemote != 0 {
		return "weak_one_stdio_remote"
	}
	return "weak_stdio_remote"
}

// parseEvent decodes one ringbuf record into a Go Event. The wire
// format is:
//
//	offset  size  field
//	------  ----  -----
//	     0     8  ts_ns
//	     8     4  policy_id
//	    12     4  pid
//	    16     4  tgid
//	    20     4  uid
//	    24     4  gid
//	    28     1  op
//	    29     1  flags
//	    30     2  _pad
//	    32    16  comm
//	    48    64  filename
//	          --
//	         112 bytes
const wireEventSize = 8 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 2 + bpfTaskCommLen + bpfFilenameLen

func parseEvent(raw []byte) (Event, error) {
	if len(raw) < wireEventSize {
		return Event{}, fmt.Errorf("event truncated: got %d bytes, want at least %d", len(raw), wireEventSize)
	}
	var e Event
	be := binary.LittleEndian
	e.TimestampNS = be.Uint64(raw[0:8])
	policyID := be.Uint32(raw[8:12])
	e.PID = be.Uint32(raw[12:16])
	e.TGID = be.Uint32(raw[16:20])
	e.UID = be.Uint32(raw[20:24])
	e.GID = be.Uint32(raw[24:28])
	e.Op = FSOp(raw[28])
	e.Flags = raw[29]
	// raw[30:32] is _pad
	e.Comm = cstr(raw[32 : 32+bpfTaskCommLen])
	e.Filename = cstr(raw[48 : 48+bpfFilenameLen])

	switch policyID {
	case bpfPolicyMemfdExec:
		e.PolicyID = PolicyMemfdExec
	case bpfPolicyReverseShell:
		e.PolicyID = PolicyReverseShell
	case bpfPolicyDeletedFileExec:
		e.PolicyID = PolicyDeletedFileExec
	case bpfPolicyInterpreterNetStdio:
		e.PolicyID = PolicyInterpreterNetStdio
	case bpfPolicySensitiveWrite:
		e.PolicyID = PolicySensitiveWrite
	case bpfPolicyCredEscal:
		e.PolicyID = PolicyCredEscal
	case bpfPolicyDirectCred:
		e.PolicyID = PolicyDirectCredInstall
	case bpfPolicyUnexpectedBPF:
		e.PolicyID = PolicyUnexpectedBPF
	case bpfPolicyFdCredMismatch:
		e.PolicyID = PolicyFdCredMismatch
	case bpfPolicyEphemeralExec:
		e.PolicyID = PolicyEphemeralExec
	case bpfPolicyPrivInstall:
		e.PolicyID = PolicyPrivInstall
	case bpfPolicyKernelModuleLoad:
		e.PolicyID = PolicyKernelModuleLoad
	default:
		return Event{}, fmt.Errorf("unknown BPF policy_id %d", policyID)
	}
	return e, nil
}

// cstr trims trailing NULs and any garbage after the first NUL,
// matching the C convention used by bpf_get_current_comm and
// bpf_probe_read_kernel_str.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
