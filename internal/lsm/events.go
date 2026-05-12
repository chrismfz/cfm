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
	bpfPolicyMemfdExec      uint32 = 1
	bpfPolicyReverseShell   uint32 = 3
	bpfPolicySensitiveWrite uint32 = 5
	bpfPolicyCredEscal      uint32 = 7
	bpfPolicyDirectCred     uint32 = 9
)

// On-wire FS operation byte for CFML-FS-005. Must stay in sync with
// internal/lsm/bpf/common.bpf.h's enum cfm_fs_op.
const (
	bpfFSOpNone     uint8 = 0
	bpfFSOpSetattr  uint8 = 1
	bpfFSOpCreate   uint8 = 2
	bpfFSOpUnlink   uint8 = 3
	bpfFSOpLink     uint8 = 4
	bpfFSOpRename   uint8 = 5
	bpfFSOpSetxattr uint8 = 6
)

// FSOp is the Go-side label for the file-system operation that
// triggered a CFML-FS-005 event. Zero (FSOpNone) means "not an FS
// event" — non-FS policies always emit FSOpNone.
type FSOp uint8

const (
	FSOpNone     FSOp = 0
	FSOpSetattr  FSOp = 1
	FSOpCreate   FSOp = 2
	FSOpUnlink   FSOp = 3
	FSOpLink     FSOp = 4
	FSOpRename   FSOp = 5
	FSOpSetxattr FSOp = 6
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
	EventFlagWebOrigin         uint8 = 1 << 0
	EventFlagDirectCredInstall uint8 = 1 << 1
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

	// Flags carries per-policy semantics. For CFML-FS-005, bit 0
	// means the match came from web-origin tracking after the current
	// uid was no longer watched.
	Flags uint8

	// Comm is the task's 16-byte command name (TASK_COMM_LEN).
	Comm string

	// Filename is the policy-specific context payload. For
	// CFML-EXEC-001 this is the memfd's d_name. For CFML-EXEC-003
	// the binary being exec'd. For CFML-FS-005 the watched file's
	// name. For CFML-CRED-002 the offending executable's name.
	Filename string
}

// Time returns the event's timestamp converted to wall time relative
// to the provided boot time. Pass the host's boot time (read once at
// daemon start) to anchor the monotonic ts_ns value to UTC.
func (e Event) Time(bootTime time.Time) time.Time {
	return bootTime.Add(time.Duration(e.TimestampNS))
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
	case bpfPolicySensitiveWrite:
		e.PolicyID = PolicySensitiveWrite
	case bpfPolicyCredEscal:
		e.PolicyID = PolicyCredEscal
	case bpfPolicyDirectCred:
		e.PolicyID = PolicyDirectCredInstall
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
