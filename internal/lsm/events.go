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
	bpfPolicyMemfdExec    uint32 = 1
	bpfPolicyReverseShell uint32 = 3
)

// Sizes of the inline char arrays in the BPF event struct. Must stay
// in sync with CFM_TASK_COMM_LEN / CFM_FILENAME_LEN in common.bpf.h.
const (
	bpfTaskCommLen = 16
	bpfFilenameLen = 64
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

	// PolicyID identifies which BPF policy emitted this event. For
	// the MVP only PolicyMemfdExec (CFML-EXEC-001) appears here.
	PolicyID PolicyID

	// PID / TGID / UID / GID are the standard process identifiers
	// of the task whose exec was intercepted.
	PID  uint32
	TGID uint32
	UID  uint32
	GID  uint32

	// Comm is the task's 16-byte command name (TASK_COMM_LEN).
	Comm string

	// Filename is the policy-specific context payload. For
	// CFML-EXEC-001 this is the memfd's d_name (typically the
	// "memfd:<label>" string the attacker passed to memfd_create).
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
//	    28     4  _pad
//	    32    16  comm
//	    48    64  filename
//	          --
//	         112 bytes
//
// (packed; no trailing padding because all fields are naturally
// aligned by the layout above.)
const wireEventSize = 8 + 4 + 4 + 4 + 4 + 4 + 4 + bpfTaskCommLen + bpfFilenameLen

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
	// raw[28:32] is _pad
	e.Comm = cstr(raw[32 : 32+bpfTaskCommLen])
	e.Filename = cstr(raw[48 : 48+bpfFilenameLen])

	switch policyID {
	case bpfPolicyMemfdExec:
		e.PolicyID = PolicyMemfdExec
	case bpfPolicyReverseShell:
		e.PolicyID = PolicyReverseShell
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
