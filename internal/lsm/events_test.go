package lsm

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// buildWireEvent assembles a synthetic on-wire event matching the
// layout described in events.go's parseEvent doc comment. Used by
// every parser test so any layout drift surfaces in one place.
func buildWireEvent(t *testing.T, policyID, pid, tgid, uid, gid uint32, ts uint64, comm, filename string) []byte {
	t.Helper()
	buf := make([]byte, wireEventSize)
	le := binary.LittleEndian
	le.PutUint64(buf[0:8], ts)
	le.PutUint32(buf[8:12], policyID)
	le.PutUint32(buf[12:16], pid)
	le.PutUint32(buf[16:20], tgid)
	le.PutUint32(buf[20:24], uid)
	le.PutUint32(buf[24:28], gid)
	// buf[28:32] op + flags + pad stays zero
	copy(buf[32:32+bpfTaskCommLen], comm)
	copy(buf[48:48+bpfFilenameLen], filename)
	return buf
}

func TestParseEvent_MemfdExec(t *testing.T) {
	raw := buildWireEvent(t,
		bpfPolicyMemfdExec /* pid */, 12345 /* tgid */, 12345,
		/* uid */ 1001 /* gid */, 1001 /* ts */, 999_888_777,
		"php-fpm", "memfd:payload",
	)
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyMemfdExec {
		t.Errorf("PolicyID: got %q, want %q", ev.PolicyID, PolicyMemfdExec)
	}
	if ev.PID != 12345 {
		t.Errorf("PID: got %d, want 12345", ev.PID)
	}
	if ev.UID != 1001 {
		t.Errorf("UID: got %d, want 1001", ev.UID)
	}
	if ev.TimestampNS != 999_888_777 {
		t.Errorf("TimestampNS: got %d, want 999_888_777", ev.TimestampNS)
	}
	if ev.Comm != "php-fpm" {
		t.Errorf("Comm: got %q, want %q", ev.Comm, "php-fpm")
	}
	if ev.Filename != "memfd:payload" {
		t.Errorf("Filename: got %q, want %q", ev.Filename, "memfd:payload")
	}
}

func TestParseEvent_DeletedFileExec(t *testing.T) {
	raw := buildWireEvent(t,
		bpfPolicyDeletedFileExec, 222, 222, 1001, 1001, 123456,
		"php-fpm", "payload",
	)
	raw[29] = EventFlagUnlinkedInode | EventFlagUnhashedDentry

	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyDeletedFileExec {
		t.Errorf("PolicyID: got %q, want %q", ev.PolicyID, PolicyDeletedFileExec)
	}
	if ev.Flags&(EventFlagUnlinkedInode|EventFlagUnhashedDentry) == 0 {
		t.Errorf("Flags: got %#x, want deleted/unhashed bits", ev.Flags)
	}
	if ev.Filename != "payload" {
		t.Errorf("Filename: got %q, want payload", ev.Filename)
	}
}

func TestParseEvent_TrimsTrailingNUL(t *testing.T) {
	// Simulate what the BPF program actually writes: comm + NUL + garbage,
	// which is the standard kernel convention.
	raw := buildWireEvent(t,
		bpfPolicyMemfdExec, 1, 1, 0, 0, 0,
		"sh\x00garbage", "memfd:x\x00leftover",
	)
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.Comm != "sh" {
		t.Errorf("Comm: got %q, want %q (everything after NUL must be dropped)", ev.Comm, "sh")
	}
	if ev.Filename != "memfd:x" {
		t.Errorf("Filename: got %q, want %q (everything after NUL must be dropped)", ev.Filename, "memfd:x")
	}
}

func TestParseEvent_DirectCredInstall(t *testing.T) {
	raw := buildWireEvent(t, bpfPolicyDirectCred, 77, 77, 1000, 1000, 123, "exploit", "php-fpm")
	raw[29] = EventFlagDirectCredInstall
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyDirectCredInstall {
		t.Fatalf("PolicyID: got %q, want %q", ev.PolicyID, PolicyDirectCredInstall)
	}
	if ev.Flags&EventFlagDirectCredInstall == 0 {
		t.Fatalf("direct credential flag missing: flags=%08b", ev.Flags)
	}
}

func TestEventExecStdioSignal(t *testing.T) {
	cases := []struct {
		name  string
		flags uint8
		want  string
	}{
		{"strict", EventFlagRevshellStrict, "strict_all_stdio_remote"},
		{"weak two", EventFlagInterpreterStdioWeak | EventFlagStdioTwoRemote, "weak_two_stdio_remote"},
		{"weak one", EventFlagInterpreterStdioWeak | EventFlagStdioOneRemote, "weak_one_stdio_remote"},
		{"none", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Event{Flags: tc.flags}).ExecStdioSignal(); got != tc.want {
				t.Fatalf("ExecStdioSignal() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseEvent_InterpreterNetStdio(t *testing.T) {
	raw := buildWireEvent(t, bpfPolicyInterpreterNetStdio, 123, 123, 1001, 1001, 789, "bash", "/bin/bash")
	raw[29] = EventFlagInterpreterStdioWeak | EventFlagStdioTwoRemote

	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyInterpreterNetStdio {
		t.Fatalf("PolicyID: got %q, want %q", ev.PolicyID, PolicyInterpreterNetStdio)
	}
	if ev.Flags&(EventFlagInterpreterStdioWeak|EventFlagStdioTwoRemote) == 0 {
		t.Fatalf("Flags: got %#x, want weak two-remote bits", ev.Flags)
	}
}

func TestParseEvent_UnexpectedBPF(t *testing.T) {
	raw := buildWireEvent(t, bpfPolicyUnexpectedBPF, 4242, 4242, 1001, 1001, 456, "php-fpm", "BPF_PROG_LOAD")
	raw[28] = bpfBPFOpProgLoad
	raw[29] = EventFlagWebOrigin
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyUnexpectedBPF {
		t.Fatalf("PolicyID: got %q, want %q", ev.PolicyID, PolicyUnexpectedBPF)
	}
	if ev.Op != BPFOpProgLoad {
		t.Fatalf("Op: got %v, want BPFOpProgLoad", ev.Op)
	}
	if ev.Flags&EventFlagWebOrigin == 0 {
		t.Fatalf("web-origin flag missing: flags=%08b", ev.Flags)
	}
	if ev.Filename != "BPF_PROG_LOAD" {
		t.Fatalf("Filename: got %q, want BPF_PROG_LOAD", ev.Filename)
	}
}

func TestParseEvent_Truncated(t *testing.T) {
	raw := make([]byte, wireEventSize-1)
	_, err := parseEvent(raw)
	if err == nil {
		t.Fatal("expected error on truncated event")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error %q does not say truncated", err.Error())
	}
}

func TestParseEvent_UnknownPolicy(t *testing.T) {
	raw := buildWireEvent(t,
		/* unknown policy_id */ 999,
		1, 1, 0, 0, 0, "x", "y")
	_, err := parseEvent(raw)
	if err == nil {
		t.Fatal("expected error on unknown policy ID")
	}
	if !strings.Contains(err.Error(), "999") {
		t.Errorf("error %q should mention the bad policy_id", err.Error())
	}
}

func TestEvent_TimeAnchorsToBoot(t *testing.T) {
	boot := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	e := Event{TimestampNS: 5 * uint64(time.Second)}
	got := e.Time(boot)
	want := boot.Add(5 * time.Second)
	if !got.Equal(want) {
		t.Errorf("Time(boot): got %s, want %s", got, want)
	}
}

func TestPolicyByID_BPFConstantsMatchGoConstants(t *testing.T) {
	// Tripwire: the on-wire policy_id values are mirrored in two
	// places — here and in internal/lsm/bpf/common.bpf.h. If anyone
	// reorders the enum, this test fires and the lockstep is restored.
	if PolicyMemfdExec == "" {
		t.Fatal("PolicyMemfdExec is the empty string — was the constant accidentally removed?")
	}
	if PolicyReverseShell == "" {
		t.Fatal("PolicyReverseShell is the empty string — was the constant accidentally removed?")
	}
	if PolicyDeletedFileExec == "" {
		t.Fatal("PolicyDeletedFileExec is the empty string — was the constant accidentally removed?")
	}
	if bpfPolicyMemfdExec != 1 {
		t.Errorf("bpfPolicyMemfdExec mismatch: Go=%d, BPF=1 (see common.bpf.h)", bpfPolicyMemfdExec)
	}
	if bpfPolicyReverseShell != 3 {
		t.Errorf("bpfPolicyReverseShell mismatch: Go=%d, BPF=3 (see common.bpf.h)", bpfPolicyReverseShell)
	}
	if bpfPolicyDeletedFileExec != 4 {
		t.Errorf("bpfPolicyDeletedFileExec mismatch: Go=%d, BPF=4 (see common.bpf.h)", bpfPolicyDeletedFileExec)
	}
	if bpfPolicyCredEscal != 7 {
		t.Errorf("bpfPolicyCredEscal mismatch: Go=%d, BPF=7 (see common.bpf.h)", bpfPolicyCredEscal)
	}
	if bpfPolicyDirectCred != 9 {
		t.Errorf("bpfPolicyDirectCred mismatch: Go=%d, BPF=9 (see common.bpf.h)", bpfPolicyDirectCred)
	}
	if bpfPolicyInterpreterNetStdio != 6 {
		t.Errorf("bpfPolicyInterpreterNetStdio mismatch: Go=%d, BPF=6 (see common.bpf.h)", bpfPolicyInterpreterNetStdio)
	}
	if bpfPolicyUnexpectedBPF != 10 {
		t.Errorf("bpfPolicyUnexpectedBPF mismatch: Go=%d, BPF=10 (see common.bpf.h)", bpfPolicyUnexpectedBPF)
	}
}

func TestWireEventSize_Stable(t *testing.T) {
	// If this fires the BPF event struct changed shape; regenerate
	// the .o objects (go generate ./internal/lsm/...) AND update
	// parseEvent's offsets to match.
	const expected = 8 + 4 + 4 + 4 + 4 + 4 + 4 + 16 + 64
	if wireEventSize != expected {
		t.Errorf("wireEventSize drifted: got %d, want %d (BPF struct layout changed?)",
			wireEventSize, expected)
	}
}
