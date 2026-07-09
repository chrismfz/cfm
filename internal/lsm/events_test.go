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
		name   string
		policy PolicyID
		flags  uint8
		want   string
	}{
		{"strict", PolicyReverseShell, EventFlagRevshellStrict, "strict_all_stdio_remote"},
		{"weak two", PolicyInterpreterNetStdio, EventFlagInterpreterStdioWeak | EventFlagStdioTwoRemote, "weak_two_stdio_remote"},
		{"weak one", PolicyInterpreterNetStdio, EventFlagInterpreterStdioWeak | EventFlagStdioOneRemote, "weak_one_stdio_remote"},
		{"none", PolicyReverseShell, 0, ""},
		// PolicyID gating: same numeric flag bits are reused by FS-007
		// (PRIV_SUID at bit 4 collides with REVSHELL_STRICT). The
		// renderer must return "" when called on a non-exec-stdio
		// policy regardless of flag bits set.
		{"fs007 not misrendered", PolicyPrivInstall, EventFlagPrivSUID, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Event{PolicyID: tc.policy, Flags: tc.flags}).ExecStdioSignal(); got != tc.want {
				t.Fatalf("ExecStdioSignal() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEventPrivInstallPrimitive(t *testing.T) {
	cases := []struct {
		name   string
		policy PolicyID
		flags  uint8
		want   string
	}{
		{"file_cap", PolicyPrivInstall, EventFlagPrivFileCap, "file_cap"},
		{"suid", PolicyPrivInstall, EventFlagPrivSUID, "suid"},
		{"sgid", PolicyPrivInstall, EventFlagPrivSGID, "sgid"},
		{"suid+sgid", PolicyPrivInstall, EventFlagPrivSUID | EventFlagPrivSGID, "suid+sgid"},
		{"none flags", PolicyPrivInstall, 0, ""},
		// PolicyID gating: a reverse-shell event with REVSHELL_STRICT
		// at bit 4 must not be rendered as "suid".
		{"revshell not misrendered", PolicyReverseShell, EventFlagRevshellStrict, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Event{PolicyID: tc.policy, Flags: tc.flags}).PrivInstallPrimitive(); got != tc.want {
				t.Fatalf("PrivInstallPrimitive() = %q, want %q", got, tc.want)
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

func TestParseEvent_FdCredMismatch(t *testing.T) {
	// Synthesise a CFML-FS-006 event: non-root attacker pid 9999 (uid
	// 1000, common DirectAdmin/cPanel hosting uid) reading /etc/shadow
	// through a fd that was opened in a root context (the setuid-helper
	// fd-leak primitive). No op byte (FS-006 doesn't carry one);
	// filename is the watched inode's dentry name.
	raw := buildWireEvent(t, bpfPolicyFdCredMismatch, 9999, 9999, 1000, 1000, 700, "chage_pwn", "shadow")
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyFdCredMismatch {
		t.Fatalf("PolicyID: got %q, want %q", ev.PolicyID, PolicyFdCredMismatch)
	}
	if ev.UID != 1000 {
		t.Errorf("UID: got %d, want 1000 (non-root attacker)", ev.UID)
	}
	if ev.Op != FSOpNone {
		t.Errorf("Op: got %v, want FSOpNone (FS-006 doesn't use op)", ev.Op)
	}
	if ev.Comm != "chage_pwn" {
		t.Errorf("Comm: got %q, want chage_pwn", ev.Comm)
	}
	if ev.Filename != "shadow" {
		t.Errorf("Filename: got %q, want shadow", ev.Filename)
	}
}

func TestParseEvent_Truncated(t *testing.T) {
	// Below the base record floor must error...
	raw := make([]byte, wireEventBaseSize-1)
	_, err := parseEvent(raw)
	if err == nil {
		t.Fatal("expected error on truncated event")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error %q does not say truncated", err.Error())
	}
	// ...but a pre-Tier-B 112-byte record must parse (tail fields zero).
	base := make([]byte, wireEventBaseSize)
	binary.LittleEndian.PutUint32(base[8:12], bpfPolicyMemfdExec)
	ev, err := parseEvent(base)
	if err != nil {
		t.Fatalf("base-size record must parse: %v", err)
	}
	if ev.PPid != 0 || ev.AuxPID != 0 || ev.AuxUID != 0 {
		t.Errorf("pre-Tier-B record must leave tail zero, got ppid=%d aux=%d/%d", ev.PPid, ev.AuxPID, ev.AuxUID)
	}
}

func TestParseEvent_TierBTail(t *testing.T) {
	raw := make([]byte, wireEventSize)
	le := binary.LittleEndian
	le.PutUint32(raw[8:12], bpfPolicyPtraceAccess)
	le.PutUint32(raw[12:16], 100) // caller pid
	le.PutUint32(raw[112:116], 999)
	le.PutUint32(raw[116:120], 4242) // target pid
	le.PutUint32(raw[120:124], 0)    // target uid (root)
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PPid != 999 {
		t.Errorf("PPid = %d, want 999", ev.PPid)
	}
	tpid, tuid, ok := ev.PtraceTarget()
	if !ok || tpid != 4242 || tuid != 0 {
		t.Errorf("PtraceTarget = (%d,%d,%v), want (4242,0,true)", tpid, tuid, ok)
	}
	// A non-OBS-004 policy must not expose a ptrace target even if aux is set.
	raw2 := make([]byte, wireEventSize)
	le.PutUint32(raw2[8:12], bpfPolicySensitiveWrite)
	le.PutUint32(raw2[116:120], 5)
	ev2, _ := parseEvent(raw2)
	if _, _, ok := ev2.PtraceTarget(); ok {
		t.Error("non-OBS-004 event must not report a ptrace target")
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
	if bpfPolicyFdCredMismatch != 11 {
		t.Errorf("bpfPolicyFdCredMismatch mismatch: Go=%d, BPF=11 (see common.bpf.h)", bpfPolicyFdCredMismatch)
	}
	if bpfPolicyEphemeralExec != 12 {
		t.Errorf("bpfPolicyEphemeralExec mismatch: Go=%d, BPF=12 (see common.bpf.h)", bpfPolicyEphemeralExec)
	}
	if PolicyEphemeralExec == "" {
		t.Fatal("PolicyEphemeralExec is the empty string — was the constant accidentally removed?")
	}
}

func TestParseEvent_EphemeralExec(t *testing.T) {
	// Tmpfs-backed match: a web user (uid 1001) execs /tmp/.payload
	// where /tmp is mounted as tmpfs.
	raw := buildWireEvent(t, bpfPolicyEphemeralExec, 4242, 4242, 1001, 1001, 555,
		"php-fpm", "/tmp/.payload")
	raw[29] = EventFlagTmpfsBacked
	ev, err := parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyEphemeralExec {
		t.Errorf("PolicyID: got %q, want %q", ev.PolicyID, PolicyEphemeralExec)
	}
	if ev.UID != 1001 {
		t.Errorf("UID: got %d, want 1001 (web-class uid)", ev.UID)
	}
	if ev.Flags&EventFlagTmpfsBacked == 0 {
		t.Errorf("Flags: got %#x, want CFM_LSM_F_TMPFS_BACKED bit set", ev.Flags)
	}
	if ev.Filename != "/tmp/.payload" {
		t.Errorf("Filename: got %q, want /tmp/.payload", ev.Filename)
	}

	// Non-tmpfs /tmp (EL9 default): the dentry-walk branch fires,
	// setting the EphemeralDir bit instead.
	raw = buildWireEvent(t, bpfPolicyEphemeralExec, 9090, 9090, 1100, 1100, 666,
		"httpd", "/var/tmp/staged")
	raw[29] = EventFlagEphemeralDir
	ev, err = parseEvent(raw)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.PolicyID != PolicyEphemeralExec {
		t.Errorf("PolicyID: got %q, want %q", ev.PolicyID, PolicyEphemeralExec)
	}
	if ev.Flags&EventFlagEphemeralDir == 0 {
		t.Errorf("Flags: got %#x, want CFM_LSM_F_EPHEMERAL_DIR bit set", ev.Flags)
	}
}

func TestWireEventSize_Stable(t *testing.T) {
	// If this fires the BPF event struct changed shape; regenerate
	// the .o objects (go generate ./internal/lsm/...) AND update
	// parseEvent's offsets to match.
	// 112-byte base (ts/policy/pid/tgid/uid/gid + op/flags/_pad + comm +
	// filename) plus the 12-byte Tier B tail: ppid + aux_pid + aux_uid.
	const expected = 8 + 4 + 4 + 4 + 4 + 4 + 4 + 16 + 64 + 4 + 4 + 4
	if wireEventSize != expected {
		t.Errorf("wireEventSize drifted: got %d, want %d (BPF struct layout changed?)",
			wireEventSize, expected)
	}
}
