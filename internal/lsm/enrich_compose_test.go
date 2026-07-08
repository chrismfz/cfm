//go:build linux

package lsm

import (
	"strings"
	"testing"
)

// TestComposeReasons_NotifyStableAcrossTargets is the flood-control
// guarantee: within one caller's burst (same pid/comm/exe) the notify
// reason must be byte-identical regardless of which target the event
// hit, so the notify deduper (keyed on Reason) collapses a whole
// /proc-sweep into a single email. The cfm.log line and the sample line
// must still differ per target so no forensic detail is lost.
func TestComposeReasons_NotifyStableAcrossTargets(t *testing.T) {
	enr := eventEnrichment{
		on: true,
		snap: procSnapshot{
			Alive: true, PID: 100, UID: 1234, User: "bob",
			Exe: "/tmp/.x/pgrep", SHA256: "abcdef0123456789aa", ParentExe: "/usr/sbin/cron",
		},
	}
	ev1 := Event{
		PolicyID: PolicyPtraceAccess, PID: 100, Comm: "pgrep", Filename: "systemd",
		Flags: EventFlagWebOrigin | EventFlagPtraceRead | EventFlagPtraceSameUid,
	}
	ev2 := ev1
	ev2.Filename = "sshd"

	l1, n1, s1 := composeReasons(ev1, enr)
	l2, n2, s2 := composeReasons(ev2, enr)

	if n1 != n2 {
		t.Errorf("notifyReason must be stable across targets:\n  %q\n  %q", n1, n2)
	}
	if strings.Contains(n1, "path=") || strings.Contains(n1, "pid=") {
		t.Errorf("notifyReason must exclude per-event target/pid (breaks dedup): %q", n1)
	}
	if l1 == l2 {
		t.Error("logReason must differ per target")
	}
	if s1[0] == s2[0] {
		t.Error("sample line must differ per target")
	}
	if !strings.Contains(l1, "path=systemd") {
		t.Errorf("logReason missing target: %q", l1)
	}
	for _, want := range []string{"exe=/tmp/.x/pgrep", "user=bob", "ptrace=read", "sameuid=1"} {
		if !strings.Contains(n1, want) {
			t.Errorf("notifyReason %q missing %q", n1, want)
		}
	}
	// The full exe path and caller tags belong in the cfm.log line too.
	if !strings.Contains(l1, "sha256=abcdef0123456789aa") {
		t.Errorf("logReason missing full sha256: %q", l1)
	}
}

// TestComposeReasons_RosterInSamples verifies the swarm roster and
// captured-binary references land in the email body (samples), not in
// the dedup-key reason.
func TestComposeReasons_RosterInSamples(t *testing.T) {
	enr := eventEnrichment{
		on:   true,
		snap: procSnapshot{Alive: true, PID: 100, UID: 1234, User: "bob", Exe: "/tmp/.x/loader"},
		roster: uidRoster{
			UID: 1234, Total: 2,
			Peers:      []peerProc{{PID: 100, Comm: "pgrep", Exe: "/tmp/.x/loader"}, {PID: 101, Comm: "systemd", Exe: "/tmp/.x/loader"}},
			Suspicious: []string{"/tmp/.x/loader"},
		},
		captured: []capturedFile{{Exe: "/tmp/.x/loader", Path: "/var/lib/cfm/lsm/capture/deadbeef.bin", SHA256: "deadbeef"}},
	}
	ev := Event{PolicyID: PolicyPtraceAccess, PID: 100, Comm: "pgrep", Filename: "systemd", Flags: EventFlagWebOrigin | EventFlagPtraceRead}

	logReason, notifyReason, samples := composeReasons(ev, enr)

	if !strings.Contains(logReason, "swarm=2procs") {
		t.Errorf("logReason missing swarm summary: %q", logReason)
	}
	if !strings.Contains(logReason, "captured=/var/lib/cfm/lsm/capture/deadbeef.bin") {
		t.Errorf("logReason missing captured path: %q", logReason)
	}
	joined := strings.Join(samples, "\n")
	if !strings.Contains(joined, "peer pid=101 comm=systemd") {
		t.Errorf("samples missing roster peer:\n%s", joined)
	}
	if !strings.Contains(joined, "captured binary: /var/lib/cfm/lsm/capture/deadbeef.bin") {
		t.Errorf("samples missing captured binary:\n%s", joined)
	}
	// Volatile roster/capture detail must NOT be in the dedup reason.
	if strings.Contains(notifyReason, "swarm=") || strings.Contains(notifyReason, "captured=") {
		t.Errorf("notifyReason must not carry roster/capture detail: %q", notifyReason)
	}
}
