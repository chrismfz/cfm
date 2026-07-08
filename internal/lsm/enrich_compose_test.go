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
		PolicyID: PolicyPtraceAccess, PID: 100, UID: 1234, Comm: "pgrep", Filename: "systemd",
		Flags: EventFlagWebOrigin | EventFlagPtraceRead | EventFlagPtraceSameUid,
	}
	ev2 := ev1
	ev2.Filename = "sshd"

	// ev2 differs in BOTH the target AND the sameuid relationship — a real
	// sweep touches same-uid and cross-uid targets — to prove neither the
	// target nor the per-target ptrace/sameuid tags leak into the dedup key.
	ev2.Flags = EventFlagWebOrigin | EventFlagPtraceRead // sameuid cleared

	l1, n1, s1 := composeReasons(ev1, enr)
	l2, n2, s2 := composeReasons(ev2, enr)

	if n1 != n2 {
		t.Errorf("notifyReason must be stable across targets AND sameuid relationship:\n  %q\n  %q", n1, n2)
	}
	for _, bad := range []string{"path=", "pid=", "ptrace=", "sameuid="} {
		if strings.Contains(n1, bad) {
			t.Errorf("notifyReason must exclude per-target/relationship field %q (breaks dedup): %q", bad, n1)
		}
	}
	if l1 == l2 {
		t.Error("logReason must differ per target")
	}
	if s1[0] == s2[0] {
		t.Error("sample line must differ per target")
	}
	if !strings.Contains(l1, "path=systemd") || !strings.Contains(l1, "sameuid=1") {
		t.Errorf("logReason missing per-event detail: %q", l1)
	}
	// notifyReason carries caller IDENTITY (uid always, plus enrichment).
	for _, want := range []string{"uid=1234", "comm=pgrep", "exe=/tmp/.x/pgrep", "user=bob"} {
		if !strings.Contains(n1, want) {
			t.Errorf("notifyReason %q missing %q", n1, want)
		}
	}
	// The per-target ptrace detail lives in the sample line, not the reason.
	if !strings.Contains(s1[0], "ptrace=read") || !strings.Contains(s1[0], "sameuid=1") {
		t.Errorf("sample line missing per-target ptrace detail: %q", s1[0])
	}
	if !strings.Contains(l1, "sha256=abcdef0123456789aa") {
		t.Errorf("logReason missing full sha256: %q", l1)
	}
}

// TestComposeReasons_DiscretePolicyKeepsTarget verifies that a non-sweep
// policy (FS-005) keeps the target in the notify reason, so distinct
// sensitive-file writes remain distinct emails and the notify JSONL audit
// keeps the target — i.e. the collapse is scoped to sweep-class policies.
func TestComposeReasons_DiscretePolicyKeepsTarget(t *testing.T) {
	enr := eventEnrichment{on: true, snap: procSnapshot{Alive: true, PID: 50, UID: 1234, User: "bob", Exe: "/usr/bin/php"}}
	ev1 := Event{PolicyID: PolicySensitiveWrite, PID: 50, Comm: "php-fpm", Filename: "/etc/shadow", Op: FSOpSetattr, Flags: EventFlagWebOrigin}
	ev2 := ev1
	ev2.Filename = "/etc/passwd"

	_, n1, _ := composeReasons(ev1, enr)
	_, n2, _ := composeReasons(ev2, enr)

	if n1 == n2 {
		t.Errorf("discrete-policy notifyReason must differ per target (distinct emails):\n  %q\n  %q", n1, n2)
	}
	if !strings.Contains(n1, "path=/etc/shadow") {
		t.Errorf("discrete-policy notifyReason must keep the target: %q", n1)
	}
}

// TestComposeReasons_StripsControlChars guards against log/email injection
// via an attacker-chosen exe path containing a newline.
func TestComposeReasons_StripsControlChars(t *testing.T) {
	enr := eventEnrichment{on: true, snap: procSnapshot{Alive: true, PID: 7, UID: 1234, Exe: "/tmp/x\n[lsm] FORGED policy=CFML-CRED-002"}}
	ev := Event{PolicyID: PolicyPtraceAccess, PID: 7, Comm: "x\nFORGED", Filename: "sys\ntemd", Flags: EventFlagWebOrigin}
	logReason, notifyReason, samples := composeReasons(ev, enr)
	for _, s := range append([]string{logReason, notifyReason}, samples...) {
		if strings.ContainsAny(s, "\n\r") {
			t.Errorf("control char survived sanitization: %q", s)
		}
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
