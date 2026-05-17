package lsm

import (
	"strings"
	"testing"
)

// TestEventFilter_Defaults_BPF001 covers the BPF-001 container-runtime
// allowlist. dmesg lines from a mailcow / Docker host show runc and
// containerd-shim spamming bpf_prog_load + bpf_map_create on every
// container start; the BPF side already suppresses systemd-class
// agents, so the userspace filter has to cover the runtime layer.
func TestEventFilter_Defaults_BPF001(t *testing.T) {
	f := BuildEventFilter(DefaultConf())
	for _, comm := range []string{"runc", "containerd-shim", "dockerd", "podman", "conmon"} {
		ev := Event{PolicyID: PolicyUnexpectedBPF, Comm: comm, Filename: "BPF_PROG_LOAD"}
		if !f.Match(ev) {
			t.Errorf("expected default conf to suppress BPF-001 comm=%q", comm)
		}
	}
	// Unknown comm should NOT be suppressed — the detector still
	// reports the long tail of webshell / kernel-exploit BPF use.
	ev := Event{PolicyID: PolicyUnexpectedBPF, Comm: "webshell.php", Filename: "BPF_PROG_LOAD"}
	if f.Match(ev) {
		t.Errorf("default conf incorrectly suppressed comm=%q", ev.Comm)
	}
}

// TestEventFilter_Defaults_CRED002 covers the per-daemon basename
// allowlist (sshd-session, postfix master, dovecot indexer-worker,
// systemd-executor). CRED-002 emits the exe d_name in Filename, so
// the filter matches on filepath.Base of that field.
func TestEventFilter_Defaults_CRED002(t *testing.T) {
	f := BuildEventFilter(DefaultConf())
	for _, name := range []string{"sshd-session", "master", "indexer-worker", "systemd-executor"} {
		ev := Event{PolicyID: PolicyCredEscal, Filename: name, Comm: "irrelevant"}
		if !f.Match(ev) {
			t.Errorf("expected default conf to suppress CRED-002 exe=%q", name)
		}
	}
	// A genuinely unknown exe must still fire so the operator hears
	// about it.
	ev := Event{PolicyID: PolicyCredEscal, Filename: "kernel_exploit_payload"}
	if f.Match(ev) {
		t.Errorf("default conf incorrectly suppressed exe=%q", ev.Filename)
	}
}

// TestEventFilter_Defaults_EXEC003 covers the strict reverse-shell
// detector. `logger` is the canonical postfix spawn(8) callee; the
// rest of the spawn-helper inventory is site-specific and arrives
// via allow_exe.
func TestEventFilter_Defaults_EXEC003(t *testing.T) {
	f := BuildEventFilter(DefaultConf())
	ev := Event{PolicyID: PolicyReverseShell, Filename: "/usr/bin/logger", Flags: EventFlagRevshellStrict}
	if !f.Match(ev) {
		t.Fatalf("expected default conf to suppress EXEC-003 logger exec")
	}
	// A real reverse-shell exec (bash with TCP stdio) must still
	// reach notify/kmsg.
	ev = Event{PolicyID: PolicyReverseShell, Filename: "/bin/bash", Flags: EventFlagRevshellStrict}
	if f.Match(ev) {
		t.Fatalf("default conf incorrectly suppressed /bin/bash")
	}
}

// TestEventFilter_NilConf_NoSuppression documents the contract that a
// nil conf means "report everything". An operator who runs cfm without
// /etc/cfm/lsm.conf at all (and without going through DefaultConf via
// LoadConf) should see every event reach notify/log/kmsg.
func TestEventFilter_NilConf_NoSuppression(t *testing.T) {
	f := BuildEventFilter(nil)
	for _, ev := range []Event{
		{PolicyID: PolicyUnexpectedBPF, Comm: "runc"},
		{PolicyID: PolicyCredEscal, Filename: "sshd-session"},
		{PolicyID: PolicyReverseShell, Filename: "/usr/bin/logger"},
	} {
		if f.Match(ev) {
			t.Errorf("nil conf must not suppress %+v", ev)
		}
	}
}

// TestEventFilter_ConfAllowExe verifies that an operator-supplied
// allow_exe under EXEC-003 narrows the strict reverse-shell detector
// by basename. The mailcow example: a site-specific spawn-helper
// script lives under /usr/local/bin/ and is otherwise indistinguishable
// from a reverse shell at bprm_check time.
func TestEventFilter_ConfAllowExe(t *testing.T) {
	body := `
[policy "CFML-EXEC-003"]
mode = monitor
allow_exe = /usr/local/bin/whitelist_forwardinghosts.sh
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	f := BuildEventFilter(c)
	ev := Event{PolicyID: PolicyReverseShell, Filename: "/usr/local/bin/whitelist_forwardinghosts.sh", Flags: EventFlagRevshellStrict}
	if !f.Match(ev) {
		t.Fatalf("expected operator allow_exe to suppress %s", ev.Filename)
	}
}

// TestEventFilter_ConfAllowComm verifies operator-supplied allow_comm
// for BPF-001 (custom orchestrator not in the default container-runtime
// list).
func TestEventFilter_ConfAllowComm(t *testing.T) {
	body := `
[policy "CFML-BPF-001"]
mode = monitor
allow_comm = my-orchestrator
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	f := BuildEventFilter(c)
	ev := Event{PolicyID: PolicyUnexpectedBPF, Comm: "my-orchestrator", Filename: "BPF_PROG_LOAD"}
	if !f.Match(ev) {
		t.Fatalf("expected operator allow_comm to suppress comm=%q", ev.Comm)
	}
}

// TestEventFilter_NilSafe documents that a nil filter (no daemon
// installed yet) is the "report everything" mode rather than a crash.
func TestEventFilter_NilSafe(t *testing.T) {
	var f *EventFilter
	if f.Match(Event{PolicyID: PolicyCredEscal, Filename: "sshd-session"}) {
		t.Fatalf("nil filter must not match")
	}
	if shouldSuppressEvent(Event{PolicyID: PolicyCredEscal, Filename: "sshd-session"}) {
		// defaultEventFilter starts nil in tests until SetEventFilter
		// is called; that path is supposed to pass everything through.
		t.Fatalf("global filter must default to no suppression")
	}
}

// TestParseConf_AllowComm exercises the new top-level allow_comm
// key. It is rejected on policies that do not consume comm-based
// allowlists (FS-005 has no need; future detectors can opt in via
// allowCommPolicy).
func TestParseConf_AllowComm(t *testing.T) {
	body := `
[policy "CFML-BPF-001"]
mode = monitor
allow_comm = my-orchestrator
allow_comm = vendor-agent
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	got := c.AllowCommFor(PolicyUnexpectedBPF)
	want := []string{"my-orchestrator", "vendor-agent"}
	if len(got) != len(want) {
		t.Fatalf("allow_comm count: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("allow_comm[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseConf_AllowCommErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "wrong policy",
			body: "[policy \"CFML-FS-005\"]\nallow_comm = whatever\n",
			want: "allow_comm is only valid",
		},
		{
			name: "exceeds 15 chars",
			body: "[policy \"CFML-BPF-001\"]\nallow_comm = this-is-too-long-for-comm\n",
			want: "exceeds 15 chars",
		},
		{
			name: "empty",
			body: "[policy \"CFML-BPF-001\"]\nallow_comm =\n",
			want: "non-empty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConf(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestParseConf_GlobalAllow exercises the new [allow] section which
// fans out to every policy that consumes an exe / comm allowlist.
// Operators get a single place to maintain the universal allowlist
// instead of duplicating it under each policy header.
func TestParseConf_GlobalAllow(t *testing.T) {
	body := `
[allow]
allow_exe = /usr/sbin/sshd
allow_exe = /usr/lib/postfix/sbin/master
allow_comm = runc
allow_comm = containerd-shim
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	wantExe := []string{"/usr/sbin/sshd", "/usr/lib/postfix/sbin/master"}
	if got := c.GlobalAllowExe; len(got) != len(wantExe) {
		t.Fatalf("GlobalAllowExe: got %v, want %v", got, wantExe)
	}
	wantComm := []string{"runc", "containerd-shim"}
	if got := c.GlobalAllowComm; len(got) != len(wantComm) {
		t.Fatalf("GlobalAllowComm: got %v, want %v", got, wantComm)
	}

	// Fanout: every policy that consumes the allowlist sees the
	// global entries via the accessor.
	for _, id := range []PolicyID{PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio} {
		eff := c.AllowExeFor(id)
		if len(eff) != len(wantExe) {
			t.Errorf("AllowExeFor(%s): got %d entries (%v), want %d (%v)", id, len(eff), eff, len(wantExe), wantExe)
		}
	}
	for _, id := range []PolicyID{PolicyUnexpectedBPF, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio} {
		eff := c.AllowCommFor(id)
		if len(eff) != len(wantComm) {
			t.Errorf("AllowCommFor(%s): got %d (%v), want %d (%v)", id, len(eff), eff, len(wantComm), wantComm)
		}
	}
	// FS-005 should NOT see them — it doesn't consume an exe/comm
	// allowlist today, and silent fanout there would be surprising.
	if got := c.AllowExeFor(PolicySensitiveWrite); len(got) != 0 {
		t.Errorf("AllowExeFor(FS-005) should be empty, got %v", got)
	}
	if got := c.AllowCommFor(PolicySensitiveWrite); len(got) != 0 {
		t.Errorf("AllowCommFor(FS-005) should be empty, got %v", got)
	}
}

// TestParseConf_GlobalAllow_DuplicateSection rejects two [allow]
// blocks the way two [kmsg] blocks are rejected — a duplicate section
// usually means a manual merge artifact and silently dropping the
// second is exactly the kind of behaviour a security tool must not
// have.
func TestParseConf_GlobalAllow_DuplicateSection(t *testing.T) {
	body := `
[allow]
allow_exe = /usr/sbin/sshd

[allow]
allow_exe = /usr/sbin/postfix
`
	_, err := ParseConf(strings.NewReader(body))
	if err == nil {
		t.Fatalf("expected duplicate [allow] section to error")
	}
	if !strings.Contains(err.Error(), "duplicate [allow]") {
		t.Fatalf("error message %q does not mention duplicate [allow]", err.Error())
	}
}

// TestDefaultConf_GlobalAllowSeeded documents the contract that the
// shipped configs/lsm.conf template (and the in-memory DefaultConf()
// used for FormatConf round-trips and external bootstrappers) carries
// a ready-to-use allowlist covering the universal false-positive
// surface (postfix, dovecot, sshd, systemd privsep helpers, container
// runtimes).
func TestDefaultConf_GlobalAllowSeeded(t *testing.T) {
	c := DefaultConf()
	if len(c.GlobalAllowExe) == 0 {
		t.Fatal("DefaultConf().GlobalAllowExe should be seeded with cross-distro defaults")
	}
	if len(c.GlobalAllowComm) == 0 {
		t.Fatal("DefaultConf().GlobalAllowComm should be seeded with container-runtime defaults")
	}

	// Spot-check a few canonical entries.
	wantExe := []string{
		"/usr/lib/postfix/sbin/master",
		"/usr/lib/dovecot/indexer-worker",
		"/usr/bin/logger",
		"/usr/sbin/logrotate",
		// CloudLinux / cPanel / SpamAssassin entries — see the
		// CageFS / cpsrvd / dccproc categories in DefaultGlobalAllowExe.
		"/usr/sbin/cagefs.server",
		"/usr/local/cpanel/cpsrvd",
		"/usr/local/cpanel/xml-api",
		"/usr/bin/dccproc",
	}
	for _, w := range wantExe {
		found := false
		for _, e := range c.GlobalAllowExe {
			if e == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultGlobalAllowExe missing %q", w)
		}
	}
	wantComm := []string{
		"runc", "containerd-shim", "dockerd",
		"cagefsctl", "clean_user_php_", "update_quota_ca",
		"spamd", "spamd child",
	}
	for _, w := range wantComm {
		found := false
		for _, e := range c.GlobalAllowComm {
			if e == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultGlobalAllowComm missing %q", w)
		}
	}
}

// TestEventFilter_DefaultConfSuppression wires DefaultConf through the
// filter and confirms the canonical mailcow / Docker noise burst the
// user reported is silenced without any operator-side changes.
func TestEventFilter_DefaultConfSuppression(t *testing.T) {
	f := BuildEventFilter(DefaultConf())

	cases := []struct {
		name string
		ev   Event
	}{
		{"BPF-001 runc", Event{PolicyID: PolicyUnexpectedBPF, Comm: "runc", Filename: "BPF_PROG_LOAD"}},
		{"BPF-001 containerd-shim", Event{PolicyID: PolicyUnexpectedBPF, Comm: "containerd-shim", Filename: "BPF_MAP_CREATE"}},
		{"CRED-002 sshd-session", Event{PolicyID: PolicyCredEscal, Filename: "sshd-session"}},
		{"CRED-002 systemd-executor", Event{PolicyID: PolicyCredEscal, Filename: "systemd-executor"}},
		{"CRED-002 postfix master", Event{PolicyID: PolicyCredEscal, Filename: "master"}},
		{"CRED-002 dovecot indexer-worker", Event{PolicyID: PolicyCredEscal, Filename: "indexer-worker"}},
		{"EXEC-003 logger", Event{PolicyID: PolicyReverseShell, Filename: "/usr/bin/logger", Flags: EventFlagRevshellStrict}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !f.Match(tc.ev) {
				t.Fatalf("default conf should suppress %+v", tc.ev)
			}
		})
	}
}

// TestParseConf_AllowExe_EXEC003 ensures that allow_exe is now
// accepted under EXEC-003 / EXEC-005 in addition to CRED-002.
func TestParseConf_AllowExe_EXEC003(t *testing.T) {
	body := `
[policy "CFML-EXEC-003"]
mode = monitor
allow_exe = /usr/local/bin/whitelist_forwardinghosts.sh

[policy "CFML-EXEC-005"]
mode = monitor
allow_exe = /usr/local/bin/some_weak_helper.sh
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if got := c.AllowExeFor(PolicyReverseShell); len(got) != 1 || got[0] != "/usr/local/bin/whitelist_forwardinghosts.sh" {
		t.Errorf("EXEC-003 allow_exe: got %v", got)
	}
	if got := c.AllowExeFor(PolicyInterpreterNetStdio); len(got) != 1 || got[0] != "/usr/local/bin/some_weak_helper.sh" {
		t.Errorf("EXEC-005 allow_exe: got %v", got)
	}
}
