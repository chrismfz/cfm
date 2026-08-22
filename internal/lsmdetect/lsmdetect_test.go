package lsmdetect

import "testing"

const ts = "2026-08-22 20:39:17"

func TestParseCRED002RealWorld(t *testing.T) {
	// The exact operator-reported shape: root system daemon, full enrichment.
	line := ts + " [lsm] Privilege escalation without setuid path: pid=2456528 (sssd) policy=CFML-CRED-002 path=sssd user=root(0) exe=/usr/sbin/sssd sha256=5e6f528d2fac parent_exe=/usr/lib/systemd/systemd"
	e, ok := Parse(line)
	if !ok {
		t.Fatalf("Parse rejected line %q", line)
	}
	if e.Kind != "detect" || e.Policy != "CFML-CRED-002" {
		t.Errorf("Kind/Policy = %q/%q", e.Kind, e.Policy)
	}
	if e.When != ts {
		t.Errorf("When = %q want %q", e.When, ts)
	}
	if e.PID != 2456528 {
		t.Errorf("PID = %d", e.PID)
	}
	if e.Comm != "sssd" {
		t.Errorf("Comm = %q", e.Comm)
	}
	if e.Title != "Privilege escalation without setuid path" {
		t.Errorf("Title = %q", e.Title)
	}
	if e.Path != "sssd" || e.User != "root" || e.Exe != "/usr/sbin/sssd" {
		t.Errorf("Path/User/Exe = %q/%q/%q", e.Path, e.User, e.Exe)
	}
	if e.SHA256 != "5e6f528d2fac" || e.ParentExe != "/usr/lib/systemd/systemd" {
		t.Errorf("SHA256/ParentExe = %q/%q", e.SHA256, e.ParentExe)
	}
}

func TestParseCommWithSpaces(t *testing.T) {
	// cPanel's "Fix mailman pac" wrapper — the comm carries spaces.
	line := ts + " [lsm] Privilege escalation without setuid path: pid=551854 (Fix mailman pac) policy=CFML-CRED-002 path=perl user=root(0) exe=/usr/local/cpanel/3rdparty/perl/542/bin/perl sha256=082ffdbf694a parent_exe=/usr/lib/systemd/systemd"
	e, ok := Parse(line)
	if !ok {
		t.Fatalf("rejected %q", line)
	}
	if e.Comm != "Fix mailman pac" {
		t.Errorf("Comm = %q", e.Comm)
	}
	if e.PID != 551854 || e.User != "root" {
		t.Errorf("PID/User = %d/%q", e.PID, e.User)
	}
	if e.Exe != "/usr/local/cpanel/3rdparty/perl/542/bin/perl" {
		t.Errorf("Exe = %q", e.Exe)
	}
}

func TestParseVariants(t *testing.T) {
	t.Run("no enrichment (proc gone early)", func(t *testing.T) {
		line := ts + " [lsm] Ephemeral-path exec: pid=42 (sh) policy=CFML-EXEC-001 path=bash"
		e, ok := Parse(line)
		if !ok {
			t.Fatalf("rejected")
		}
		if e.Kind != "detect" || e.Policy != "CFML-EXEC-001" || e.PID != 42 ||
			e.Comm != "sh" || e.Path != "bash" || e.User != "" || e.Gone {
			t.Fatalf("got %+v", e)
		}
	})

	t.Run("deleted exe + proc gone", func(t *testing.T) {
		line := ts + " [lsm] Deleted-file exec: pid=7 (.x/pgrep) policy=CFML-EXEC-006 path=.x/pgrep user=bob(1234) exe=/tmp/.x/pgrep (deleted) sha256=abcdef0123456789aa proc=gone"
		e, ok := Parse(line)
		if !ok {
			t.Fatalf("rejected")
		}
		if e.Policy != "CFML-EXEC-006" || e.User != "bob" ||
			e.Exe != "/tmp/.x/pgrep" || !e.Deleted || !e.Gone ||
			e.SHA256 != "abcdef0123456789aa" {
			t.Fatalf("got %+v", e)
		}
	})

	t.Run("suppression summary", func(t *testing.T) {
		line := ts + " [lsm] CFML-CRED-002 suppressed=12 in_last=60s (cfm.log+notify)"
		e, ok := Parse(line)
		if !ok {
			t.Fatalf("rejected")
		}
		if e.Kind != "suppressed" || e.Policy != "CFML-CRED-002" || e.Suppressed != 12 {
			t.Fatalf("got %+v", e)
		}
	})

	t.Run("value containing spaces re-glues", func(t *testing.T) {
		line := ts + " [lsm] T: pid=1 (x) policy=CFML-FS-005 op=create path=my file.txt user=u(9)"
		e, ok := Parse(line)
		if !ok {
			t.Fatalf("rejected")
		}
		if e.Op != "create" || e.Path != "my file.txt" || e.User != "u" {
			t.Fatalf("got %+v", e)
		}
	})
}

func TestParseRejectsNonDetectLines(t *testing.T) {
	lines := []string{
		ts + " [lsm] lifecycle note without any anchor",
		"",
		"2026-08-22 20:39:17 other-subsystem line",
		ts + " [lsm] Something: pid=1 (x) notpolicy=nope",
		ts + " [lsm] Something: pid=1 (x) policy=nope-nope",
		ts + " [lsm] CFML-CRED-002 suppressed=abc in_last=60s (cfm.log+notify)", // non-numeric count
	}
	for _, ln := range lines {
		if _, ok := Parse(ln); ok {
			t.Errorf("Parse accepted %q", ln)
		}
	}
}

func TestParseQuotedCmdlineCannotForgeExe(t *testing.T) {
	// An attacker-controlled cmdline must not overwrite the exe field even
	// when it embeds a plausible-looking ' exe=' token inside the quotes.
	line := ts + ` [lsm] T: pid=9 (evil) policy=CFML-CRED-002 user=u(1) exe=/bin/true cwd=/tmp cmdline="run /bin/false exe=/evil/path --x" parent_exe=/bin/sh`
	e, ok := Parse(line)
	if !ok {
		t.Fatalf("rejected")
	}
	if e.Exe != "/bin/true" {
		t.Errorf("exe hijacked via quoted cmdline: %q", e.Exe)
	}
	if e.ParentExe != "/bin/sh" {
		t.Errorf("ParentExe = %q", e.ParentExe)
	}
}

func TestParseSpoofedCommWithFakePidAnchor(t *testing.T) {
	// A pre-root process can spoof its comm; one embedding ": pid=" must not
	// corrupt the parsed title/pid (first anchor wins, not the last).
	line := ts + ` [lsm] Privilege escalation without setuid path: pid=777 (a: pid=99 (b)) policy=CFML-CRED-002 user=root(0) exe=/usr/sbin/x`
	e, ok := Parse(line)
	if !ok {
		t.Fatalf("rejected")
	}
	if e.Title != "Privilege escalation without setuid path" || e.PID != 777 || e.Comm != "a: pid=99 (b)" {
		t.Fatalf("spoofed comm corrupted the parse: %+v", e)
	}
}
