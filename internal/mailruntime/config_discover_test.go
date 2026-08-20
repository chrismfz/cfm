package mailruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverEximMaximaIn(t *testing.T) {
	dir := t.TempDir()
	noOpt := filepath.Join(dir, "exim-no-opt.conf")
	withOpt := filepath.Join(dir, "exim.conf")
	writeFile(t, noOpt, "acl_smtp_rcpt = acl_check_rcpt\n")
	writeFile(t, withOpt, "smtp_accept_max = 200\n")

	// First file exists but doesn't set the option → keep looking → found in 2nd.
	m, path := discoverEximMaximaIn([]string{noOpt, withOpt})
	if !m.SMTPAcceptMaxFound || m.SMTPAcceptMax != 200 {
		t.Fatalf("maxima = %+v, want smtp_accept_max=200 found", m)
	}
	if path != withOpt {
		t.Errorf("path = %q, want %q", path, withOpt)
	}
}

func TestDiscoverEximMaximaInNoneFound(t *testing.T) {
	dir := t.TempDir()
	noOpt := filepath.Join(dir, "exim.conf")
	writeFile(t, noOpt, "# no smtp_accept_max here\nacl_smtp_rcpt = acl_check_rcpt\n")

	// A present-but-silent config, plus a missing path: unresolved, no default
	// assumed.
	m, path := discoverEximMaximaIn([]string{filepath.Join(dir, "nope.conf"), noOpt})
	if m.SMTPAcceptMaxFound {
		t.Errorf("must not resolve a cap when none is set, got %+v", m)
	}
	if path != "" {
		t.Errorf("path = %q, want empty", path)
	}
	// And it flows through to unknown, never ok.
	if m.EximMax().Known {
		t.Errorf("unresolved maxima must yield an unknown ResolvedMax")
	}
}

func TestDiscoverSpamdMaxChildrenIn(t *testing.T) {
	root := t.TempDir()
	mkProc := func(pid, comm, cmdline string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Grounded in the operator's live `ps -o args= -C spamd` on a cPanel box:
	// the MASTER runs under perl (COMM "perl", cmdline is the raw perl invocation
	// of .../bin/spamd --max-children=N), and only the WORKERS rewrite COMM to
	// "spamd child". Matching must therefore be on the cmdline, not the COMM.
	// Workers get the lower pids so the scan sees them first and must reject them
	// (they mention spamd but have no --max-children).
	mkProc("300", "spamd child\n", "spamd child\x00")
	mkProc("301", "spamd child\n", "spamd child\x00")
	mkProc("500", "perl\n", "/usr/local/cpanel/3rdparty/perl/542/bin/perl\x00-T\x00-w\x00/usr/local/cpanel/3rdparty/bin/spamd\x00--max-children=10\x00--timeout-child=30\x00--pidfile=/var/run/spamd.pid\x00")

	n, ok := discoverSpamdMaxChildrenIn(root)
	if !ok || n != 10 {
		t.Fatalf("discoverSpamdMaxChildrenIn = (%d,%v), want (10,true) — master under perl must be found by cmdline", n, ok)
	}
}

func TestDiscoverSpamdMaxChildrenInEmptyCmdline(t *testing.T) {
	// A master whose cmdline raced away to empty (zombie/kernel-thread shape):
	// no flag → unresolved, never a bogus number.
	root := t.TempDir()
	dir := filepath.Join(root, "500")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "comm"), []byte("spamd\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "cmdline"), []byte(""), 0o644)
	if n, ok := discoverSpamdMaxChildrenIn(root); ok || n != 0 {
		t.Fatalf("empty master cmdline → (%d,%v), want (0,false)", n, ok)
	}
}

func TestDiscoverSpamdMaxChildrenInAbsent(t *testing.T) {
	root := t.TempDir()
	// Only a worker child, no master, and a master without the flag elsewhere.
	dir := filepath.Join(root, "700")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "comm"), []byte("spamd child\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "cmdline"), []byte("spamd child\x00"), 0o644)

	if n, ok := discoverSpamdMaxChildrenIn(root); ok || n != 0 {
		t.Fatalf("no master spamd → (%d,%v), want (0,false)", n, ok)
	}
}

func TestCmdlineToString(t *testing.T) {
	got := cmdlineToString([]byte("/usr/bin/spamd\x00--max-children=10\x00"))
	want := "/usr/bin/spamd --max-children=10"
	if got != want {
		t.Errorf("cmdlineToString = %q, want %q", got, want)
	}
}
