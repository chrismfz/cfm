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
	// A worker child (must be ignored — comm "spamd child") and the master.
	mkProc("501", "spamd child\n", "spamd child\x00")
	mkProc("500", "spamd\n", "/usr/bin/spamd\x00--max-children=6\x00--daemonize\x00")

	n, ok := discoverSpamdMaxChildrenIn(root)
	if !ok || n != 6 {
		t.Fatalf("discoverSpamdMaxChildrenIn = (%d,%v), want (6,true)", n, ok)
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
