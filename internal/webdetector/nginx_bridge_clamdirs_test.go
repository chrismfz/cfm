package webdetector

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The edge's spool (already_copied) is accepted only as a regular file
// directly in pending, by the path given: root removes it after the scan,
// and pending is writable by the edge's user. Resolving symlinks let
// pending/x -> /etc/shadow be deleted as root; a subdir could be swapped for
// a symlink after the check.
func TestValidateUploadSourcePathAlreadyCopiedIsADirectRegularChild(t *testing.T) {
	pending := filepath.Join(t.TempDir(), "pending")
	if err := os.MkdirAll(filepath.Join(pending, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	inPending := filepath.Join(pending, "upload_1")
	if err := os.WriteFile(inPending, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(pending, "sub", "upload_2")
	if err := os.WriteFile(nested, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pending, "upload_3")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	// A symlink inside pending pointing back into pending is refused too.
	loop := filepath.Join(pending, "upload_4")
	if err := os.Symlink(inPending, loop); err != nil {
		t.Fatal(err)
	}
	if p, ok := validateUploadSourcePath(inPending, true, pending); !ok || p != inPending {
		t.Fatalf("direct spool: %q %v", p, ok)
	}
	for _, p := range []string{nested, link, loop, pending} {
		if got, ok := validateUploadSourcePath(p, true, pending); ok {
			t.Errorf("%s accepted (as %s)", p, got)
		}
	}
	if _, ok := validateUploadSourcePath(inPending, true, ""); ok {
		t.Error("accepted with no pending dir")
	}
}

// SetClamManager runs every 15 s: it set pending/infected's mode and group
// by name, so a symlink at either had root chmod 0770 / chown root:cfm its
// target. Now a symlinked dir is left alone and disables what uses it.
func TestSetClamManagerRefusesSymlinkedDirs(t *testing.T) {
	if os.Geteuid() != 0 { // root:root needs root (the CI runner is not)
		orig := clamInfectedGID
		clamInfectedGID = -1
		t.Cleanup(func() { clamInfectedGID = orig })
	}
	root := t.TempDir()
	victim := filepath.Join(root, "etc")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(root, "pending")
	if err := os.Symlink(victim, pending); err != nil {
		t.Fatal(err)
	}
	infected := filepath.Join(root, "infected")
	if err := os.Symlink(victim, infected); err != nil {
		t.Fatal(err)
	}
	b := &NginxBridge{}
	fake := &fakeSyncScanner{pending: pending}
	b.SetClamManager(fake, pending, infected)
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o700 {
		t.Fatalf("symlink target re-moded to %o", st.Mode().Perm())
	}
	if cw := b.clamWired(); cw.mgr != nil || cw.pending != "" || cw.infected != "" {
		t.Fatalf("symlinked dirs still wired: %+v", cw)
	}
	if b.clamDirWarn == "" {
		t.Error("refusal not recorded for the log")
	}

	// Plain dirs: pending 0770, infected 0700, wired.
	p2, i2 := filepath.Join(root, "p2"), filepath.Join(root, "i2")
	b.SetClamManager(fake, p2, i2)
	if cw := b.clamWired(); cw.mgr == nil || cw.pending != p2 || cw.infected != i2 {
		t.Fatalf("plain dirs not wired: %+v", cw)
	}
	if st, _ := os.Stat(p2); st.Mode().Perm() != 0o770 {
		t.Errorf("pending mode %o", st.Mode().Perm())
	}
	if st, _ := os.Stat(i2); st.Mode().Perm() != 0o700 {
		t.Errorf("infected mode %o", st.Mode().Perm())
	}
	if b.clamDirWarn != "" {
		t.Errorf("stale warning %q", b.clamDirWarn)
	}
	if os.Geteuid() == 0 {
		if st, _ := os.Stat(i2); st.Sys().(*syscall.Stat_t).Gid != 0 {
			t.Errorf("infected group %d, want root", st.Sys().(*syscall.Stat_t).Gid)
		}
	}
}

// A path with a control character is refused, spool or nginx body temp:
// the path (or a copy named after it) goes to clamd in a newline-terminated
// SCAN command.
func TestValidateUploadSourcePathRefusesControlChars(t *testing.T) {
	pending := t.TempDir()
	p := filepath.Join(pending, "upload_x\nSHUTDOWN")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := validateUploadSourcePath(p, true, pending); ok {
		t.Error("control character accepted in a spool name")
	}
	tmp := filepath.Join(os.TempDir(), "x\nSHUTDOWN")
	if _, ok := validateUploadSourcePath(tmp, false, pending); ok {
		t.Error("control character accepted in a body temp path")
	}
}

// A spool hard-linked to another file (fs.protected_hardlinks off) is not
// the edge's own.
func TestValidateUploadSourcePathRefusesHardLinks(t *testing.T) {
	pending := t.TempDir()
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hl := filepath.Join(pending, "upload_hl")
	if err := os.Link(victim, hl); err != nil {
		t.Skipf("link: %v", err)
	}
	if _, ok := validateUploadSourcePath(hl, true, pending); ok {
		t.Error("hard-linked spool accepted")
	}
}
