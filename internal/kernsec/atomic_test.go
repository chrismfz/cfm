package kernsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAtomicWriteFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")

	if err := AtomicWriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Errorf("got %q, want %q", got, "hello\n")
	}

	st, _ := os.Stat(path)
	if mode := st.Mode().Perm(); mode != 0o644 {
		t.Errorf("perm = %v, want 0644", mode)
	}

	// No tmp file should remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "out.conf" {
			t.Errorf("stray file in dir: %s", e.Name())
		}
	}
}

func TestAtomicWriteFile_OverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("got %q, want %q", got, "new")
	}
}

func TestAtomicWriteFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "out.conf")
	if err := AtomicWriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestBackupOnce_HappyPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.conf")
	dst := filepath.Join(dir, "src.conf.bak")
	if err := os.WriteFile(src, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BackupOnce(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "original" {
		t.Errorf("backup = %q, want %q", got, "original")
	}
}

func TestBackupOnce_DoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.conf")
	dst := filepath.Join(dir, "src.conf.bak")
	if err := os.WriteFile(src, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("v1-original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BackupOnce(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "v1-original" {
		t.Errorf("backup overwritten: got %q, want %q", got, "v1-original")
	}
}

func TestBackupOnce_MissingSourceIsNoOp(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "missing")
	dst := filepath.Join(dir, "missing.bak")
	if err := BackupOnce(src, dst); err != nil {
		t.Fatalf("expected no error for missing src, got %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("dst should not exist when src is missing")
	}
}

func TestBackupTimestampedSuffix_DistinguishesByPID(t *testing.T) {
	// Two same-second apply runs must produce distinct backup paths
	// even when they hit within the same UTC second. Previously the
	// suffix was just the timestamp; the second writer silently
	// overwrote the first writer's preserved-extras backup, losing
	// the operator's edits. PID disambiguates.
	origNow := nowFunc
	origPid := pidFunc
	t.Cleanup(func() {
		nowFunc = origNow
		pidFunc = origPid
	})

	frozen := time.Date(2026, 5, 10, 14, 5, 30, 0, time.UTC)
	nowFunc = func() time.Time { return frozen }

	pidFunc = func() int { return 100 }
	a := BackupTimestampedSuffix()
	pidFunc = func() int { return 200 }
	b := BackupTimestampedSuffix()

	if a == b {
		t.Fatalf("same-second + different PIDs collided: %q == %q", a, b)
	}
	if !strings.Contains(a, ".100") {
		t.Errorf("PID 100 should be in suffix: %q", a)
	}
	if !strings.Contains(b, ".200") {
		t.Errorf("PID 200 should be in suffix: %q", b)
	}
	if !strings.Contains(a, "20260510T140530Z") {
		t.Errorf("timestamp should be in suffix: %q", a)
	}
}

func TestCanonicalLine_StripsInlineComments(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"kernel.kptr_restrict = 2", "kernel.kptr_restrict=2"},
		{"kernel.kptr_restrict=2", "kernel.kptr_restrict=2"},
		// Inline comment on a managed line — operator-added note. Must
		// canonicalise to the same form as the bare line so the next
		// apply doesn't flag this as an unmanaged extra and trigger a
		// per-run backup on every invocation.
		{"kernel.kptr_restrict = 2 # bumped per CVE-X", "kernel.kptr_restrict=2"},
		{"kernel.kptr_restrict=2  #note", "kernel.kptr_restrict=2"},
		// Whole-line comment → empty.
		{"# leading comment", ""},
		// Comment-only after stripping → empty.
		{"   # spaces then comment", ""},
		// Modprobe-style two-token line with inline comment.
		{"blacklist bluetooth # we have BT hw", "blacklist bluetooth"},
		// Line that's only "#" → empty.
		{"#", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := canonicalLine(tc.in); got != tc.want {
				t.Errorf("canonicalLine(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAuditExtraLines_InlineCommentsDoNotTriggerBackup(t *testing.T) {
	// Operator added a comment after a managed line. Apply was
	// previously flagging this as an unmanaged extra and writing a
	// per-run backup on every invocation; with canonicalLine stripping
	// inline comments, the line should match.
	dir := t.TempDir()
	path := filepath.Join(dir, "managed.conf")
	desired := []byte("# header\nkernel.kptr_restrict = 2\nfs.protected_hardlinks = 1\n")
	existing := []byte("# header\nkernel.kptr_restrict = 2 # bumped per CVE-X\nfs.protected_hardlinks = 1\n")
	if err := os.WriteFile(path, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	extras, err := auditExtraLines(path, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(extras) != 0 {
		t.Errorf("inline-commented managed line should not be flagged as extra; got: %q", extras)
	}
}
