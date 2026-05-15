package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertConfKey_ReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.conf")
	original := "# cfm.conf\nFOO = 1\nCLAMD_ENABLED = true\nBAR = 2\n"
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}

	if err := UpsertConfKey(path, "CLAMD_ENABLED", "false"); err != nil {
		t.Fatalf("UpsertConfKey: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "# cfm.conf\nFOO = 1\nCLAMD_ENABLED = false\nBAR = 2\n"
	if string(got) != want {
		t.Errorf("content drift\n got: %q\nwant: %q", got, want)
	}

	// Mode preserved.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Errorf("mode drift: got %04o want 0640", fi.Mode().Perm())
	}

	// No leftover .tmp from the atomic-rename path.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("leftover tmp file present (err=%v)", err)
	}
}

func TestUpsertConfKey_AppendWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.conf")
	if err := os.WriteFile(path, []byte("FOO = 1\n"), 0640); err != nil {
		t.Fatal(err)
	}

	if err := UpsertConfKey(path, "CLAMD_NGINX_HOOK_ENABLED", "false"); err != nil {
		t.Fatalf("UpsertConfKey: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "CLAMD_NGINX_HOOK_ENABLED = false") {
		t.Errorf("appended key missing in: %q", got)
	}
	if !strings.Contains(string(got), "FOO = 1") {
		t.Errorf("pre-existing key dropped: %q", got)
	}
}

func TestUpsertConfKey_AppendsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.conf")
	// File without trailing newline.
	if err := os.WriteFile(path, []byte("FOO = 1"), 0640); err != nil {
		t.Fatal(err)
	}

	if err := UpsertConfKey(path, "BAR", "true"); err != nil {
		t.Fatalf("UpsertConfKey: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "FOO = 1\nBAR = true\n" {
		t.Errorf("got: %q", got)
	}
}

func TestUpsertConfKey_NoOpWhenValueUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.conf")
	original := "CLAMD_ENABLED = true\n"
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := UpsertConfKey(path, "CLAMD_ENABLED", "true"); err != nil {
		t.Fatalf("UpsertConfKey: %v", err)
	}

	// Content unchanged.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("content drift on no-op: %q", got)
	}
	// And no rename happened (mtime unchanged) — proves we short-circuited
	// before the atomic-write path.
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Errorf("mtime changed on no-op upsert: before=%s after=%s",
			infoBefore.ModTime(), infoAfter.ModTime())
	}
}

func TestUpsertConfKey_RejectsInvalidKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.conf")
	if err := os.WriteFile(path, []byte(""), 0640); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"", "WITH SPACE", "with-dash", "FOO;rm -rf"} {
		if err := UpsertConfKey(path, k, "x"); err == nil {
			t.Errorf("expected error for invalid key %q, got nil", k)
		}
	}
}

func TestUpsertConfKey_RequiresAbsolutePath(t *testing.T) {
	if err := UpsertConfKey("relative.conf", "FOO", "1"); err == nil {
		t.Errorf("expected error for relative path")
	}
}
