package wafconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setup points both paths at a temp dir: tests never touch /etc/cfm or
// /var/lib/cfm (CLAUDE.md §5).
func setup(t *testing.T) (src, dst string) {
	t.Helper()
	dir := t.TempDir()
	src = filepath.Join(dir, "etc", "cfm_waf_config.lua")
	dst = filepath.Join(dir, "lua", "cfm_waf_config.lua")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	oldS, oldL := SourcePath, LuaPath
	SourcePath, LuaPath = src, dst
	t.Cleanup(func() { SourcePath, LuaPath = oldS, oldL })
	return src, dst
}

func mustSync(t *testing.T, want Result) {
	t.Helper()
	got, err := Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got != want {
		t.Fatalf("Sync = %v, want %v", got, want)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNoSourceNoCopyDoesNothing(t *testing.T) {
	_, dst := setup(t)
	mustSync(t, Unchanged)
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("no source must create nothing, stat err=%v", err)
	}
}

func TestCopiesWithHeaderAndGroupReadMode(t *testing.T) {
	src, dst := setup(t)
	body := "return { rule_bad_ua = \"disabled\" }\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Written)
	if got := read(t, dst); got != Header+body {
		t.Fatalf("copy = %q, want header + source", got)
	}
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 0640 (the cfm-group edge worker must read it)", st.Mode().Perm())
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind")
	}
	// Steady state: nothing to do.
	mustSync(t, Unchanged)
}

func TestFollowsEditsAndRemoval(t *testing.T) {
	src, dst := setup(t)
	if err := os.WriteFile(src, []byte("return { a = 1 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Written)

	next := "return { a = 2, b = 3 }\n"
	if err := os.WriteFile(src, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force a different mtime even on coarse-timestamp filesystems.
	later := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(src, later, later)
	mustSync(t, Written)
	if got := read(t, dst); got != Header+next {
		t.Fatalf("edit not followed: %q", got)
	}

	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Removed)
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("copy must go with the source, stat err=%v", err)
	}
	mustSync(t, Unchanged)
}

func TestRewritesACopyChangedBehindItsBack(t *testing.T) {
	src, dst := setup(t)
	body := "return { a = 1 }\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Written)
	// Someone edits the generated copy; the header is still there.
	if err := os.WriteFile(dst, []byte(Header+"return { a = 9 }\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Written) // the next poll, no restart needed
	if got := read(t, dst); got != Header+body {
		t.Fatalf("copy not restored from the source: %q", got)
	}
}

func TestSameSizeEditWithinOneTickIsFollowed(t *testing.T) {
	src, dst := setup(t)
	if err := os.WriteFile(src, []byte("return { a = 1 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Written)
	st, _ := os.Stat(src)
	if err := os.WriteFile(src, []byte("return { a = 2 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same size and the same mtime: only a content compare sees the edit.
	_ = os.Chtimes(src, st.ModTime(), st.ModTime())
	mustSync(t, Written)
	if got := read(t, dst); got != Header+"return { a = 2 }\n" {
		t.Fatalf("same-size edit missed: %q", got)
	}
}

func TestHandPlacedFileKeptWhenNoSource(t *testing.T) {
	_, dst := setup(t)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatal(err)
	}
	hand := "return { rule_xss = \"logonly\" }\n"
	if err := os.WriteFile(dst, []byte(hand), 0o640); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Unchanged)
	if got := read(t, dst); got != hand {
		t.Fatal("a hand-placed file without the header must never be removed")
	}
}

func TestHandPlacedFileBackedUpBeforeOverwrite(t *testing.T) {
	src, dst := setup(t)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatal(err)
	}
	hand := "return { rule_xss = \"logonly\" }\n"
	if err := os.WriteFile(dst, []byte(hand), 0o640); err != nil {
		t.Fatal(err)
	}
	body := "return { rule_xss = \"block\" }\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, Written)
	if got := read(t, dst); got != Header+body {
		t.Fatalf("/etc/cfm must win: %q", got)
	}
	baks, _ := filepath.Glob(dst + ".handplaced.*")
	if len(baks) != 1 || read(t, baks[0]) != hand {
		t.Fatalf("hand-placed file not backed up: %v", baks)
	}
}

func TestRefusesOversizeAndNonRegular(t *testing.T) {
	src, dst := setup(t)
	if err := os.WriteFile(src, []byte(strings.Repeat("-", maxSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(); err == nil {
		t.Fatal("oversize source must be refused")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("refused source must not be copied")
	}
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(); err == nil {
		t.Fatal("a directory must be refused")
	}
}
