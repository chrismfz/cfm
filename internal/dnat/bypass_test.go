package dnat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendBypassUnique_CreatesAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.dnat_bypass")

	added, err := appendBypassUnique(path, "84.54.49.205")
	if err != nil {
		t.Fatalf("first append: %v", err)
	}
	if !added {
		t.Fatalf("expected added=true on first insert")
	}

	added, err = appendBypassUnique(path, "84.54.49.205")
	if err != nil {
		t.Fatalf("duplicate append: %v", err)
	}
	if added {
		t.Fatalf("expected added=false on duplicate")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := strings.Count(string(b), "84.54.49.205"); got != 1 {
		t.Fatalf("expected single occurrence of value, got %d in %q", got, string(b))
	}
}

func TestAppendBypassUnique_NormalisesCIDRBeforeDedupCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.dnat_bypass")

	if _, err := appendBypassUnique(path, "84.54.49.0/24"); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// appendBypassUnique receives the already-canonical value (the CLI
	// normalises CIDR host bits before calling). This tests that an exact
	// canonical duplicate is rejected.
	added, err := appendBypassUnique(path, "84.54.49.0/24")
	if err != nil {
		t.Fatalf("dup append: %v", err)
	}
	if added {
		t.Fatalf("expected added=false on canonical duplicate")
	}
}

func TestRemoveBypassEntry_RemovesOnlyMatchingLine_PreservesComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.dnat_bypass")
	content := `# header comment
84.54.49.205
84.54.49.206 # peer
84.54.49.207
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	removed, err := removeBypassEntry(path, "84.54.49.206")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !removed {
		t.Fatalf("expected removed=true")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	gotStr := string(got)
	if strings.Contains(gotStr, "84.54.49.206") {
		t.Errorf("expected 84.54.49.206 removed, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "# header comment") {
		t.Errorf("expected header comment preserved, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "84.54.49.205") || !strings.Contains(gotStr, "84.54.49.207") {
		t.Errorf("expected other entries preserved, got: %q", gotStr)
	}
}

func TestRemoveBypassEntry_MissingFileNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-such-file")
	removed, err := removeBypassEntry(path, "84.54.49.205")
	if err != nil {
		t.Fatalf("expected nil err for missing file, got %v", err)
	}
	if removed {
		t.Fatalf("expected removed=false for missing file")
	}
}

func TestRemoveBypassEntry_NotFoundLeavesFileIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm.dnat_bypass")
	content := "84.54.49.205\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	removed, err := removeBypassEntry(path, "1.2.3.4")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if removed {
		t.Fatalf("expected removed=false when value absent")
	}
	got, _ := os.ReadFile(path)
	if string(got) != content {
		t.Errorf("file unexpectedly modified: %q", string(got))
	}
}
