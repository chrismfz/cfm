package detectors

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// readPathListFile is what both MALPATH_FILE and CHALLENGE_PATHS_FILE use
// (read once when both name the same file): trimmed, lower-cased, blank and
// # lines skipped, order kept (first match wins on that order).
func TestReadPathListFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "malpaths.txt")
	if err := os.WriteFile(p, []byte("# comment\n/.ENV\n\n  5:/WP-Config.php  \n   # indented comment\n/.git/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := readPathListFile("MALPATH_FILE", p)
	if want := []string{"/.env", "5:/wp-config.php", "/.git/"}; !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q ok=%v, want %q ok=true", got, ok, want)
	}
	if got, ok := readPathListFile("MALPATH_FILE", filepath.Join(t.TempDir(), "missing")); ok || got != nil {
		t.Fatalf("missing file: got %q ok=%v, want nil false", got, ok)
	}
}
