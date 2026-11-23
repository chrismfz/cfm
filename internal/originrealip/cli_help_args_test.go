package originrealip

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// treeDigest hashes every file name and content under root.
func treeDigest(t *testing.T, root string) [32]byte {
	t.Helper()
	h := sha256.New()
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		h.Write([]byte(p))
		h.Write(b)
		return nil
	})
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// `cfm realip` / `cfm edge realip` answer a help word with the usage and
// change nothing: `realip fix --help` was read as `realip fix` (the flags map
// ignores what it does not know) and rewrote the origin's config.
func TestCLIHelpWordsChangeNothing(t *testing.T) {
	l, r := cpanelHost(t) // an origin the fix would rewrite
	before := treeDigest(t, r)
	for _, h := range []string{"-h", "--help", "help"} {
		for _, pre := range [][]string{{}, {"status"}, {"fix"}, {"fix", "--dry-run"}, {"status", "--json"}} {
			args := append(append([]string{}, pre...), h)
			var out bytes.Buffer
			rc := runCLI(args, &out, l, func() bool { t.Errorf("%q: probed the edge", args); return true })
			if rc != 0 || !strings.Contains(out.String(), "cfm edge realip fix") || strings.Contains(out.String(), "origin: panel=") {
				t.Errorf("%q: rc=%d out=%q, want the usage only", args, rc, out.String())
			}
		}
	}
	if treeDigest(t, r) != before {
		t.Fatal("a help word changed the origin's files")
	}
	// Without the help word the same host is a fix to make (so the test
	// above asked a command that would act).
	var out bytes.Buffer
	if rc := runCLI([]string{"fix", "--dry-run"}, &out, l, func() bool { return true }); rc != 0 || !strings.Contains(out.String(), "would write") {
		t.Fatalf("`realip fix --dry-run` plans nothing here, so the test above proves nothing: rc=%d %s", rc, out.String())
	}
}
