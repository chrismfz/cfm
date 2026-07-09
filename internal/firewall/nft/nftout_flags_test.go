package nft

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nftOut feeds its argument to `nft -f -` (script mode). Command-line flags such
// as -a/-n/-t/-s/-j are NOT valid inside an nft script and make the whole
// command a syntax error. Passing e.g. `nftOut("-a list chain …")` therefore
// returns an error string instead of a listing — and callers that discard the
// error (or reuse the returned text) silently misbehave. That is precisely how
// the DNAT/panel scoped accepts ended up appended AFTER the default drop (and
// duplicated): the chain listing "succeeded" with garbage. Chain/set listings
// with flags must go through ListChainText / runNFTCommand (argv mode).
//
// This guard scans the package source so the mistake can't quietly return.
func TestNftOutIsNeverCalledWithCLIFlags(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// Matches nftOut("-…") or nftOut(fmt.Sprintf("-…") — a leading dash inside
	// the string literal is always a CLI flag, never valid script syntax.
	bad := regexp.MustCompile(`nftOut\(\s*(?:fmt\.Sprintf\(\s*)?"-`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if bad.MatchString(line) {
				t.Errorf("%s:%d passes a CLI flag to nftOut (script mode) — use ListChainText/runNFTCommand instead:\n\t%s", f, i+1, trimmed)
			}
		}
	}
}
