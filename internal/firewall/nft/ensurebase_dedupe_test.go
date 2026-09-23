//go:build linux

package nft

import (
	"strings"
	"testing"
)

// EnsureBase reads the input chain with handles and deletes the copies the
// old presence check piled up (it never recognised `iif lo accept`, which
// nft prints `iif "lo" accept`), keeping the top one, and adds neither
// another `iif lo accept` nor a second `jump flood`.
func TestEnsureBase_RemovesPiledUpCopies(t *testing.T) {
	log := fakeNFTBinary(t, `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		iif "lo" accept # handle 40
		iif "lo" accept # handle 41
		ip saddr @self_v4 accept # handle 42
		iif "lo" accept # handle 43
		jump flood # handle 60
	}
}
`)
	if err := New().EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	got := readFile(t, log)
	if !strings.Contains(got, "ARGS -a list chain inet cfm input") {
		t.Fatalf("the input chain must be read with handles:\n%.400s", got)
	}
	if !strings.Contains(got, "delete rule inet cfm input handle 41\ndelete rule inet cfm input handle 43") {
		t.Errorf("want handles 41 and 43 deleted in one run (40, the top one, kept):\n%s", got)
	}
	if strings.Contains(got, "delete rule inet cfm input handle 40") {
		t.Errorf("deleted the top-most iif lo")
	}
	if strings.Contains(got, "iif lo accept") {
		t.Errorf("inserted another iif lo accept:\n%s", got)
	}
	if strings.Contains(got, "input jump flood") {
		t.Errorf("added a second jump flood:\n%s", got)
	}
}
