package nft

import (
	"errors"
	"strings"
	"testing"
)

// The replace is ONE nft script: the flush first, then every element, so
// `nft -f` commits them as one transaction (LiveNFTFeedReplaceIsAtomic runs it
// on a kernel).
func TestReplaceSetScript_FlushThenEveryElementInOneScript(t *testing.T) {
	elems := make([]string, 2*replaceChunk+7)
	for i := range elems {
		elems[i] = "198.51.100.1"
	}
	script := replaceSetScript("block_ext_v4_hosts", elems, "")
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines, want the flush and 3 add statements:\n%.300s", len(lines), script)
	}
	if lines[0] != "flush set inet cfm block_ext_v4_hosts" {
		t.Fatalf("first line %q, want the flush", lines[0])
	}
	total := 0
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "add element inet cfm block_ext_v4_hosts { ") || !strings.HasSuffix(l, " };") {
			t.Fatalf("not an add statement: %.120s", l)
		}
		total += strings.Count(l, "198.51.100.1")
	}
	if total != len(elems) {
		t.Fatalf("%d elements in the script, want %d", total, len(elems))
	}

	ttl := replaceSetScript("block_ext_v4_hosts_x", []string{"198.51.100.1", "198.51.100.2"}, "6h")
	if !strings.Contains(ttl, "{ 198.51.100.1 timeout 6h, 198.51.100.2 timeout 6h };") {
		t.Fatalf("TTL script: %q", ttl)
	}
	if got := replaceSetScript("s", nil, ""); got != "flush set inet cfm s\n" {
		t.Fatalf("empty replace: %q, want the flush alone", got)
	}
}

// Blank elements would make a `{ , }` statement that fails the whole
// transaction.
func TestCleanElems_DropsBlanks(t *testing.T) {
	got := cleanElems([]string{" 198.51.100.1 ", "", "  ", "198.51.100.2"})
	if strings.Join(got, ",") != "198.51.100.1,198.51.100.2" {
		t.Fatalf("got %q", got)
	}
}

func TestForgetApplied(t *testing.T) {
	b := &Backend{}
	b.recordApplied("a", 1)
	b.recordApplied("b", 2)
	if !b.appliedMatches("a", 1) || b.appliedMatches("a", 2) {
		t.Fatal("appliedMatches")
	}
	b.forgetApplied("a")
	if b.appliedMatches("a", 1) || !b.appliedMatches("b", 2) {
		t.Fatal("forgetApplied(a) must drop a only")
	}
	b.forgetApplied("")
	if b.appliedMatches("b", 2) {
		t.Fatal(`forgetApplied("") must drop every set`)
	}
}

// Only a batch too large for one nft run may fall back to the batched write;
// any other failure (a rejected element) must leave the set as it was.
func TestTooLargeForOneRun(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New(`nft -f - failed: exit status 1 stderr="netlink: Error: Could not process rule: Message too long\nPlease, rise /proc/sys/net/core/wmem_max"`), true},
		{errors.New(`nft -f - failed: exit status 1 stderr="Error: syntax error, unexpected junk"`), false},
		{errors.New(`nft -f - failed: timed_out=true`), false},
		{nil, false},
	} {
		if got := tooLargeForOneRun(tc.err); got != tc.want {
			t.Errorf("tooLargeForOneRun(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
