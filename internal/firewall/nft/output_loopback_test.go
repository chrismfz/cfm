//go:build linux

package nft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNFTOutputChain puts an `nft` script first in PATH that prints listing
// for a read of `inet cfm output` (with or without -a) and logs every script
// fed on stdin.
func fakeNFTOutputChain(t *testing.T, listing string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	if err := os.WriteFile(filepath.Join(dir, "chain"), []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
d=%q
case "$*" in
"list chain inet cfm output"|"-a list chain inet cfm output") cat "$d/chain"; exit 0;;
"-f -") in=$(cat); printf 'SCRIPT %%s\n' "$in" >> "$d/nft.log"; exit 0;;
esac
exit 0
`, dir)
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// A chain that already holds the catch-all NEW drops (every node upgraded from
// a release without the rule) gets the loopback accept INSERTED at its head:
// appended, it would sit below the drops and exempt nothing.
func TestOutputLoopbackAccept_InsertedAtHeadWhenMissing(t *testing.T) {
	log := fakeNFTOutputChain(t, `table inet cfm {
	chain output { # handle 3
		type filter hook output priority filter; policy accept;
		ct state established,related accept # handle 40
		ct state invalid drop # handle 41
		ct state new tcp dport @tcp_out_ports accept # handle 42
		ct state new udp dport @udp_out_ports accept # handle 43
		ct state new tcp dport 0-65535 drop # handle 44
		ct state new udp dport 0-65535 drop # handle 45
	}
}
`)
	if err := (&Backend{}).ensureOutputLoopbackAccept(); err != nil {
		t.Fatalf("ensureOutputLoopbackAccept: %v", err)
	}
	b, err := os.ReadFile(log) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `insert rule inet cfm output oif "lo" accept`) {
		t.Fatalf("want the loopback accept inserted at the head of output:\n%s", got)
	}
	if strings.Contains(got, "add rule inet cfm output") {
		t.Fatalf("appended instead of inserted:\n%s", got)
	}
}

// Present (as nft prints it), it is left alone, so no apply stacks copies.
func TestOutputLoopbackAccept_NotDuplicated(t *testing.T) {
	log := fakeNFTOutputChain(t, `table inet cfm {
	chain output { # handle 3
		type filter hook output priority filter; policy accept;
		oif "lo" accept # handle 39
		ct state established,related accept # handle 40
		ct state new tcp dport 0-65535 drop # handle 44
	}
}
`)
	if err := (&Backend{}).ensureOutputLoopbackAccept(); err != nil {
		t.Fatalf("ensureOutputLoopbackAccept: %v", err)
	}
	b, err := os.ReadFile(log) // #nosec G304 -- test temp file
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SCRIPT") {
		t.Fatalf("wrote a rule although the accept is present:\n%s", b)
	}
}
