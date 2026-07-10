//go:build linux

package nft

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestDNATOnPlacesAcceptsBeforeDefaultDrop exercises the real DNATOn code path
// against a live `nft` ruleset and asserts the scoped accepts land BEFORE the
// default drop. It is a regression test for the 2026-07 bug where
// ensureScopedDNATAccepts listed the chain with `nftOut("-a list …")` — a
// script-mode syntax error — so the accepts were appended AFTER the drop and
// silently never matched.
//
// It mutates the live `inet cfm` table, so it is gated behind
// CFM_NFT_INTEGRATION=1 and root + nft; normal `go test ./...` skips it. Run it
// in an isolated netns, e.g.:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run DNATOnPlaces -v
func TestDNATOnPlacesAcceptsBeforeDefaultDrop(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}

	// Safety net: this test flush/delete-s the `inet cfm` table, which is the
	// PRODUCTION table name. Netns isolation is the operator's job (see the doc
	// comment), but if an inet cfm table with real content already exists we
	// refuse rather than wipe a live firewall — CFM_NFT_INTEGRATION=1 set on the
	// wrong host must not nuke production.
	if out, err := exec.Command("nft", "list", "table", "inet", "cfm").CombinedOutput(); err == nil {
		s := string(out)
		if strings.Contains(s, "allow_v4") || strings.Contains(s, "block_v4") || strings.Contains(s, "hook input") {
			t.Fatalf("refusing to run: a populated `inet cfm` table already exists (looks like a real firewall) — run this test inside an isolated netns (unshare -rn)")
		}
	}

	nft := func(script string) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f -: %v\n%s\nscript:\n%s", err, out, script)
		}
	}

	// Daemon-like base: input chain at -50 with the catch-all default drop that
	// ApplyPortsPolicy installs. Fresh table so we control the contents.
	nft(`add table inet cfm
flush table inet cfm
add chain inet cfm input { type filter hook input priority -50; policy accept; }
add rule inet cfm input ct state established,related accept
add rule inet cfm input ct state new tcp dport 0-65535 drop
add rule inet cfm input ct state new udp dport 0-65535 drop
add rule inet cfm input ct state invalid drop`)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	b := New()
	// DNATOn also builds the inet cfm_redirect table; drop it on the way out.
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm_redirect").Run() })
	if err := b.DNATOn("inet", "cfm_redirect", 9080, 9043); err != nil {
		t.Fatalf("DNATOn: %v", err)
	}

	// Call twice: the second run must NOT duplicate the accepts (the old bug's
	// cleanup read an error string and deleted nothing).
	if err := b.EnsureDNATAccepts(); err != nil {
		t.Fatalf("EnsureDNATAccepts: %v", err)
	}

	out, err := b.ListChainText("inet", "cfm", "input")
	if err != nil {
		t.Fatalf("ListChainText: %v", err)
	}

	dropIdx, acceptIdx := -1, -1
	acceptCount := 0
	for i, line := range strings.Split(out, "\n") {
		if webDNATIsDropLineForTest(line) && dropIdx == -1 {
			dropIdx = i
		}
		if strings.Contains(line, "cfm_dnat_accept:web_http_tcp:80:9080") {
			if acceptIdx == -1 {
				acceptIdx = i
			}
			acceptCount++
		}
	}
	if acceptIdx == -1 {
		t.Fatalf("no web_http_tcp accept found in chain:\n%s", out)
	}
	if dropIdx == -1 {
		t.Fatalf("no default drop found in chain:\n%s", out)
	}
	if acceptIdx > dropIdx {
		t.Fatalf("accept (line %d) is AFTER the default drop (line %d) — the bug:\n%s", acceptIdx, dropIdx, out)
	}
	if acceptCount != 1 {
		t.Fatalf("web_http_tcp accept appears %d times, want 1 (no duplicates):\n%s", acceptCount, out)
	}
}

func webDNATIsDropLineForTest(line string) bool {
	n := strings.ReplaceAll(line, `"`, "")
	return strings.Contains(n, "ct state new") && strings.Contains(n, "tcp dport 0-65535") && strings.Contains(n, " drop")
}
