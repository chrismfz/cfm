//go:build linux

package nftlib

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPanelDNATOnReplacesTheRedirectInOneBatch: PanelDNATOn deletes and
// rebuilds the panel redirect in one netlink batch, so a rebuild that fails
// (here an invalid nat priority) leaves the old redirect in force. The delete
// used to be flushed on its own first, and a failed rebuild left the panel
// DNAT off. Run in an isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nftlib/ -run PanelDNATOnReplaces -v
func TestPanelDNATOnReplacesTheRedirectInOneBatch(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "" {
		t.Fatalf("refusing to run: this namespace already has tables (not an isolated netns?):\n%s", out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", panelDNATTableName).Run() })
	listing := func() string {
		out, err := exec.Command("nft", "list", "table", "inet", panelDNATTableName).CombinedOutput()
		if err != nil {
			return ""
		}
		return string(out)
	}

	b, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.PanelDNATOn(-101); err != nil {
		t.Fatalf("PanelDNATOn: %v", err)
	}
	// A second call (a bypass edit, a priority change) replaces it.
	if err := b.PanelDNATOn(-99); err != nil {
		t.Fatalf("PanelDNATOn (replace): %v", err)
	}
	if s := listing(); !strings.Contains(s, "dstnat + 1") || !strings.Contains(s, "dnat to :12083") {
		t.Fatalf("panel redirect after the replace:\n%s", s)
	}
	if got := strings.Count(listing(), "dnat to :12083"); got != 1 {
		t.Fatalf("2083 redirect rules = %d, want 1 (the replace duplicated it?)\n%s", got, listing())
	}
	// nft refuses a nat chain at -200 or below: the batch fails whole.
	if err := b.PanelDNATOn(-250); err == nil {
		t.Fatal("PanelDNATOn(-250) succeeded; want the kernel to refuse it")
	}
	if s := listing(); !strings.Contains(s, "dstnat + 1") || !strings.Contains(s, "dnat to :12083") {
		t.Fatalf("a failed rebuild must keep the old panel redirect, got:\n%s", s)
	}
}
