//go:build linux

package nft

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"cfm/internal/config"
)

// TestDNATOnReplacesTheRedirectInOneTransaction: DNATOn and PanelDNATOn
// replace their redirect table in one nft transaction. A replacement that
// fails (here an invalid nat priority) leaves the old redirect in force, the
// same with new listener ports (`cfm dnat on` then removes a redirect to
// other ports itself: dropRedirectToOtherPorts in internal/dnat). Run in an
// isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run DNATOnReplaces -v
func TestDNATOnReplacesTheRedirectInOneTransaction(t *testing.T) {
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
	t.Cleanup(func() {
		for _, tbl := range []string{"cfm", "cfm_redirect", "cfm_panel_redirect"} {
			_ = exec.Command("nft", "delete", "table", "inet", tbl).Run()
		}
	})
	listing := func(tbl string) string {
		out, err := exec.Command("nft", "list", "table", "inet", tbl).CombinedOutput()
		if err != nil {
			return ""
		}
		return string(out)
	}

	b := New()
	b.cfg = &config.Config{}
	b.cfg.NFT.DNATPriority = -101
	if err := b.DNATOn("inet", "cfm_redirect", 9080, 9043); err != nil {
		t.Fatalf("DNATOn: %v", err)
	}
	// A second DNATOn (a bypass edit, a priority change) replaces it.
	b.cfg.NFT.DNATPriority = -99
	if err := b.DNATOn("inet", "cfm_redirect", 9080, 9043); err != nil {
		t.Fatalf("DNATOn (replace): %v", err)
	}
	if s := listing("cfm_redirect"); !strings.Contains(s, "dnat to :9080") || !strings.Contains(s, "dstnat + 1") {
		t.Fatalf("redirect after the replace:\n%s", s)
	}

	// Same ports, failing replacement: the old redirect stays in force.
	b.cfg.NFT.DNATPriority = -300 // nft refuses a nat chain at -200 or below
	if err := b.DNATOn("inet", "cfm_redirect", 9080, 9043); err == nil {
		t.Fatal("DNATOn with an invalid priority succeeded")
	}
	if s := listing("cfm_redirect"); !strings.Contains(s, "dnat to :9080") || !strings.Contains(s, "dstnat + 1") {
		t.Fatalf("a failed same-port replacement did not keep the old redirect:\n%s", s)
	}

	// New ports, failing replacement: the backend keeps the old redirect too;
	// whether it must go is the `cfm dnat on` caller's call.
	if err := b.DNATOn("inet", "cfm_redirect", 9081, 9044); err == nil {
		t.Fatal("DNATOn to new ports with an invalid priority succeeded")
	}
	if s := listing("cfm_redirect"); !strings.Contains(s, "dnat to :9080") {
		t.Fatalf("a failed port change did not keep the old redirect:\n%s", s)
	}

	// And it comes back once the replacement can succeed.
	b.cfg.NFT.DNATPriority = -101
	if err := b.DNATOn("inet", "cfm_redirect", 9081, 9044); err != nil {
		t.Fatalf("DNATOn (recovered): %v", err)
	}
	if s := listing("cfm_redirect"); !strings.Contains(s, "dnat to :9081") {
		t.Fatalf("redirect after recovery:\n%s", s)
	}

	// Panel: a failing replacement keeps the old panel redirect.
	if err := b.PanelDNATOn(-101); err != nil {
		t.Fatalf("PanelDNATOn: %v", err)
	}
	if err := b.PanelDNATOn(-300); err == nil {
		t.Fatal("PanelDNATOn with an invalid priority succeeded")
	}
	if s := listing("cfm_panel_redirect"); !strings.Contains(s, "dnat to :12083") || !strings.Contains(s, "dstnat - 1") {
		t.Fatalf("a failed panel replacement did not keep the old redirect:\n%s", s)
	}
}
