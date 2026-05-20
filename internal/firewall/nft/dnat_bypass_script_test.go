//go:build linux

package nft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// TestPanelDNATScript_NoBypassFile asserts the panel DNAT script is byte-
// identical to its pre-bypass form when the bypass file does not exist.
// This guards against accidentally emitting empty/garbage rules into the
// nft script when no bypass is configured.
func TestPanelDNATScript_NoBypassFile(t *testing.T) {
	withBypassPath(t, &firewall.DNATBypassCpanelPath, filepath.Join(t.TempDir(), "missing"))

	script := panelDNATScript(-101)
	if strings.Contains(script, "cfm_dnat_bypass") {
		t.Errorf("expected no bypass rules when file missing, got:\n%s", script)
	}
	if strings.Contains(script, "ip saddr") {
		t.Errorf("expected no ip saddr lines when file missing, got:\n%s", script)
	}
}

// TestPanelDNATScript_BypassRulesPrecedeDNAT verifies the critical ordering
// invariant: source-IP bypass accept rules must appear BEFORE the dport
// DNAT rules in the prerouting chain, otherwise nft's first-match-wins
// semantics would NAT the packet before the bypass match short-circuits.
func TestPanelDNATScript_BypassRulesPrecedeDNAT(t *testing.T) {
	tmp := t.TempDir()
	bypass := filepath.Join(tmp, "cpanel_bypass")
	if err := os.WriteFile(bypass, []byte("84.54.49.205\n2001:db8::1\n"), 0o644); err != nil {
		t.Fatalf("write bypass: %v", err)
	}
	withBypassPath(t, &firewall.DNATBypassCpanelPath, bypass)

	script := panelDNATScript(-101)

	bypassIdx := strings.Index(script, "ip saddr 84.54.49.205 accept")
	if bypassIdx < 0 {
		t.Fatalf("expected ipv4 bypass rule in script:\n%s", script)
	}
	if !strings.Contains(script, "ip6 saddr 2001:db8::1 accept") {
		t.Fatalf("expected ipv6 bypass rule in script:\n%s", script)
	}
	if !strings.Contains(script, `comment "cfm_dnat_bypass"`) {
		t.Fatalf("bypass rule must carry cfm_dnat_bypass comment for operator diagnosis:\n%s", script)
	}
	firstDNATIdx := strings.Index(script, "tcp dport 2082 dnat to :12082")
	if firstDNATIdx < 0 {
		t.Fatalf("expected first DNAT mapping in script:\n%s", script)
	}
	if bypassIdx > firstDNATIdx {
		t.Fatalf("bypass rule must precede DNAT rule, but bypass at %d > dnat at %d:\n%s",
			bypassIdx, firstDNATIdx, script)
	}
}

func TestPanelDNATScript_SkippedEntriesEmitWarningComment(t *testing.T) {
	tmp := t.TempDir()
	bypass := filepath.Join(tmp, "cpanel_bypass")
	if err := os.WriteFile(bypass, []byte("84.54.49.205\nnot-an-ip\n999.999.999.999\n"), 0o644); err != nil {
		t.Fatalf("write bypass: %v", err)
	}
	withBypassPath(t, &firewall.DNATBypassCpanelPath, bypass)

	script := panelDNATScript(-101)

	if !strings.Contains(script, "ip saddr 84.54.49.205 accept") {
		t.Errorf("expected valid entry kept:\n%s", script)
	}
	if !strings.Contains(script, "WARNING") {
		t.Errorf("expected WARNING comment for unparseable entries:\n%s", script)
	}
}

func TestDnatScript_BypassRulesPrecedeDNAT(t *testing.T) {
	tmp := t.TempDir()
	bypass := filepath.Join(tmp, "web_bypass")
	if err := os.WriteFile(bypass, []byte("84.54.49.205\n"), 0o644); err != nil {
		t.Fatalf("write bypass: %v", err)
	}
	withBypassPath(t, &firewall.DNATBypassWebPath, bypass)

	script := dnatScript("inet", "cfm_redirect", 9080, 9043, -99)

	bypassIdx := strings.Index(script, "ip saddr 84.54.49.205 accept")
	firstDNATIdx := strings.Index(script, "tcp dport 80")
	if bypassIdx < 0 {
		t.Fatalf("expected bypass rule in web DNAT script:\n%s", script)
	}
	if !strings.Contains(script, `comment "cfm_dnat_bypass"`) {
		t.Fatalf("bypass rule must carry cfm_dnat_bypass comment for operator diagnosis:\n%s", script)
	}
	if firstDNATIdx < 0 {
		t.Fatalf("expected dport 80 DNAT in script:\n%s", script)
	}
	if bypassIdx > firstDNATIdx {
		t.Fatalf("bypass rule must precede DNAT rule, bypass=%d dnat=%d:\n%s",
			bypassIdx, firstDNATIdx, script)
	}
}

func TestDnatScript_NoBypassFile(t *testing.T) {
	withBypassPath(t, &firewall.DNATBypassWebPath, filepath.Join(t.TempDir(), "missing"))
	script := dnatScript("inet", "cfm_redirect", 9080, 9043, -99)
	if strings.Contains(script, "cfm_dnat_bypass") {
		t.Errorf("expected no bypass rules when file missing, got:\n%s", script)
	}
}

// withBypassPath swaps the package-level bypass path var for the duration
// of a test and restores it via t.Cleanup, so tests don't bleed into one
// another or into production paths.
func withBypassPath(t *testing.T, target *string, value string) {
	t.Helper()
	prev := *target
	*target = value
	t.Cleanup(func() { *target = prev })
}
