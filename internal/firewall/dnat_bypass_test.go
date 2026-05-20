package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDNATBypass_FileMissingReturnsEmpty(t *testing.T) {
	entries, skipped, err := LoadDNATBypass(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected nil err for missing file, got %v", err)
	}
	if len(entries) != 0 || len(skipped) != 0 {
		t.Fatalf("expected empty entries/skipped for missing file, got %d/%d", len(entries), len(skipped))
	}
}

func TestLoadDNATBypass_ParsesIPv4_IPv6_CIDR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass")
	content := `# comment
84.54.49.205
84.54.49.0/24 # cluster
2001:db8::1
2001:db8::/64 # ipv6 net

# blank line above
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, skipped, err := LoadDNATBypass(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("unexpected skipped: %v", skipped)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d: %+v", len(entries), entries)
	}
	want := []DNATBypassEntry{
		{Value: "84.54.49.205", IsCIDR: false, IsV6: false},
		{Value: "84.54.49.0/24", IsCIDR: true, IsV6: false},
		{Value: "2001:db8::1", IsCIDR: false, IsV6: true},
		{Value: "2001:db8::/64", IsCIDR: true, IsV6: true},
	}
	for i, w := range want {
		g := entries[i]
		if g.Value != w.Value || g.IsCIDR != w.IsCIDR || g.IsV6 != w.IsV6 {
			t.Errorf("entry %d: got %+v want %+v", i, g, w)
		}
	}
}

func TestLoadDNATBypass_SkipsUnparseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass")
	content := `84.54.49.205
not-an-ip
999.999.999.999
2001:db8::1
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, skipped, err := LoadDNATBypass(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 parsed entries, got %d", len(entries))
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped entries, got %d: %v", len(skipped), skipped)
	}
}

func TestDNATBypassRuleExprs_EmptyReturnsNil(t *testing.T) {
	out := DNATBypassRuleExprs(nil, "inet", "tbl", "prerouting")
	if out != nil {
		t.Fatalf("expected nil rules for empty entries, got %v", out)
	}
}

func TestDNATBypassRuleExprs_EmitsCorrectMatcher(t *testing.T) {
	entries := []DNATBypassEntry{
		{Value: "84.54.49.205"},
		{Value: "84.54.49.0/24", IsCIDR: true},
		{Value: "2001:db8::1", IsV6: true},
		{Value: "2001:db8::/64", IsCIDR: true, IsV6: true},
	}
	rules := DNATBypassRuleExprs(entries, "inet", "cfm_test", "prerouting")
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d: %v", len(rules), rules)
	}
	want := []string{
		`add rule inet cfm_test prerouting ip saddr 84.54.49.205 accept comment "cfm_dnat_bypass"`,
		`add rule inet cfm_test prerouting ip saddr 84.54.49.0/24 accept comment "cfm_dnat_bypass"`,
		`add rule inet cfm_test prerouting ip6 saddr 2001:db8::1 accept comment "cfm_dnat_bypass"`,
		`add rule inet cfm_test prerouting ip6 saddr 2001:db8::/64 accept comment "cfm_dnat_bypass"`,
	}
	for i, w := range want {
		if rules[i] != w {
			t.Errorf("rule %d:\n got: %s\nwant: %s", i, rules[i], w)
		}
	}
}

func TestParseDNATBypassEntry_NormalizesCIDR(t *testing.T) {
	e, err := ParseDNATBypassEntry("84.54.49.5/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Value != "84.54.49.0/24" {
		t.Errorf("expected mask-normalised network, got %s", e.Value)
	}
	if !e.IsCIDR || e.IsV6 {
		t.Errorf("expected IsCIDR=true IsV6=false, got %+v", e)
	}
}

func TestParseDNATBypassEntry_Rejects(t *testing.T) {
	for _, in := range []string{"", " ", "host.example.com", "1.2.3", "1.2.3.4.5", "1.2.3.4/99", "no slash but/many/parts"} {
		if _, err := ParseDNATBypassEntry(in); err == nil {
			t.Errorf("expected error for %q, got nil", in)
		}
	}
}

func TestDNATBypassScope_Path(t *testing.T) {
	if got := DNATBypassScopeWeb.Path(); !strings.HasSuffix(got, "cfm.dnat_bypass") {
		t.Errorf("web scope path: %s", got)
	}
	if got := DNATBypassScopeCpanel.Path(); !strings.HasSuffix(got, "cfm.dnat_cpanel_bypass") {
		t.Errorf("cpanel scope path: %s", got)
	}
}
