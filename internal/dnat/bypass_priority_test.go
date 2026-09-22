package dnat

import (
	"os"
	"testing"

	"cfm/internal/firewall"
)

// bypassReloadBackend reports web DNAT on with a given live table, and records
// the priority DNATOn would install (the backends read NFT_DNAT_PRIORITY when,
// as in the CLI, they carry no config).
type bypassReloadBackend struct {
	firewall.Backend
	show    string
	sawPrio string
	calls   int
}

func (b *bypassReloadBackend) DNATStatus(string, string) (bool, error) { return true, nil }
func (b *bypassReloadBackend) DNATShow(string, string) (string, error) { return b.show, nil }
func (b *bypassReloadBackend) DNATOn(string, string, int, int) error {
	b.calls++
	b.sawPrio = os.Getenv("NFT_DNAT_PRIORITY")
	return nil
}

// A bypass add/remove re-renders the web table. It must keep the live
// priority: it used to fall back to -99, so on a node at -101 (CFM ahead of
// Imunify's -100) every bypass edit silently moved CFM behind Imunify.
func TestBypassReload_KeepsLiveWebDNATPriority(t *testing.T) {
	cases := []struct {
		name, show, want string
	}{
		{"nft backend (symbolic)", "table inet cfm_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n\t\ttcp dport 80 dnat to :9080\n\t}\n}\n", "-101"},
		{"nftlib backend (numeric)", "table inet cfm_redirect {\n  chain prerouting {\n    type nat hook prerouting priority -101; policy accept;\n\n    tcp dport 80 dnat to :9080\n  }\n}\n", "-101"},
		{"unreadable: configured value", "", "-99"},
	}
	for _, tc := range cases {
		t.Setenv("NFT_DNAT_PRIORITY", "")
		b := &bypassReloadBackend{show: tc.show}
		if rc := reloadDNATScope(firewall.DNATBypassScopeWeb, b); rc != 0 || b.calls != 1 {
			t.Fatalf("%s: rc=%d DNATOn calls=%d", tc.name, rc, b.calls)
		}
		if b.sawPrio != tc.want {
			t.Errorf("%s: reload installed priority %q, want %q", tc.name, b.sawPrio, tc.want)
		}
	}
}
