package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/firewall"
)

type excludeSetsBE struct {
	firewall.Backend
	sets map[string][]string
}

func (b excludeSetsBE) ListSetElementsTimed(set string) ([]firewall.SetElementTimed, error) {
	var out []firewall.SetElementTimed
	for _, e := range b.sets[set] {
		out = append(out, firewall.SetElementTimed{Elem: e})
	}
	return out, nil
}

// The TTL restore's exclude for an IPv6 client /64: any address of it in an
// allow or ignore set, cfm.ignore or IGNORE_NETS keeps it from coming back
// (the firewall's own guard cannot see those yet at boot).
func TestTTLBanExcludeNetSources(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfm.ignore"), []byte("2001:db8:3:4::9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "detectors.conf"), []byte("[global]\nIGNORE_NETS = 2001:db8:5:6:8000::/65\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	be := excludeSetsBE{sets: map[string][]string{"allow_ext_v6_hosts": {"2001:db8:1:2::77"}}}
	host, nets := ttlBanExclude(be, dir)
	for p, want := range map[string]bool{
		"2001:db8:1:2::/64": true, // a fleet-allowed host inside
		"2001:db8:3:4::/64": true, // cfm.ignore
		"2001:db8:5:6::/64": true, // IGNORE_NETS
		"2001:db8:7:8::/64": false,
	} {
		if got := nets(netip.MustParsePrefix(p)); got != want {
			t.Errorf("exclude %s = %v, want %v", p, got, want)
		}
	}
	if !host(net.ParseIP("2001:db8:1:2::77")) || host(net.ParseIP("2001:db8:1:2::78")) {
		t.Error("the host exclude is exact")
	}
}
