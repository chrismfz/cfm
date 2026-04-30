package cli

import (
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/firewall/setinventory"
)

func TestFirewallAndStatusShareCanonicalSetInventory(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "cfm.blocklists"), []byte("allow alpha https://example/allow\nblock bad feed https://example/block\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	inventory := setinventory.BuildSetNames(loadConfiguredFeeds(tmp))
	sets := map[string][]string{}
	for _, setName := range inventory {
		sets[setName] = nil
	}
	be := mockDiagBE{dnat: true, sets: sets}
	r := collectFirewallStatus(be, tmp, "nft", "default", false)

	for key, setName := range inventory {
		if _, ok := r.SetSizes[key+"_cardinality"]; !ok {
			t.Fatalf("firewall status missing canonical key %s", key)
		}
		if !(key == "allow_v4" || key == "allow_v6" || key == "allow_v4_nets" || key == "allow_v6_nets" ||
			key == "allow_dyn_v4" || key == "allow_dyn_v6" || key == "block_v4" || key == "block_v6" ||
			key == "block_v4_nets" || key == "block_v6_nets" ||
			len(key) > 10 && (key[:10] == "allow_ext_" || key[:10] == "block_ext_")) {
			continue
		}
		if _, _, _, _, ok := setinventory.ClassifySet(setName); !ok {
			t.Fatalf("cfm status taxonomy does not recognize canonical set %s", setName)
		}
	}
}
