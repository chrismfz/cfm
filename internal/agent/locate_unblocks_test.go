package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cfm/internal/locate"
)

// One search for the whole batch; requests for the same IP get separate
// results (the unblock appends to them), and an IP that doesn't parse is
// left out rather than failing the batch.
func TestLocateUnblocks(t *testing.T) {
	cfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg, "cfm.deny"), []byte("1.2.3.4 # autoblock: SYN flood\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reqs := []PendingUnblock{{ID: 1, IP: "1.2.3.4"}, {ID: 2, IP: "1.2.3.4"}, {ID: 3, IP: "not-an-ip"}, {ID: 4, IP: "5.6.7.8"}}
	found := locateUnblocks(context.Background(), reqs, locate.Options{ConfigDir: cfg})
	if _, ok := found[3]; ok {
		t.Error("an unparsable IP got a result")
	}
	if found[1] == nil || found[2] == nil || found[4] == nil {
		t.Fatalf("found = %v", found)
	}
	if len(found[1].Locations) != 1 || found[1].Locations[0].Reason != "autoblock: SYN flood" {
		t.Errorf("1.2.3.4: %+v", found[1].Locations)
	}
	if len(found[4].Locations) != 0 {
		t.Errorf("5.6.7.8: %+v", found[4].Locations)
	}
	found[1].Locations = append(found[1].Locations, locate.Location{Source: "waf"})
	found[1].Skipped["x"] = "y"
	if len(found[2].Locations) != 1 || found[2].Skipped["x"] != "" {
		t.Error("requests for the same IP share a result")
	}
}
