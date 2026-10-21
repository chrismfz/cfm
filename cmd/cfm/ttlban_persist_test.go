package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/ttlban"
)

// restoreFake is setsFake plus a recorded AddBlockBatch.
type restoreFake struct {
	setsFake
	got []firewall.BlockEntry
}

func (f *restoreFake) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	f.got = append(f.got, entries...)
	return firewall.BlockBatchResult{Added: len(entries)}, nil
}

// A restored ban never covers an address the node must not block: nft's
// allow / ignore sets, cfm.allow and cfm.ignore (a fresh table holds none of
// those yet) and [global] IGNORE_IPS / IGNORE_NETS.
func TestTTLBanRestoreHonoursAllowsAndIgnores(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("cfm.allow", "192.0.2.10\n198.51.100.0/24\n")
	write("cfm.ignore", "192.0.2.11\n")
	write("detectors.conf", "[global]\nIGNORE_IPS = 192.0.2.12\nIGNORE_NETS = 10.20.0.0/16\n")
	defer ttlban.SetPathForTest(filepath.Join(dir, "ttlbans.json"))()
	defer ttlban.SetDefault(nil)

	exp := time.Now().Add(time.Hour)
	s := ttlban.New(ttlban.DefaultPath)
	_, _ = s.Restore(nil, nil)
	var elems []firewall.SetElementTimed
	for _, ip := range []string{
		"192.0.2.10", "198.51.100.77", // cfm.allow host / net
		"192.0.2.11",              // cfm.ignore
		"192.0.2.12", "10.20.3.4", // IGNORE_IPS / IGNORE_NETS
		"203.0.113.1", "203.0.113.2", // nft allow host / fleet whitelist net
		"203.0.113.3",                  // nft ignore set
		"203.0.113.50", "2001:db8::50", // banned, nothing covers them
	} {
		elems = append(elems, firewall.SetElementTimed{Elem: ip, Expires: time.Until(exp)})
	}
	if err := s.Snapshot(time.Now(), elems); err != nil {
		t.Fatal(err)
	}

	be := &restoreFake{setsFake: setsFake{sets: map[string][]firewall.SetElementTimed{
		"allow_v4":          {{Elem: "203.0.113.1"}},
		"allow_ext_v4_nets": {{Elem: "203.0.113.0/30"}}, // .0-.3, covers .2 (and .1, .3)
		"ignore_v4":         {{Elem: "203.0.113.3"}},
	}, fail: map[string]bool{"allow_dyn_v6": true}}} // an unreadable set is skipped, not fatal

	got := restoreTTLBans(be, dir)
	if ttlban.Default() != got {
		t.Fatal("restore did not install the default store")
	}
	restored := map[string]bool{}
	for _, e := range be.got {
		restored[e.IP.String()] = true
	}
	if len(restored) != 2 || !restored["203.0.113.50"] || !restored["2001:db8::50"] {
		t.Fatalf("restored %v, want only 203.0.113.50 and 2001:db8::50", restored)
	}
	if got.Len() != 2 {
		t.Fatalf("store kept %d entries, want the 2 restored", got.Len())
	}
}

// The edge ban reconcile's complete read refreshes the TTL ban store; a
// failed read leaves it alone.
func TestEdgeBanReconcileSnapshotsTTLBans(t *testing.T) {
	dir := t.TempDir()
	ts := ttlban.New(filepath.Join(dir, "ttlbans.json"))
	_, _ = ts.Restore(nil, nil)
	ttlban.SetDefault(ts)
	defer ttlban.SetDefault(nil)

	s := newReconcileStore(t)
	be := &setsFake{sets: map[string][]firewall.SetElementTimed{
		"block_v4": {{Elem: "203.0.113.5", Expires: 6 * time.Hour}, {Elem: "203.0.113.6"}},
	}, fail: map[string]bool{}}
	edgeBanReconcileOnce(s, be, 0)
	e := ts.Entries()
	if len(e) != 1 || e["203.0.113.5"].Set != "block_v4" {
		t.Fatalf("after a full read: %v, want only the timed 203.0.113.5", e)
	}
	be.fail["block_v6"] = true
	be.sets["block_v4"] = nil
	edgeBanReconcileOnce(s, be, 0)
	if ts.Len() != 1 {
		t.Fatal("a failed read emptied the TTL ban store")
	}
}

// The shutdown snapshot reads every persisted set or saves nothing.
func TestSnapshotTTLBansAllOrNone(t *testing.T) {
	ts := ttlban.New(filepath.Join(t.TempDir(), "ttlbans.json"))
	_, _ = ts.Restore(nil, nil)
	be := &setsFake{sets: map[string][]firewall.SetElementTimed{
		"block_v4": {{Elem: "203.0.113.5", Expires: time.Hour}},
		"block_v6": {{Elem: "2001:db8::5", Expires: time.Hour}},
	}, fail: map[string]bool{}}
	if err := snapshotTTLBans(ts, be); err != nil || ts.Len() != 2 {
		t.Fatalf("len=%d err=%v", ts.Len(), err)
	}
	be.fail["block_v6"] = true
	be.sets["block_v4"] = nil
	if err := snapshotTTLBans(ts, be); err == nil || ts.Len() != 2 {
		t.Fatalf("partial read: len=%d err=%v, want an error and the store kept", ts.Len(), err)
	}
}
