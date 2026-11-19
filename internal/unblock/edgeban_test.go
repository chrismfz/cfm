package unblock

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/ttlban"
)

type removeOnlyBE struct{ firewall.Backend }

func (removeOnlyBE) RemoveBlock(net.IP) error        { return nil }
func (removeOnlyBE) RemoveBlockBatch([]net.IP) error { return nil }
func (removeOnlyBE) ListTableTextNoDNS(string, string) (string, error) {
	return "", nil
}
func (removeOnlyBE) HasElem(string, string) (bool, error) { return false, nil }
func (removeOnlyBE) AddAllowBatch([]firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	return firewall.BlockBatchResult{}, nil
}

// DoMany (the agent's fleet unblock, `cfm unblock` in-process) lifts the
// edge ban with the nft one.
func TestDoManyLiftsEdgeBan(t *testing.T) {
	fakeTools(t, map[string]string{})
	s := edgeban.New(filepath.Join(t.TempDir(), "edgeban.json"))
	edgeban.SetDefault(s)
	t.Cleanup(func() { edgeban.SetDefault(nil) })
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		s.Add(net.ParseIP(ip), nil, "waf_security", false)
	}
	s.Reconcile(edgeban.Snapshot{Blocks: []firewall.SetElementTimed{{Elem: "198.51.100.1"}, {Elem: "198.51.100.2"}}, ReadAt: time.Now().Add(time.Second)})

	DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2"), Options{BE: removeOnlyBE{}})
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if ok, _ := s.Banned(ip); ok {
			t.Errorf("%s still edge-banned after DoMany", ip)
		}
	}
}

// netRemoveBE records the network removes an unblock makes.
type netRemoveBE struct {
	removeOnlyBE
	nets []string
}

func (b *netRemoveBE) WriteSetElem(string, string, *time.Duration, bool) error { return nil }
func (b *netRemoveBE) WriteSetElems(string, []firewall.SetElemWrite) error     { return nil }
func (b *netRemoveBE) ListSetElementsTimed(set string) ([]firewall.SetElementTimed, error) {
	if set == firewall.BlockV6Clients {
		return []firewall.SetElementTimed{{Elem: "2001:db8:1:2::/64", Expires: time.Hour}}, nil
	}
	return nil, nil
}
func (b *netRemoveBE) DeleteSetElem(set, cidr string) error {
	b.nets = append(b.nets, set+" "+cidr)
	return nil
}

// Unblocking an IPv6 address frees its client's /64 (an automatic ban takes
// the /64): in nft, at the edge, and in the persisted TTL bans.
func TestDoManyFreesTheIPv6ClientSlash64(t *testing.T) {
	fakeTools(t, map[string]string{})
	s := edgeban.New(filepath.Join(t.TempDir(), "edgeban.json"))
	edgeban.SetDefault(s)
	t.Cleanup(func() { edgeban.SetDefault(nil) })
	s.AddElem("2001:db8:1:2::/64", nil, "waf_security", false)
	s.Reconcile(edgeban.Snapshot{Blocks: []firewall.SetElementTimed{{Elem: "2001:db8:1:2::/64"}}, ReadAt: time.Now().Add(time.Second)})
	if ok, _ := s.Banned("2001:db8:1:2::77"); !ok {
		t.Fatal("setup: the /64 is not edge-banned")
	}
	ts := ttlban.New(filepath.Join(t.TempDir(), "ttlbans.json"))
	ttlban.SetDefault(ts)
	t.Cleanup(func() { ttlban.SetDefault(nil) })
	if _, err := ts.Restore(nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = ts.Snapshot(time.Now(), []firewall.SetElementTimed{{Elem: "2001:db8:1:2::/64", Expires: time.Hour}})
	if ts.Len() != 1 {
		t.Fatalf("setup: ttlban holds %v", ts.Entries())
	}

	be := &netRemoveBE{}
	DoMany(context.Background(), ips("2001:db8:1:2::abcd"), Options{BE: be})
	if len(be.nets) != 1 || be.nets[0] != "block_v6_clients 2001:db8:1:2::/64" {
		t.Fatalf("nft net removes %v, want the /64", be.nets)
	}
	if ok, _ := s.Banned("2001:db8:1:2::77"); ok {
		t.Error("the /64 is still edge-banned")
	}
	if ts.Len() != 0 {
		t.Errorf("the /64 stays restorable: %v", ts.Entries())
	}
}
