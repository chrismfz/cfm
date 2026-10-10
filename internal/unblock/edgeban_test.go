package unblock

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
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
