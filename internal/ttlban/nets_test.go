package ttlban

import (
	"net"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// netsFake adds block_v6_clients to batchFake: listed, written and deleted
// as the real set is (firewall.SetElemWriter); the guard's sets are empty.
type netsFake struct {
	batchFake
	nets    map[string]time.Duration // 0 = permanent
	addErr  error
	added   []string
	removed []string
}

func (f *netsFake) ListSetElementsTimed(set string) ([]firewall.SetElementTimed, error) {
	var out []firewall.SetElementTimed
	if set == firewall.BlockV6Clients {
		for e, d := range f.nets {
			out = append(out, firewall.SetElementTimed{Elem: e, Expires: d})
		}
	}
	return out, nil
}

func (f *netsFake) WriteSetElem(set, cidr string, ttl *time.Duration, replace bool) error {
	if set != firewall.BlockV6Clients {
		return errFake
	}
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, cidr)
	f.nets[cidr] = 0
	if ttl != nil {
		f.nets[cidr] = *ttl
	}
	return nil
}

func (f *netsFake) DeleteSetElem(set, cidr string) error {
	f.removed = append(f.removed, cidr)
	delete(f.nets, cidr)
	return nil
}

// block_v6_clients is one of the mirrored sets: an IPv6 client's /64 ban
// survives a restart like a host ban. IPv4 nets, ranges and permanent
// elements are not kept.
func TestSnapshotKeepsTimedIPv6Nets(t *testing.T) {
	found := false
	for _, s := range Sets {
		found = found || s == firewall.BlockV6Clients
	}
	if !found {
		t.Fatalf("Sets = %v, want %s in it", Sets, firewall.BlockV6Clients)
	}
	s, path := newStore(t)
	if _, err := s.Restore(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Snapshot(t0, []firewall.SetElementTimed{
		{Elem: "2001:DB8:1:2::/64", Expires: 6 * time.Hour},
		{Elem: "2001:db8:9::/48", Expires: time.Hour},
		{Elem: "2001:db8:7::/64"},                             // permanent (cfm.deny)
		{Elem: "198.51.100.0/24", Expires: time.Hour},         // IPv4 net
		{Elem: "2001:db8::1-2001:db8::9", Expires: time.Hour}, // a range
		{Elem: "2001:db8:1:2::1/64", Expires: time.Hour},      // not canonical: its network
	}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if len(got) != 2 || got["2001:db8:1:2::/64"].Set != firewall.BlockV6Clients || got["2001:db8:9::/48"].Set != firewall.BlockV6Clients {
		t.Fatalf("file %v", got)
	}
	if !got["2001:db8:1:2::/64"].Expires.Equal(t0.Add(6 * time.Hour)) {
		t.Fatalf("expiry: %v (the later of the two equal keys must not win blindly)", got["2001:db8:1:2::/64"])
	}
}

// Restore brings a /64 back with the time it had left, through the
// never-shorten extend; host bans still go through the batch.
func TestRestoreBringsBackIPv6Nets(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{
		"2001:db8:1:2::/64": {Set: firewall.BlockV6Clients, Expires: t0.Add(90 * time.Minute)},
		"2001:db8:5:6::/64": {Set: firewall.BlockV6Clients, Expires: t0.Add(-time.Minute)}, // expired
		"192.0.2.1":         {Set: "block_v4", Expires: t0.Add(time.Hour)},
	})
	if err := s.Load(); err != nil || s.Len() != 3 {
		t.Fatalf("load: len=%d err=%v", s.Len(), err)
	}
	be := &netsFake{nets: map[string]time.Duration{}}
	res, err := s.Restore(be, nil)
	if err != nil {
		t.Fatal(err)
	}
	if be.nets["2001:db8:1:2::/64"] != 90*time.Minute || len(be.nets) != 1 {
		t.Fatalf("nets after restore: %v", be.nets)
	}
	if len(be.got) != 1 || be.got[0].IP.String() != "192.0.2.1" {
		t.Fatalf("host batch: %v", be.got)
	}
	if res.Expired != 1 {
		t.Fatalf("result %+v", res)
	}
	// A longer ban in nft already is kept, never shortened.
	s2, path2 := newStore(t)
	writeFile(t, path2, map[string]Entry{"2001:db8:1:2::/64": {Expires: t0.Add(time.Hour)}})
	_ = s2.Load()
	be2 := &netsFake{nets: map[string]time.Duration{"2001:db8:1:2::/64": 0}}
	if _, err := s2.Restore(be2, nil); err != nil || be2.nets["2001:db8:1:2::/64"] != 0 || len(be2.added) != 0 {
		t.Fatalf("over a permanent /64: err=%v nets=%v added=%v", err, be2.nets, be2.added)
	}
	// A net nft cannot take is reported, the host bans still restored.
	s3, path3 := newStore(t)
	writeFile(t, path3, map[string]Entry{"2001:db8:1:2::/64": {Expires: t0.Add(time.Hour)}, "192.0.2.9": {Expires: t0.Add(time.Hour)}})
	_ = s3.Load()
	be3 := &netsFake{nets: map[string]time.Duration{}, addErr: errFake}
	if _, err := s3.Restore(be3, nil); err == nil || !strings.Contains(err.Error(), "2001:db8:1:2::/64") || len(be3.got) != 1 {
		t.Fatalf("a failed net: err=%v hosts=%v", err, be3.got)
	}
}

var errFake = &net.AddrError{Err: "refused"}

// An unblock forgets the /64; one landing during the restore takes it out
// again; ForgetInFile drops it from a file.
func TestForgetIPv6Nets(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{"2001:db8:1:2::/64": {Expires: t0.Add(time.Hour)}})
	_ = s.Load()
	be := &netsFake{nets: map[string]time.Duration{}}
	be.during = func() {}
	// The unblock lands after the batch: Forget inside the net extend is not
	// hookable, so forget right after Load, before Restore runs the undo pass.
	if err := s.Forget("2001:db8:1:2::/64"); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("store after Forget: %v", s.Entries())
	}
	writeFile(t, path, map[string]Entry{"2001:db8:1:2::/64": {Expires: t0.Add(time.Hour)}, "192.0.2.1": {Expires: t0.Add(time.Hour)}})
	if err := ForgetInFile(path, "2001:DB8:1:2::/64"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); len(got) != 1 {
		t.Fatalf("file after ForgetInFile: %v", got)
	}
}
