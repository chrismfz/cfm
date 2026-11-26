package unblock

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// lookupFeedBackend is feedBackend with the two cheap reads both engines
// have: the sets listing (ListSetsJSON) and the kernel lookup
// (LookupSetElems). The table's text listing, the set dump and HasElem fail
// the test: an unblock must not reach them when the cheap reads answer.
type lookupFeedBackend struct {
	feedBackend
	t         *testing.T
	listErr   error
	lookupErr error
	lookups   int
	dumps     int
}

func (b *lookupFeedBackend) ListSetsJSON(context.Context, string) ([]byte, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	// nft -j -t list sets inet: every table of the family, without elements.
	return []byte(`{"nftables":[{"metainfo":{}},
{"set":{"family":"inet","name":"block_ext_v4_hosts_MYBLOCK","table":"cfm","type":"ipv4_addr"}},
{"set":{"family":"inet","name":"block_ext_v6_hosts_MYBLOCK","table":"cfm","type":"ipv6_addr"}},
{"set":{"family":"inet","name":"block_ext_v4_hosts_OTHER","table":"other","type":"ipv4_addr"}},
{"set":{"family":"inet","name":"block_v4","table":"cfm","type":"ipv4_addr"}}]}`), nil
}

func (b *lookupFeedBackend) ListTableTextNoDNS(string, string) (string, error) {
	b.t.Error("the table's text listing was read (it loads every element on EL8)")
	return b.feedBackend.ListTableTextNoDNS("", "")
}

func (b *lookupFeedBackend) ListSetElementsRaw(set string) ([]string, error) {
	b.dumps++
	if b.lookupErr == nil {
		b.t.Errorf("set %s dumped although the lookup answered", set)
	}
	return b.feedBackend.ListSetElementsRaw(set)
}

func (b *lookupFeedBackend) LookupSetElems(_ context.Context, table, set string, addrs []netip.Addr) (from, to []netip.Addr, ok []bool, err error) {
	b.lookups++
	if table != "cfm" {
		b.t.Errorf("lookup in table %q", table)
	}
	if b.lookupErr != nil {
		return nil, nil, nil, b.lookupErr
	}
	from, to, ok = make([]netip.Addr, len(addrs)), make([]netip.Addr, len(addrs)), make([]bool, len(addrs))
	for i, a := range addrs {
		if a.Is4() != setIsV4(set) {
			return nil, nil, nil, errors.New("setprobe: wrong family")
		}
		for _, e := range b.feed {
			if e == a.String() {
				from[i], to[i], ok[i] = a, a, true
			}
		}
	}
	return from, to, ok, nil
}

// An unblock finds the feed sets from the sets listing and asks each one
// about its family's IPs by lookup: no table listing, no set dump.
func TestDoMany_FeedsFromTheSetsListingAndLookups(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &lookupFeedBackend{feedBackend: feedBackend{feed: []string{"198.51.100.1", "2001:db8::1"}}, t: t}
	ttl := 4 * time.Hour
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "2001:db8::1"), Options{BE: be, TempWhitelist: true, AllowTTL: &ttl})
	if be.lookups != 2 {
		t.Errorf("%d lookups, want one per feed set of the cfm table (2)", be.lookups)
	}
	for ip, want := range map[string]bool{"198.51.100.1": true, "198.51.100.2": false, "2001:db8::1": true} {
		r := res[ip]
		if got := len(r.FromFeeds) == 1 && r.FromFeeds[0] == "MYBLOCK"; got != want || r.Whitelisted != want {
			t.Errorf("%s: feeds %v whitelisted %v, want in the feed: %v", ip, r.FromFeeds, r.Whitelisted, want)
		}
		for _, s := range stepsOf(r, SrcFeeds) {
			if s.Action == ActionError {
				t.Errorf("%s: feed error step %+v", ip, s)
			}
		}
	}
}

// A lookup the kernel cannot answer falls back to the set's dump, as before.
func TestDoMany_FeedLookupFailureReadsTheSet(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &lookupFeedBackend{feedBackend: feedBackend{feed: []string{"198.51.100.1"}}, t: t, lookupErr: errors.New("setprobe: ambiguous")}
	ttl := 4 * time.Hour
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2"), Options{BE: be, TempWhitelist: true, AllowTTL: &ttl})
	if be.dumps != 1 {
		t.Errorf("%d dumps, want the v4 set read once", be.dumps)
	}
	if r := res["198.51.100.1"]; len(r.FromFeeds) != 1 || !r.Whitelisted {
		t.Errorf("fallback: feeds %v whitelisted %v", r.FromFeeds, r.Whitelisted)
	}
}

// A sets listing that ran out of time is an error step (the feeds are
// unchecked), not a fallback to the table listing, which is slower still.
func TestDoMany_SetsListingTimeoutIsAnError(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &lookupFeedBackend{feedBackend: feedBackend{feed: []string{"198.51.100.1"}}, t: t, listErr: context.DeadlineExceeded}
	res := DoMany(context.Background(), ips("198.51.100.1"), Options{BE: be, TempWhitelist: true})
	var errs int
	for _, s := range stepsOf(res["198.51.100.1"], SrcFeeds) {
		if s.Action == ActionError {
			errs++
		}
	}
	if errs != 1 {
		t.Errorf("%d feed error steps, want 1", errs)
	}
}
