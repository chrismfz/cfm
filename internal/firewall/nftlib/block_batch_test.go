//go:build linux

package nftlib

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"cfm/internal/firewall"
)

// wireElem is one set element as sent or dumped over netlink.
type wireElem struct {
	key        net.IP
	timeout    time.Duration
	hasTimeout bool
	expires    time.Duration
}

// setElemMsg encodes a NEWSETELEM message for set holding elems, the shape
// the kernel dumps and the library sends.
func setElemMsg(set string, elems []wireElem) netlink.Message {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.String(unix.NFTA_SET_ELEM_LIST_TABLE, cfmTableName)
	ae.String(unix.NFTA_SET_ELEM_LIST_SET, set)
	ae.Nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, func(list *netlink.AttributeEncoder) error {
		for _, e := range elems {
			list.Nested(unix.NFTA_LIST_ELEM, func(el *netlink.AttributeEncoder) error {
				el.Nested(unix.NFTA_SET_ELEM_KEY, func(k *netlink.AttributeEncoder) error {
					k.Bytes(unix.NFTA_DATA_VALUE, normalizeIP(e.key))
					return nil
				})
				if e.hasTimeout {
					el.Uint64(unix.NFTA_SET_ELEM_TIMEOUT, uint64(e.timeout.Milliseconds()))
					el.Uint64(unix.NFTA_SET_ELEM_EXPIRATION, uint64(e.expires.Milliseconds()))
				}
				return nil
			})
		}
		return nil
	})
	data, _ := ae.Encode()
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM), Flags: netlink.Multi},
		Data:   append([]byte{unix.NFPROTO_INET, 0, 0, 0}, data...),
	}
}

// decodeSetElems reads the set name and elements of a NEW/DELSETELEM message.
func decodeSetElems(t *testing.T, m netlink.Message) (set string, elems []wireElem) {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(m.Data[4:])
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_LIST_SET:
			set = ad.String()
		case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
			ad.Nested(func(list *netlink.AttributeDecoder) error {
				list.ByteOrder = binary.BigEndian
				for list.Next() {
					var e wireElem
					list.Nested(func(el *netlink.AttributeDecoder) error {
						el.ByteOrder = binary.BigEndian
						for el.Next() {
							switch el.Type() {
							case unix.NFTA_SET_ELEM_KEY:
								el.Nested(func(k *netlink.AttributeDecoder) error {
									for k.Next() {
										if k.Type() == unix.NFTA_DATA_VALUE {
											e.key = net.IP(k.Bytes())
										}
									}
									return nil
								})
							case unix.NFTA_SET_ELEM_TIMEOUT:
								e.timeout, e.hasTimeout = time.Duration(el.Uint64())*time.Millisecond, true
							}
						}
						return nil
					})
					elems = append(elems, e)
				}
				return nil
			})
		}
	}
	if err := ad.Err(); err != nil {
		t.Fatal(err)
	}
	return set, elems
}

// batchFake serves the block sets from dump (by set name), records every
// write transaction, and fails the first failWrites of them.
type batchFake struct {
	dump       map[string][]wireElem
	failWrites int
	batches    [][]netlink.Message
}

func (f *batchFake) backend(t *testing.T) *Backend {
	t.Helper()
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if isBatch(req) {
			f.batches = append(f.batches, req)
			if f.failWrites > 0 {
				f.failWrites--
				return nil, unix.ENOENT
			}
			return nil, io.EOF
		}
		if nftMsgType(req[0]) != unix.NFT_MSG_GETSETELEM {
			return nil, io.EOF
		}
		ad, _ := netlink.NewAttributeDecoder(req[0].Data[4:])
		set := ""
		for ad.Next() {
			if ad.Type() == unix.NFTA_SET_NAME {
				set = ad.String()
			}
		}
		seq := req[0].Header.Sequence
		var out []netlink.Message
		if elems := f.dump[set]; len(elems) > 0 {
			m := setElemMsg(set, elems)
			m.Header.Sequence = seq
			out = append(out, m)
		}
		return append(out, netlink.Message{Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi, Sequence: seq}}), nil
	})
	for _, s := range []struct {
		name string
		key  nftables.SetDatatype
	}{{setBlockV4, nftables.TypeIPAddr}, {setBlockV6, nftables.TypeIP6Addr}} {
		b.namedSets[s.name] = &nftables.Set{Name: s.name, KeyType: s.key, HasTimeout: true,
			Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
	}
	return b
}

// elemsOf decodes a transaction's DEL/NEWSETELEM messages, in order.
func elemsOf(t *testing.T, batch []netlink.Message) (dels, adds map[string][]wireElem, order []int) {
	dels, adds = map[string][]wireElem{}, map[string][]wireElem{}
	for _, m := range batch {
		switch typ := nftMsgType(m); typ {
		case unix.NFT_MSG_DELSETELEM, unix.NFT_MSG_NEWSETELEM:
			set, elems := decodeSetElems(t, m)
			if typ == unix.NFT_MSG_DELSETELEM {
				dels[set] = append(dels[set], elems...)
			} else {
				adds[set] = append(adds[set], elems...)
			}
			order = append(order, typ)
		}
	}
	return dels, adds, order
}

func v4Entries(n int, ttl time.Duration) []firewall.BlockEntry {
	var out []firewall.BlockEntry
	for i := 0; i < n; i++ {
		out = append(out, firewall.BlockEntry{IP: net.IPv4(10, 2, byte(i/250), byte(i%250+1)), TTL: ttl})
	}
	return out
}

// What goes on the wire: only replaced keys are deleted, deletes come first,
// every add carries its own timeout (none when permanent), and a mixed v4+v6
// batch is ONE transaction.
func TestAddBlockBatch_WireFormat(t *testing.T) {
	f := &batchFake{dump: map[string][]wireElem{setBlockV4: {
		{key: net.ParseIP("10.0.0.1")}, // permanent
		{key: net.ParseIP("10.0.0.2"), hasTimeout: true, timeout: time.Hour, expires: time.Minute},
	}}}
	res, err := f.backend(t).AddBlockBatch([]firewall.BlockEntry{
		{IP: net.ParseIP("10.0.0.1"), TTL: time.Hour},     // permanent: kept
		{IP: net.ParseIP("10.0.0.2"), TTL: 6 * time.Hour}, // 1m left: replaced
		{IP: net.ParseIP("10.0.0.3"), Permanent: true},    // added, no timeout
		{IP: net.ParseIP("2001:db8::1"), TTL: time.Hour},  // added to v6
	})
	if err != nil {
		t.Fatalf("AddBlockBatch: %v", err)
	}
	if res != (firewall.BlockBatchResult{Added: 2, Extended: 1, Kept: 1}) {
		t.Errorf("result = %+v", res)
	}
	if len(f.batches) != 1 {
		t.Fatalf("%d transactions, want one for both families", len(f.batches))
	}
	dels, adds, order := elemsOf(t, f.batches[0])
	if len(dels[setBlockV4]) != 1 || !dels[setBlockV4][0].key.Equal(net.ParseIP("10.0.0.2")) || len(dels[setBlockV6]) != 0 {
		t.Errorf("deletes = %+v, want only the replaced 10.0.0.2", dels)
	}
	if len(order) == 0 || order[0] != unix.NFT_MSG_DELSETELEM {
		t.Errorf("message order %v, want the delete first", order)
	}
	want := map[string]wireElem{
		"10.0.0.2":    {hasTimeout: true, timeout: 6 * time.Hour},
		"10.0.0.3":    {},
		"2001:db8::1": {hasTimeout: true, timeout: time.Hour},
	}
	got := map[string]wireElem{}
	for _, set := range []string{setBlockV4, setBlockV6} {
		for _, e := range adds[set] {
			got[e.key.String()] = e
		}
	}
	if len(got) != len(want) {
		t.Fatalf("adds = %+v, want %v", adds, want)
	}
	for ip, w := range want {
		g := got[ip]
		if g.hasTimeout != w.hasTimeout || g.timeout != w.timeout {
			t.Errorf("%s: sent timeout=%v (present %v), want %v (present %v)", ip, g.timeout, g.hasTimeout, w.timeout, w.hasTimeout)
		}
	}
}

// One transaction per setWriteChunk addresses, not one per address.
func TestAddBlockBatch_OneTransactionPerChunk(t *testing.T) {
	f := &batchFake{}
	res, err := f.backend(t).AddBlockBatch(v4Entries(2500, time.Hour))
	if err != nil {
		t.Fatalf("AddBlockBatch: %v", err)
	}
	if res.Added != 2500 || len(f.batches) != 3 {
		t.Fatalf("result %+v in %d transactions, want 2500 added in 3", res, len(f.batches))
	}
}

// When a later chunk fails, the chunks that committed are counted once and
// left out of the retry — even if the re-read doesn't show them (they may
// have been removed meanwhile, or a tiny TTL expired).
func TestAddBlockBatch_RetryCountsCommittedChunksOnce(t *testing.T) {
	g := &secondFails{}
	res, err := g.backend(t).AddBlockBatch(v4Entries(1500, time.Hour))
	if err != nil {
		t.Fatalf("AddBlockBatch: %v", err)
	}
	if res != (firewall.BlockBatchResult{Added: 1500}) {
		t.Errorf("result = %+v, want exactly 1500 added (no double count, no negative kept)", res)
	}
	if len(g.sizes) != 3 || g.sizes[2] != 500 {
		t.Errorf("transactions carried %v elements, want [1000 500 500] (only the failed chunk retried)", g.sizes)
	}
}

// secondFails commits the first write, fails the second, and serves an
// empty set on every read.
type secondFails struct {
	writes int
	sizes  []int
}

func (g *secondFails) backend(t *testing.T) *Backend {
	t.Helper()
	f := &batchFake{}
	b := f.backend(t)
	b.conn = nlTestConn(t, &b.nl, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, io.EOF
		}
		if isBatch(req) {
			g.writes++
			_, adds, _ := elemsOf(t, req)
			g.sizes = append(g.sizes, len(adds[setBlockV4]))
			if g.writes == 2 {
				return nil, unix.ENOENT
			}
			return nil, io.EOF
		}
		seq := req[0].Header.Sequence
		return []netlink.Message{{Header: netlink.Header{Type: netlink.Done, Flags: netlink.Multi, Sequence: seq}}}, nil
	})
	return b
}

// A write that keeps failing is retried up to blockBatchAttempts times, then
// reported — never broken up into one transaction per address.
func TestAddBlockBatch_RetriesThenReports(t *testing.T) {
	f := &batchFake{failWrites: 99}
	_, err := f.backend(t).AddBlockBatch(v4Entries(10, time.Hour))
	if err == nil || !strings.Contains(err.Error(), "nftlib AddBlockBatch") {
		t.Fatalf("want the write error, got %v", err)
	}
	if len(f.batches) != blockBatchAttempts {
		t.Errorf("%d transactions, want %d (no per-address fallback)", len(f.batches), blockBatchAttempts)
	}
}

// An element with a timeout read at its last instant (0 left) is about to
// expire, not permanent: the batch must extend it, not keep it.
func TestAddBlockBatch_LastInstantIsNotPermanent(t *testing.T) {
	f := &batchFake{dump: map[string][]wireElem{setBlockV4: {
		{key: net.ParseIP("10.0.0.4"), hasTimeout: true, timeout: time.Second},
	}}}
	res, err := f.backend(t).AddBlockBatch([]firewall.BlockEntry{{IP: net.ParseIP("10.0.0.4"), TTL: time.Hour}})
	if err != nil || res != (firewall.BlockBatchResult{Extended: 1}) {
		t.Fatalf("res=%+v err=%v, want the expiring block extended", res, err)
	}
}

// RemoveBlockBatch deletes just the addresses the block sets hold: deleting
// one they don't hold fails the whole transaction with ENOENT, which used to
// leave every address of the batch blocked.
func TestRemoveBlockBatch_DeletesOnlyPresent(t *testing.T) {
	f := &batchFake{dump: map[string][]wireElem{
		setBlockV4: {{key: net.ParseIP("10.0.0.1")}, {key: net.ParseIP("10.0.0.2"), hasTimeout: true, timeout: time.Hour, expires: time.Minute}},
		setBlockV6: {{key: net.ParseIP("2001:db8::1")}},
	}}
	err := f.backend(t).RemoveBlockBatch([]net.IP{
		net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.1"),
		net.ParseIP("2001:db8::7"), net.ParseIP("2001:db8::1"), net.ParseIP("10.0.0.1"),
	})
	if err != nil {
		t.Fatalf("RemoveBlockBatch: %v", err)
	}
	var got []string
	for _, batch := range f.batches {
		dels, adds, _ := elemsOf(t, batch)
		if len(adds) != 0 {
			t.Errorf("unblock sent adds: %+v", adds)
		}
		for _, set := range []string{setBlockV4, setBlockV6} {
			for _, e := range dels[set] {
				got = append(got, set+":"+e.key.String())
			}
		}
	}
	if want := "block_v4:10.0.0.2 block_v4:10.0.0.1 block_v6:2001:db8::1"; strings.Join(got, " ") != want {
		t.Errorf("deleted %v, want %s (present ones only, once each)", got, want)
	}
}

// Nothing to delete means no write at all; a write that keeps failing is
// retried from a fresh read, then reported — never one transaction per address.
func TestRemoveBlockBatch_RetriesThenReports(t *testing.T) {
	f := &batchFake{}
	if err := f.backend(t).RemoveBlockBatch([]net.IP{net.ParseIP("10.0.0.9")}); err != nil || len(f.batches) != 0 {
		t.Fatalf("err=%v, %d transactions; want none for an address no set holds", err, len(f.batches))
	}
	f = &batchFake{failWrites: 1, dump: map[string][]wireElem{setBlockV4: {{key: net.ParseIP("10.0.0.1")}, {key: net.ParseIP("10.0.0.2")}}}}
	if err := f.backend(t).RemoveBlockBatch([]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}); err != nil || len(f.batches) != 2 {
		t.Fatalf("err=%v, %d transactions; want one failed write retried once", err, len(f.batches))
	}
	f.failWrites = 99
	f.batches = nil
	err := f.backend(t).RemoveBlockBatch([]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")})
	if err == nil || !strings.Contains(err.Error(), "nftlib RemoveBlockBatch") {
		t.Fatalf("want the write error, got %v", err)
	}
	if len(f.batches) != blockBatchAttempts {
		t.Errorf("%d transactions, want %d (no per-address fallback)", len(f.batches), blockBatchAttempts)
	}
}

// More than setWriteChunk deletes go in one transaction per chunk; a block
// set that can't be read fails the batch before any write.
func TestRemoveBlockBatch_ChunksAndReadError(t *testing.T) {
	var ips []net.IP
	var dump []wireElem
	for i := 0; i < 2500; i++ {
		ip := net.IPv4(10, 5, byte(i/250), byte(i%250+1))
		ips = append(ips, ip)
		dump = append(dump, wireElem{key: ip})
	}
	f := &batchFake{dump: map[string][]wireElem{setBlockV4: dump}}
	if err := f.backend(t).RemoveBlockBatch(ips); err != nil {
		t.Fatalf("RemoveBlockBatch: %v", err)
	}
	var sizes []int
	for _, batch := range f.batches {
		dels, _, _ := elemsOf(t, batch)
		sizes = append(sizes, len(dels[setBlockV4]))
	}
	if len(sizes) != 3 || sizes[0] != setWriteChunk || sizes[2] != 500 {
		t.Errorf("transactions deleted %v, want [1000 1000 500]", sizes)
	}

	var wrote bool
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			wrote = true
			return nil, io.EOF
		}
		return nil, unix.EIO
	})
	b.namedSets[setBlockV4] = &nftables.Set{Name: setBlockV4, KeyType: nftables.TypeIPAddr, HasTimeout: true,
		Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
	if err := b.RemoveBlockBatch([]net.IP{net.ParseIP("10.0.0.1")}); err == nil || wrote {
		t.Fatalf("err=%v wrote=%v; want a read error and no write", err, wrote)
	}
}
