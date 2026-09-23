//go:build linux

package nftlib

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// intervalElems decodes a NEWSETELEM message's element list: how many
// elements, and whether each start is followed by its IntervalEnd.
func intervalElems(t *testing.T, m netlink.Message) (n int, pairsIntact bool) {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(m.Data[4:])
	if err != nil {
		t.Fatal(err)
	}
	ad.ByteOrder = binary.BigEndian
	var ends []bool
	for ad.Next() {
		if ad.Type() != unix.NFTA_SET_ELEM_LIST_ELEMENTS {
			continue
		}
		ad.Nested(func(list *netlink.AttributeDecoder) error {
			for list.Next() {
				end := false
				list.Nested(func(el *netlink.AttributeDecoder) error {
					el.ByteOrder = binary.BigEndian
					for el.Next() {
						if el.Type() == unix.NFTA_SET_ELEM_FLAGS {
							end = el.Uint32()&unix.NFT_SET_ELEM_INTERVAL_END != 0
						}
					}
					return nil
				})
				ends = append(ends, end)
			}
			return nil
		})
	}
	if err := ad.Err(); err != nil {
		t.Fatalf("element list does not decode: %v", err)
	}
	pairsIntact = len(ends)%2 == 0
	for i := 0; i+1 < len(ends) && pairsIntact; i += 2 {
		pairsIntact = !ends[i] && ends[i+1]
	}
	return len(ends), pairsIntact
}

// A large interval write arrives whole. google/nftables puts a message's
// elements in one netlink attribute whose 16-bit length silently wraps past
// 64 KiB, so one message of ~1,600+ IPv4 CIDRs reached the kernel truncated —
// possibly as a start without its end, an interval open to the top of the
// address space. Each message now carries at most setWriteChunk elements,
// every start with its end.
func TestReplaceSetFlushAdd_LargeIntervalSetArrivesWhole(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   nftables.SetDatatype
		cidrs func(i int) string
		n     int
		ttl   *time.Duration
	}{
		{"block_ext_v4_nets", nftables.TypeIPAddr, func(i int) string { return fmt.Sprintf("10.%d.%d.0/24", i/256, i%256) }, 5000, nil},
		{"allow_ext_v6_nets", nftables.TypeIP6Addr, func(i int) string { return fmt.Sprintf("2001:db8:%x::/48", i) }, 3000, func() *time.Duration { d := time.Hour; return &d }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []netlink.Message
			var perBatch []int // NEWSETELEM messages in each transaction
			b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
				if !isBatch(req) {
					return nil, io.EOF
				}
				n := 0
				for _, m := range req {
					if nftMsgType(m) == unix.NFT_MSG_NEWSETELEM {
						msgs = append(msgs, m)
						n++
					}
				}
				perBatch = append(perBatch, n)
				return nil, io.EOF
			})
			b.namedSets[tc.name] = &nftables.Set{Name: tc.name, KeyType: tc.key, Interval: true, HasTimeout: true,
				Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
			var elems []string
			for i := 0; i < tc.n; i++ {
				elems = append(elems, tc.cidrs(i))
			}
			if err := b.ReplaceSetFlushAdd(tc.name, elems, tc.ttl); err != nil {
				t.Fatalf("ReplaceSetFlushAdd: %v", err)
			}
			total := 0
			for i, m := range msgs {
				n, ok := intervalElems(t, m)
				if n > setWriteChunk+1 || !ok {
					t.Errorf("message %d: %d elements, pairs intact=%v; want <= %d, every start with its end", i, n, ok, setWriteChunk+1)
				}
				total += n
			}
			if total != 2*tc.n {
				t.Errorf("%d elements arrived, want %d (%d start/end pairs)", total, 2*tc.n, tc.n)
			}
			// The flush is its own transaction (ENOTEMPTY otherwise), then one
			// transaction per batch: many in one would overflow the socket
			// buffer on a large feed ("message too long").
			if len(perBatch) < 2 || perBatch[0] != 0 {
				t.Fatalf("transactions carried %v NEWSETELEM messages, want the flush alone first", perBatch)
			}
			for i, n := range perBatch[1:] {
				if n != 1 {
					t.Errorf("transaction %d carried %d NEWSETELEM messages, want 1", i+1, n)
				}
			}
		})
	}
}

// A bare address bound for an interval set is written as its /32 or /128: a
// lone start element would be an interval open to the top of the address
// space. A host set keeps one element per address.
func TestParseElems_BareAddressInIntervalSet(t *testing.T) {
	iv := &nftables.Set{Interval: true}
	for _, ip := range []string{"198.51.100.7", "2001:db8::7"} {
		got := parseElems(iv, []string{ip}, nil)
		if len(got) != 2 || got[0].IntervalEnd || !got[1].IntervalEnd {
			t.Errorf("%s in an interval set: %+v, want a start and its end", ip, got)
		}
	}
	if got := parseElems(&nftables.Set{}, []string{"198.51.100.7"}, nil); len(got) != 1 || got[0].IntervalEnd {
		t.Errorf("host set: %+v, want one element", got)
	}
}
