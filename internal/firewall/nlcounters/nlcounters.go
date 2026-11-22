//go:build linux

// Package nlcounters reads the named counters of one nftables table over
// netlink: a single NFT_MSG_GETOBJ dump, filtered by the kernel to that table
// and to counter objects, decoded here (name + packets + bytes, nothing else).
//
// It exists because `nft list counters table inet cfm` makes the nft CLI load
// every set element of the table before it prints a counter. On EL8's nft
// 1.0.4 with the fleet's sets (26k–85k block_v4, ~307k feed hosts) that took
// 2.8–18.5 s per run, idle (earth, mars, virgo, orion, 2026-11-22), while the
// same dump over netlink answered in 0.3–1.2 ms with the same counters and
// values; every CLI form tried (-t, -j, one `list counter`, `list chain`)
// loads the cache too. The dump never touches a set, so its cost does not
// grow with them.
//
// The decoder skips anything it does not understand (another object type, an
// unknown attribute) rather than failing the dump: google/nftables v0.3.0's
// GetObjects fails the whole call on an object type it cannot decode.
package nlcounters

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Counter is one named counter's value.
type Counter struct {
	Packets uint64
	Bytes   uint64
}

// Dump returns the named counters of table (family inet) by name. A table
// that does not exist yields an empty map and no error (the kernel's dump
// filter matches nothing): the caller decides what an empty answer means.
// Any netlink failure is an error; it never reads as "no counters".
func Dump(ctx context.Context, table string) (map[string]Counter, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("nlcounters: dial: %w", err)
	}
	defer c.Close()
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(5 * time.Second)
	}
	// Without a deadline a dump the kernel never finishes would block the
	// caller for good (the flood dump's overlap guard would then skip every
	// later tick), so a deadline that cannot be set is an error.
	if err := c.SetDeadline(dl); err != nil {
		return nil, fmt.Errorf("nlcounters: set deadline: %w", err)
	}
	// A ruleset change during the dump (a feed apply, a ban) makes the kernel
	// flag the reply NLM_F_DUMP_INTR: it may miss objects. Retry, then fail
	// rather than hand back a partial answer as a whole one.
	for attempt := 0; attempt < dumpAttempts; attempt++ {
		msgs, err := c.Execute(Request(table))
		if err != nil {
			return nil, fmt.Errorf("nlcounters: dump: %w", err)
		}
		if !interrupted(msgs) {
			return Decode(msgs, table), nil
		}
	}
	return nil, ErrInterrupted
}

// dumpAttempts bounds the retries of an interrupted dump.
const dumpAttempts = 3

// ErrInterrupted is Dump's answer when the ruleset changed during every
// attempt.
var ErrInterrupted = errors.New("nlcounters: the ruleset changed during every dump attempt")

func interrupted(msgs []netlink.Message) bool {
	for _, m := range msgs {
		if m.Header.Flags&netlink.DumpInterrupted != 0 {
			return true
		}
	}
	return false
}

// Request is the GETOBJ dump request for table's counter objects.
func Request(table string) netlink.Message {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.String(unix.NFTA_OBJ_TABLE, table)
	ae.Uint32(unix.NFTA_OBJ_TYPE, unix.NFT_OBJECT_COUNTER)
	attrs, _ := ae.Encode() // only fails on an encoder error, none here
	// nfgenmsg: family, version, res_id (big endian).
	data := append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, attrs...)
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETOBJ),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}
}

// Decode turns NEWOBJ dump replies into table's counters. A message that is
// not a counter of inet table (the kernel filters the dump, this does not
// rely on it), or that lacks a name or a packet count, is skipped.
func Decode(msgs []netlink.Message, table string) map[string]Counter {
	out := make(map[string]Counter, len(msgs))
	want := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWOBJ)
	for _, m := range msgs {
		if m.Header.Type != want || len(m.Data) < 4 || m.Data[0] != unix.NFPROTO_INET {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			continue
		}
		ad.ByteOrder = binary.BigEndian
		var (
			name     string
			tbl      string
			objType  uint32
			typeSeen bool
			cnt      Counter
			pktsSeen bool
		)
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_OBJ_TABLE:
				tbl = ad.String()
			case unix.NFTA_OBJ_NAME:
				name = ad.String()
			case unix.NFTA_OBJ_TYPE:
				objType, typeSeen = ad.Uint32(), true
			case unix.NFTA_OBJ_DATA:
				ad.Nested(func(nd *netlink.AttributeDecoder) error {
					for nd.Next() {
						switch nd.Type() {
						case unix.NFTA_COUNTER_PACKETS:
							cnt.Packets, pktsSeen = nd.Uint64(), true
						case unix.NFTA_COUNTER_BYTES:
							cnt.Bytes = nd.Uint64()
						}
					}
					return nil
				})
			}
		}
		if ad.Err() != nil || tbl != table || name == "" || !typeSeen || objType != unix.NFT_OBJECT_COUNTER || !pktsSeen {
			continue
		}
		out[name] = cnt
	}
	return out
}
