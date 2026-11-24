//go:build linux

package setprobe

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// reply encodes a NEWSETELEM body with one element: key, and the timeout /
// expiration attributes when set (< 0 = left out).
func reply(t *testing.T, key string, timeoutMS, expirationMS int64) []byte {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.String(unix.NFTA_SET_ELEM_LIST_TABLE, "cfm")
	ae.String(unix.NFTA_SET_ELEM_LIST_SET, "block_v4")
	ae.Nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, func(l *netlink.AttributeEncoder) error {
		l.Nested(unix.NFTA_LIST_ELEM, func(e *netlink.AttributeEncoder) error {
			e.ByteOrder = binary.BigEndian
			e.Nested(unix.NFTA_SET_ELEM_KEY, func(k *netlink.AttributeEncoder) error {
				k.Bytes(unix.NFTA_DATA_VALUE, netip.MustParseAddr(key).AsSlice())
				return nil
			})
			if timeoutMS >= 0 {
				e.Uint64(unix.NFTA_SET_ELEM_TIMEOUT, uint64(timeoutMS))
			}
			if expirationMS >= 0 {
				e.Uint64(unix.NFTA_SET_ELEM_EXPIRATION, uint64(expirationMS))
			}
			return nil
		})
		return nil
	})
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseElemReply(t *testing.T) {
	for _, c := range []struct {
		name                string
		timeout, expiration int64
		left                time.Duration
	}{
		{"timed", 3_600_000, 1_800_000, 30 * time.Minute},
		{"expiration only (the set's default timeout)", -1, 60_000, time.Minute},
		{"permanent", -1, -1, 0},
		{"last instant", 3_600_000, 0, time.Millisecond}, // never 0: that reads as permanent
	} {
		r, ok, err := parseElemReply(reply(t, "192.0.2.7", c.timeout, c.expiration))
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", c.name, ok, err)
		}
		if r.key != netip.MustParseAddr("192.0.2.7") || r.left() != c.left {
			t.Errorf("%s: key=%s left=%s, want 192.0.2.7 %s", c.name, r.key, r.left(), c.left)
		}
	}
	if _, err := firstElemReply([]netlink.Message{{Data: []byte{unix.NFPROTO_INET, 0, 0, 0}}}); err == nil {
		t.Error("a reply without an element answered")
	}
}
