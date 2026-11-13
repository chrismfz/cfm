//go:build linux

// Package setprobe asks the kernel whether one element is in a set of the
// inet cfm table: a single NFT_MSG_GETSETELEM over netlink, answered by a
// lookup in the set. `nft get element` answers the same question but loads
// the whole set into its cache first, ~0.7 s for 200 000 addresses, which is
// as much as rewriting it.
//
// Both engines use it before skipping the rewrite of an unchanged feed union,
// so a set another process emptied or recreated (`cfm reset` / `cfm disable`
// from the CLI) is written again; the feed live test probes with it.
//
// Lookup goes further: which element holds an address, the interval of an
// interval set included. ipquery.FindMany (`cfm which` / `cfm search`, the
// agent's locate) answers address queries with it instead of dumping sets.
package setprobe

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Timeout bounds one probe.
var Timeout = 5 * time.Second

// Holds reports whether set (in table inet cfm) holds elem, an address or a
// CIDR. A CIDR is looked up by its first address, the key its interval starts
// at; an address in an interval set is found when an interval covers it.
//
// (false, nil) means the kernel answered that the element is absent (ENOENT).
// Any other failure is an error: an unparsable element, no netlink, a kernel
// that cannot answer a single-element get. Callers that skip work on a true
// answer treat an error as false.
func Holds(set, elem string) (bool, error) {
	key, err := elemKey(elem)
	if err != nil {
		return false, err
	}
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return false, fmt.Errorf("setprobe: dial: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(Timeout))

	data, err := request("cfm", set, key)
	if err != nil {
		return false, err
	}
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETSETELEM),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return false, fmt.Errorf("setprobe: get %s in %s: %w", elem, set, err)
}

// request is the message body: nfgenmsg (inet, v0) and the element list.
func request(table, set string, key []byte) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_SET_ELEM_LIST_TABLE, table)
	ae.String(unix.NFTA_SET_ELEM_LIST_SET, set)
	ae.Nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, func(l *netlink.AttributeEncoder) error {
		l.Nested(unix.NFTA_LIST_ELEM, func(e *netlink.AttributeEncoder) error {
			e.Nested(unix.NFTA_SET_ELEM_KEY, func(k *netlink.AttributeEncoder) error {
				k.Bytes(unix.NFTA_DATA_VALUE, key)
				return nil
			})
			return nil
		})
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("setprobe: encode: %w", err)
	}
	return append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, attrs...), nil
}

// elemKey is the set key of an address or CIDR: 4 bytes for IPv4, 16 for
// IPv6, the network address of a CIDR.
func elemKey(elem string) ([]byte, error) {
	elem = strings.TrimSpace(elem)
	var ip net.IP
	if strings.Contains(elem, "/") {
		_, n, err := net.ParseCIDR(elem)
		if err != nil {
			return nil, fmt.Errorf("setprobe: %q: %w", elem, err)
		}
		ip = n.IP
	} else {
		ip = net.ParseIP(elem)
	}
	if ip == nil {
		return nil, fmt.Errorf("setprobe: %q is not an address or CIDR", elem)
	}
	if v4 := ip.To4(); v4 != nil {
		return []byte(v4), nil
	}
	return []byte(ip.To16()), nil
}
