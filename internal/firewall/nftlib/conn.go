//go:build linux

package nftlib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"sort"
	"strings"
	"time"

	"cfm/internal/firewall"
	"github.com/google/nftables"
)

// getChain resolves a named chain from inet cfm table.
// Must be called with b.mu held.
func (b *Backend) getChain(name string) (*nftables.Chain, error) {
	t, err := b.lookupTable()
	if err != nil {
		return nil, err
	}
	chains, err := b.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, fmt.Errorf("nftlib: list chains inet: %w", err)
	}
	for _, ch := range chains {
		if ch == nil || ch.Table == nil {
			continue
		}
		if ch.Table.Name == t.Name && ch.Name == name {
			return ch, nil
		}
	}
	return nil, fmt.Errorf("nftlib: chain %q in table %q not found", name, t.Name)
}

// lookupTable returns (or caches) the inet cfm table handle from the kernel.
// Must be called with b.mu held.
func (b *Backend) lookupTable() (*nftables.Table, error) {
	if b.table != nil {
		return b.table, nil
	}
	t, err := b.conn.ListTableOfFamily(cfmTableName, nftables.TableFamilyINet)
	if err != nil {
		return nil, fmt.Errorf("nftlib: inet cfm table: %w", err)
	}
	b.table = t
	return t, nil
}

// lookupSet returns (or caches) a named set handle from the inet cfm table.
// Must be called with b.mu held.
func (b *Backend) lookupSet(name string) (*nftables.Set, error) {
	if s, ok := b.namedSets[name]; ok {
		return s, nil
	}
	t, err := b.lookupTable()
	if err != nil {
		return nil, err
	}
	s, err := b.conn.GetSetByName(t, name)
	if err != nil {
		return nil, fmt.Errorf("nftlib: set %q in inet cfm: %w", name, err)
	}
	b.namedSets[name] = s
	return s, nil
}

// invalidateCache clears the cached table and set handles.
// Must be called with b.mu held whenever the kernel-side table structure changes
// (EnsureBase, ResetTable, EnsureSetDynamic, DeleteSetIfExists).
func (b *Backend) invalidateCache() {
	b.table = nil
	b.namedSets = make(map[string]*nftables.Set)
	// Drop the applied-content cache too: after any structural change the kernel
	// set may have been recreated/flushed, so a matching input hash no longer
	// means the kernel still holds that content — force the next write to apply.
	b.appliedHash = make(map[string]uint64)
}

// normalizeIP returns the canonical byte encoding for a set element key.
// IPv4 → 4 bytes, IPv6 → 16 bytes.
func normalizeIP(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		key := make([]byte, 4)
		copy(key, v4)
		return key
	}
	key := make([]byte, 16)
	copy(key, ip.To16())
	return key
}

// broadcastPlusOne computes "broadcast address + 1" for a network.
// This is the interval-end marker required by nftables interval sets
// to encode a CIDR range as two consecutive set elements.
func broadcastPlusOne(network *net.IPNet) []byte {
	var addr []byte
	if network.IP.To4() != nil {
		addr = make([]byte, 4)
		copy(addr, network.IP.To4())
	} else {
		addr = make([]byte, 16)
		copy(addr, network.IP.To16())
	}
	mask := []byte(network.Mask)

	// broadcast = IP | ~mask
	broadcast := make([]byte, len(addr))
	for i := range addr {
		broadcast[i] = addr[i] | ^mask[i]
	}

	// result = broadcast + 1
	result := make([]byte, len(broadcast))
	copy(result, broadcast)
	carry := 1
	for i := len(result) - 1; i >= 0 && carry > 0; i-- {
		sum := int(result[i]) + carry
		result[i] = byte(sum & 0xFF)
		carry = sum >> 8
	}
	return result
}

// cidrToIntervalElems converts a CIDR string to the two nftables interval
// elements (start + IntervalEnd) required by nftables interval sets.
func cidrToIntervalElems(cidrStr string, ttl *time.Duration) ([]nftables.SetElement, error) {
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}
	var startKey []byte
	if network.IP.To4() != nil {
		startKey = make([]byte, 4)
		copy(startKey, network.IP.To4())
	} else {
		startKey = make([]byte, 16)
		copy(startKey, network.IP.To16())
	}
	start := nftables.SetElement{Key: startKey}
	if ttl != nil {
		start.Timeout = *ttl
	}
	end := nftables.SetElement{Key: broadcastPlusOne(network), IntervalEnd: true}
	return []nftables.SetElement{start, end}, nil
}

// parseElems converts a slice of IP/CIDR strings to nftables.SetElement values.
// For interval sets, CIDR entries are encoded as start+end pairs.
// Unparseable entries are silently skipped (consistent with nft CLI behaviour).
func parseElems(set *nftables.Set, elems []string, ttl *time.Duration) []nftables.SetElement {
	var result []nftables.SetElement
	for _, e := range elems {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			parts, err := cidrToIntervalElems(e, ttl)
			if err != nil {
				continue
			}
			result = append(result, parts...)
		} else {
			ip := net.ParseIP(e)
			if ip == nil {
				continue
			}
			if set.Interval {
				// A bare start would be an interval open to the top of the
				// address space: encode the address as its /32 or /128.
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				if parts, err := cidrToIntervalElems(fmt.Sprintf("%s/%d", ip, bits), ttl); err == nil {
					result = append(result, parts...)
				}
				continue
			}
			elem := nftables.SetElement{Key: normalizeIP(ip)}
			if ttl != nil {
				elem.Timeout = *ttl
			}
			result = append(result, elem)
		}
	}
	return result
}

// ── Read-path helpers (decode kernel set elements back to Go types) ───────────

// keyToIP converts a set element Key byte slice back to a net.IP.
// Returns nil for unrecognised lengths.
func keyToIP(key []byte) net.IP {
	switch len(key) {
	case 4:
		ip := make(net.IP, 4)
		copy(ip, key)
		return ip
	case 16:
		ip := make(net.IP, 16)
		copy(ip, key)
		return ip
	}
	return nil
}

// rangeString renders the addresses first..last (inclusive): one address as
// itself (as nft lists it), a CIDR when they are exactly one prefix, else
// "first-last".
func rangeString(first, last []byte) string {
	a, b := keyToIP(first), keyToIP(last)
	if a == nil || len(first) != len(last) {
		return ""
	}
	if bytes.Equal(first, last) {
		return a.String()
	}
	if len(first) == 4 {
		s, l := uint64(binary.BigEndian.Uint32(first)), uint64(binary.BigEndian.Uint32(last))
		if n := l - s + 1; l >= s && n&(n-1) == 0 && s&(n-1) == 0 {
			return (&net.IPNet{IP: a, Mask: net.CIDRMask(32-bits.TrailingZeros64(n), 32)}).String()
		}
	} else {
		s, l := new(big.Int).SetBytes(first), new(big.Int).SetBytes(last)
		n := new(big.Int).Add(new(big.Int).Sub(l, s), big.NewInt(1))
		if tz := int(n.TrailingZeroBits()); n.Sign() > 0 && n.BitLen()-1 == tz && (s.Sign() == 0 || int(s.TrailingZeroBits()) >= tz) {
			return (&net.IPNet{IP: a, Mask: net.CIDRMask(128-tz, 128)}).String()
		}
	}
	return a.String() + "-" + b.String()
}

// intervalRange is one range of an interval set: its start element (which
// carries the timeout) and its last address.
type intervalRange struct {
	start nftables.SetElement
	last  []byte
}

// intervalRanges pairs an interval set's elements into ranges. The kernel
// stores a range as a start element and an end element keyed one past its
// last address, and a range running to the top of the address space
// (224.0.0.0/3 in a bogon feed, ::/0) has no end element. The elements are
// walked in key order, each start closed by the end that follows it. They
// used to be paired by index — the n-th start with the n-th end — so one
// range without an end shifted every range after it, and a set holding only
// such ranges read as plain addresses.
func intervalRanges(elems []nftables.SetElement) []intervalRange {
	sorted := append([]nftables.SetElement(nil), elems...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if c := bytes.Compare(sorted[i].Key, sorted[j].Key); c != 0 {
			return c < 0
		}
		// Adjacent ranges share a key: the end closes the lower one first.
		return sorted[i].IntervalEnd && !sorted[j].IntervalEnd
	})
	var out []intervalRange
	for i, e := range sorted {
		if e.IntervalEnd {
			continue
		}
		last := bytes.Repeat([]byte{0xff}, len(e.Key)) // no end: to the top
		if i+1 < len(sorted) && len(sorted[i+1].Key) == len(e.Key) && bytes.Compare(sorted[i+1].Key, e.Key) > 0 {
			last = keyMinusOne(sorted[i+1].Key) // the end, or (malformed) the next start
		}
		out = append(out, intervalRange{start: e, last: last})
	}
	return out
}

func keyMinusOne(key []byte) []byte {
	out := append([]byte(nil), key...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]--
		if out[i] != 0xff {
			break
		}
	}
	return out
}

// elemsToTimed converts kernel set elements to (string, expires) pairs,
// preserving the per-element TTL reported by netlink: addresses for a plain
// set, ranges (see intervalRanges, rangeString) for an interval set, with
// the start element's timeout.
func elemsToTimed(elems []nftables.SetElement, interval bool) []firewall.SetElementTimed {
	if !interval {
		out := make([]firewall.SetElementTimed, 0, len(elems))
		for _, e := range elems {
			if ip := keyToIP(e.Key); ip != nil {
				out = append(out, firewall.SetElementTimed{Elem: ip.String(), Expires: elemExpires(e)})
			}
		}
		return out
	}
	var out []firewall.SetElementTimed
	for _, r := range intervalRanges(elems) {
		if s := rangeString(r.start.Key, r.last); s != "" {
			out = append(out, firewall.SetElementTimed{Elem: s, Expires: elemExpires(r.start)})
		}
	}
	return out
}

// elemExpires is an element's remaining time. An element with a timeout read
// at its last instant can report 0 left, which must not read as "no
// timeout" (permanent): it is about to go.
func elemExpires(e nftables.SetElement) time.Duration {
	if e.Expires == 0 && e.Timeout > 0 {
		return time.Millisecond
	}
	return e.Expires
}

// elemsToStrings converts kernel set elements to strings: addresses for a
// plain set, ranges (see intervalRanges, rangeString) for an interval set.
func elemsToStrings(elems []nftables.SetElement, interval bool) []string {
	timed := elemsToTimed(elems, interval)
	out := make([]string, len(timed))
	for i, t := range timed {
		out[i] = t.Elem
	}
	return out
}
