//go:build linux

package nftlib

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/nftables"
)

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
			elem := nftables.SetElement{Key: normalizeIP(ip)}
			if ttl != nil {
				elem.Timeout = *ttl
			}
			result = append(result, elem)
		}
	}
	return result
}
