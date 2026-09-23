//go:build linux

package nftlib

import (
	"fmt"
	"net"
	"time"

	"cfm/internal/firewall"

	"github.com/google/nftables"
)

// ── AddBlock / RemoveBlock ───────────────────────────────────────────────────

func (b *Backend) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	setName := setBlockV4
	if ip.To4() == nil {
		setName = setBlockV6
	}
	return b.addIPElem(setName, ip, ttl)
}

func (b *Backend) RemoveBlock(ip net.IP) error {
	setName := setBlockV4
	if ip.To4() == nil {
		setName = setBlockV6
	}
	return b.delIPElem(setName, ip)
}

// RemoveBlockBatch unblocks many host addresses: one read of each block set,
// then deletes of just the addresses it holds (firewall.HostsPresent), one
// transaction per setWriteChunk. Deleting an element the set doesn't hold
// fails the whole transaction with ENOENT, and most addresses of a fleet-wide
// unblock aren't blocked on any one node, so the batch used to delete
// nothing whenever one address was absent.
//
// An element can still expire between the read and the write (ENOENT again);
// the write is then retried from a fresh read, up to blockBatchAttempts
// rounds. Chunks that committed are simply gone from the next read.
func (b *Backend) RemoveBlockBatch(ips []net.IP) error {
	v4, v6 := firewall.SplitHostAddrs(ips)
	if len(v4)+len(v6) == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	fams := []struct {
		name string
		set  *nftables.Set
		want []net.IP
	}{{name: setBlockV4, want: v4}, {name: setBlockV6, want: v6}}
	for i := range fams {
		if len(fams[i].want) == 0 {
			continue
		}
		set, err := b.lookupSet(fams[i].name)
		if err != nil {
			return fmt.Errorf("nftlib RemoveBlockBatch %s: %w", fams[i].name, err)
		}
		fams[i].set = set
	}
	var lastErr error
	for attempt := 0; attempt < blockBatchAttempts; attempt++ {
		lastErr = nil
		for _, f := range fams {
			if len(f.want) == 0 {
				continue
			}
			elems, err := b.conn.GetSetElements(f.set)
			if err != nil {
				return fmt.Errorf("nftlib RemoveBlockBatch read %s: %w", f.name, err)
			}
			present := firewall.HostsPresent(f.want, elemsToTimed(elems, f.set.Interval))
			for i := 0; i < len(present) && lastErr == nil; i += setWriteChunk {
				var chunk []nftables.SetElement
				for _, ip := range present[i:min(i+setWriteChunk, len(present))] {
					chunk = append(chunk, nftables.SetElement{Key: normalizeIP(ip)})
				}
				if err := b.conn.SetDeleteElements(f.set, chunk); err != nil {
					lastErr = err
				} else if err := b.conn.Flush(); err != nil {
					lastErr = err
				}
			}
			if lastErr != nil {
				break
			}
		}
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("nftlib RemoveBlockBatch: %w", lastErr)
}

// ── AddAllow / RemoveAllow ───────────────────────────────────────────────────

func (b *Backend) AddAllow(ip net.IP, ttl *time.Duration) error {
	setName := setAllowV4
	if ip.To4() == nil {
		setName = setAllowV6
	}
	return b.addIPElem(setName, ip, ttl)
}

func (b *Backend) RemoveAllow(ip net.IP) error {
	setName := setAllowV4
	if ip.To4() == nil {
		setName = setAllowV6
	}
	return b.delIPElem(setName, ip)
}

// ── AddIgnore / RemoveIgnore ─────────────────────────────────────────────────

func (b *Backend) AddIgnore(ip net.IP, ttl *time.Duration) error {
	setName := setIgnoreV4
	if ip.To4() == nil {
		setName = setIgnoreV6
	}
	return b.addIPElem(setName, ip, ttl)
}

func (b *Backend) RemoveIgnore(ip net.IP) error {
	setName := setIgnoreV4
	if ip.To4() == nil {
		setName = setIgnoreV6
	}
	return b.delIPElem(setName, ip)
}

// ── CIDR variants ────────────────────────────────────────────────────────────

func (b *Backend) AddBlockNet(cidr string, ttl *time.Duration) error {
	setName, err := cidrSetName(cidr, setBlockV4Net, setBlockV6Net)
	if err != nil {
		return fmt.Errorf("nftlib AddBlockNet: %w", err)
	}
	return b.addCIDRElem(setName, cidr, ttl)
}

func (b *Backend) RemoveBlockNet(cidr string) error {
	setName, err := cidrSetName(cidr, setBlockV4Net, setBlockV6Net)
	if err != nil {
		return fmt.Errorf("nftlib RemoveBlockNet: %w", err)
	}
	return b.delCIDRElem(setName, cidr)
}

func (b *Backend) AddAllowNet(cidr string, ttl *time.Duration) error {
	setName, err := cidrSetName(cidr, setAllowV4Net, setAllowV6Net)
	if err != nil {
		return fmt.Errorf("nftlib AddAllowNet: %w", err)
	}
	return b.addCIDRElem(setName, cidr, ttl)
}

func (b *Backend) RemoveAllowNet(cidr string) error {
	setName, err := cidrSetName(cidr, setAllowV4Net, setAllowV6Net)
	if err != nil {
		return fmt.Errorf("nftlib RemoveAllowNet: %w", err)
	}
	return b.delCIDRElem(setName, cidr)
}

func (b *Backend) AddIgnoreNet(cidr string, ttl *time.Duration) error {
	setName, err := cidrSetName(cidr, setIgnoreV4Net, setIgnoreV6Net)
	if err != nil {
		return fmt.Errorf("nftlib AddIgnoreNet: %w", err)
	}
	return b.addCIDRElem(setName, cidr, ttl)
}

func (b *Backend) RemoveIgnoreNet(cidr string) error {
	setName, err := cidrSetName(cidr, setIgnoreV4Net, setIgnoreV6Net)
	if err != nil {
		return fmt.Errorf("nftlib RemoveIgnoreNet: %w", err)
	}
	return b.delCIDRElem(setName, cidr)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

func (b *Backend) addIPElem(setName string, ip net.IP, ttl *time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return fmt.Errorf("nftlib addIPElem %s %s: %w", setName, ip, err)
	}
	elem := nftables.SetElement{Key: normalizeIP(ip)}
	if ttl != nil {
		elem.Timeout = *ttl
	}
	if err := b.conn.SetAddElements(set, []nftables.SetElement{elem}); err != nil {
		return fmt.Errorf("nftlib addIPElem %s %s: %w", setName, ip, err)
	}
	return b.conn.Flush()
}

func (b *Backend) delIPElem(setName string, ip net.IP) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return fmt.Errorf("nftlib delIPElem %s %s: %w", setName, ip, err)
	}
	elem := nftables.SetElement{Key: normalizeIP(ip)}
	if err := b.conn.SetDeleteElements(set, []nftables.SetElement{elem}); err != nil {
		return fmt.Errorf("nftlib delIPElem %s %s: %w", setName, ip, err)
	}
	if err := b.conn.Flush(); err != nil {
		// Deleting an element that isn't in the set is the desired end state, not a
		// failure — the exec-nft backend explicitly tolerates it ("Could not delete
		// element" / ENOENT). Match that so callers don't see a spurious error.
		// lookupSet already caught a missing set above.
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib delIPElem %s %s: %w", setName, ip, err)
	}
	return nil
}

func (b *Backend) addCIDRElem(setName, cidr string, ttl *time.Duration) error {
	elems, err := cidrToIntervalElems(cidr, ttl)
	if err != nil {
		return fmt.Errorf("nftlib addCIDRElem %s: %w", setName, err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return fmt.Errorf("nftlib addCIDRElem %s %s: %w", setName, cidr, err)
	}
	if err := b.conn.SetAddElements(set, elems); err != nil {
		return fmt.Errorf("nftlib addCIDRElem %s %s: %w", setName, cidr, err)
	}
	return b.conn.Flush()
}

func (b *Backend) delCIDRElem(setName, cidr string) error {
	elems, err := cidrToIntervalElems(cidr, nil)
	if err != nil {
		return fmt.Errorf("nftlib delCIDRElem %s: %w", setName, err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return fmt.Errorf("nftlib delCIDRElem %s %s: %w", setName, cidr, err)
	}
	if err := b.conn.SetDeleteElements(set, elems); err != nil {
		return fmt.Errorf("nftlib delCIDRElem %s %s: %w", setName, cidr, err)
	}
	if err := b.conn.Flush(); err != nil {
		// Deleting a CIDR that isn't in the set is a no-op success — parity with the
		// exec-nft backend (tolerates "Could not delete element" / ENOENT).
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib delCIDRElem %s %s: %w", setName, cidr, err)
	}
	return nil
}

// cidrSetName picks the v4 or v6 set name based on the address family of cidr.
func cidrSetName(cidr, v4Name, v6Name string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if network.IP.To4() != nil {
		return v4Name, nil
	}
	return v6Name, nil
}
