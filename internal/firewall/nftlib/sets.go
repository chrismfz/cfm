//go:build linux

package nftlib

import (
	"fmt"
	"net"
	"time"

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

func (b *Backend) RemoveBlockBatch(ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	v4Set, err4 := b.lookupSet(setBlockV4)
	v6Set, err6 := b.lookupSet(setBlockV6)

	var v4Elems, v6Elems []nftables.SetElement
	for _, ip := range ips {
		if ip.To4() != nil {
			v4Elems = append(v4Elems, nftables.SetElement{Key: normalizeIP(ip)})
		} else {
			v6Elems = append(v6Elems, nftables.SetElement{Key: normalizeIP(ip)})
		}
	}

	var lastErr error
	if len(v4Elems) > 0 && err4 == nil {
		if err := b.conn.SetDeleteElements(v4Set, v4Elems); err != nil {
			lastErr = err
		}
	}
	if len(v6Elems) > 0 && err6 == nil {
		if err := b.conn.SetDeleteElements(v6Set, v6Elems); err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return fmt.Errorf("nftlib RemoveBlockBatch: %w", lastErr)
	}
	if len(v4Elems)+len(v6Elems) == 0 {
		return nil
	}
	return b.conn.Flush()
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

// ── AddChallenge / RemoveChallenge ───────────────────────────────────────────

func (b *Backend) AddChallenge(ip net.IP, ttl *time.Duration) error {
	setName := setChalV4
	if ip.To4() == nil {
		setName = setChalV6
	}
	return b.addIPElem(setName, ip, ttl)
}

func (b *Backend) RemoveChallenge(ip net.IP) error {
	setName := setChalV4
	if ip.To4() == nil {
		setName = setChalV6
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
	return b.conn.Flush()
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
	return b.conn.Flush()
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
