package nftlib

import (
	"fmt"
	"time"

	"github.com/google/nftables"

	"cfm/internal/firewall"
)

var _ firewall.SetElemWriter = (*Backend)(nil)

// WriteSetElem writes elem (a CIDR of an interval set) to set with ttl (nil:
// permanent). replace deletes the element equal to elem first in the same
// netlink batch, one transaction: the element is never absent in between,
// and a failed add leaves the old one in place.
func (b *Backend) WriteSetElem(set, elem string, ttl *time.Duration, replace bool) error {
	add, err := cidrToIntervalElems(elem, ttl)
	if err != nil {
		return fmt.Errorf("nftlib WriteSetElem %s: %w", set, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := b.lookupSet(set)
	if err != nil {
		return fmt.Errorf("nftlib WriteSetElem %s %s: %w", set, elem, err)
	}
	if replace {
		del, _ := cidrToIntervalElems(elem, nil)
		if err := b.conn.SetDeleteElements(s, del); err != nil {
			return fmt.Errorf("nftlib WriteSetElem %s %s: %w", set, elem, err)
		}
	}
	if err := b.conn.SetAddElements(s, add); err != nil {
		return fmt.Errorf("nftlib WriteSetElem %s %s: %w", set, elem, err)
	}
	return b.conn.Flush()
}

// DeleteSetElem deletes elem (a CIDR of an interval set) from set; an element
// the set does not hold is not an error.
func (b *Backend) DeleteSetElem(set, elem string) error {
	if err := b.delCIDRElem(set, elem); err != nil && !isNotFound(err) {
		return err // a missing set (a table an older daemon built) is no error
	}
	return nil
}

// WriteSetElems writes many elements (CIDRs of an interval set) in ONE
// netlink batch (one transaction).
func (b *Backend) WriteSetElems(set string, elems []firewall.SetElemWrite) error {
	if len(elems) == 0 {
		return nil
	}
	var dels, adds []nftables.SetElement
	for _, e := range elems {
		a, err := cidrToIntervalElems(e.Elem, e.TTL)
		if err != nil {
			return fmt.Errorf("nftlib WriteSetElems %s: %w", set, err)
		}
		adds = append(adds, a...)
		if e.Replace {
			d, _ := cidrToIntervalElems(e.Elem, nil)
			dels = append(dels, d...)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := b.lookupSet(set)
	if err != nil {
		return fmt.Errorf("nftlib WriteSetElems %s: %w", set, err)
	}
	if len(dels) > 0 {
		if err := b.conn.SetDeleteElements(s, dels); err != nil {
			return fmt.Errorf("nftlib WriteSetElems %s: %w", set, err)
		}
	}
	if err := b.conn.SetAddElements(s, adds); err != nil {
		return fmt.Errorf("nftlib WriteSetElems %s: %w", set, err)
	}
	return b.conn.Flush()
}
