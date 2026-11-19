package nftlib

import (
	"fmt"
	"time"

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
