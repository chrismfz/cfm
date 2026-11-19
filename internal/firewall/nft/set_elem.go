package nft

import (
	"fmt"
	"strings"
	"time"

	"cfm/internal/firewall"
)

var _ firewall.SetElemWriter = (*Backend)(nil)

// WriteSetElem writes elem to set with ttl (nil: permanent). replace deletes
// the element equal to elem first in the same `nft -f` run, one transaction:
// the element is never absent in between, and a failed add leaves the old
// one in place.
func (b *Backend) WriteSetElem(set, elem string, ttl *time.Duration, replace bool) error {
	add := fmt.Sprintf("add element %s %s %s { %s }", family, tableName, set, elem)
	if ttl != nil && *ttl > 0 {
		add = fmt.Sprintf("add element %s %s %s { %s timeout %s }", family, tableName, set, elem, humanTimeout(*ttl))
	}
	script := add
	if replace {
		script = fmt.Sprintf("delete element %s %s %s { %s }\n%s", family, tableName, set, elem, add)
	}
	return b.nftExpr(script)
}

// DeleteSetElem deletes elem from set; an element the set does not hold is
// not an error.
func (b *Backend) DeleteSetElem(set, elem string) error {
	out, err := b.nftOut(fmt.Sprintf("delete element %s %s %s { %s }", family, tableName, set, elem))
	if err != nil && !missingElement(out) && !missingElement(err.Error()) {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// WriteSetElems writes many elements in ONE `nft -f` run (one transaction).
func (b *Backend) WriteSetElems(set string, elems []firewall.SetElemWrite) error {
	if len(elems) == 0 {
		return nil
	}
	var sb strings.Builder
	for _, e := range elems {
		if e.Replace {
			fmt.Fprintf(&sb, "delete element %s %s %s { %s }\n", family, tableName, set, e.Elem)
		}
		if e.TTL != nil && *e.TTL > 0 {
			fmt.Fprintf(&sb, "add element %s %s %s { %s timeout %s }\n", family, tableName, set, e.Elem, humanTimeout(*e.TTL))
		} else {
			fmt.Fprintf(&sb, "add element %s %s %s { %s }\n", family, tableName, set, e.Elem)
		}
	}
	return b.nftExpr(strings.TrimSuffix(sb.String(), "\n"))
}
