//go:build linux

package nftlib

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
)

// EnsureBase creates all core CFM-owned tables, chains, and sets using netlink.
// The local set handle cache is invalidated so the next nftlib operation
// re-fetches handles from the kernel.
func (b *Backend) EnsureBase() error {
	table := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.conn.AddTable(table)

	inputPrio := nftables.ChainPriority(-50)
	acceptPolicy := nftables.ChainPolicyAccept
	b.conn.AddChain(&nftables.Chain{
		Table:    table,
		Name:     "input",
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &inputPrio,
		Policy:   &acceptPolicy,
	})
	b.conn.AddChain(&nftables.Chain{Table: table, Name: "flood"})
	dstNatPrio := *nftables.ChainPriorityNATDest
	b.conn.AddChain(&nftables.Chain{
		Table:    table,
		Name:     "preraw",
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &dstNatPrio,
		Policy:   &acceptPolicy,
	})

	for _, spec := range []struct {
		name       string
		keyType    nftables.SetDatatype
		hasTimeout bool
		interval   bool
	}{
		{name: setAllowV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setAllowV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: setBlockV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setBlockV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: setAllowV4Net, keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: setAllowV6Net, keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: setBlockV4Net, keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: setBlockV6Net, keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: setIgnoreV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setIgnoreV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
		{name: setIgnoreV4Net, keyType: nftables.TypeIPAddr, hasTimeout: true, interval: true},
		{name: setIgnoreV6Net, keyType: nftables.TypeIP6Addr, hasTimeout: true, interval: true},
		{name: setChalV4, keyType: nftables.TypeIPAddr, hasTimeout: true},
		{name: setChalV6, keyType: nftables.TypeIP6Addr, hasTimeout: true},
	} {
		b.conn.AddSet(&nftables.Set{
			Table:      table,
			Name:       spec.name,
			KeyType:    spec.keyType,
			HasTimeout: spec.hasTimeout,
			Interval:   spec.interval,
		}, nil)
	}

	if err := b.conn.Flush(); err != nil {
		if isAlreadyExists(err) {
			// preserve idempotency for repeated EnsureBase calls
		} else {
			return fmt.Errorf("nftlib: ensure base: %w", err)
		}
	}

	b.mu.Lock()
	b.invalidateCache()
	b.mu.Unlock()
	return nil
}

// DropEverything removes all CFM-owned firewall state.
func (b *Backend) DropEverything() error {
	b.mu.Lock()
	table, err := b.lookupTable()
	b.mu.Unlock()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib: drop everything: %w", err)
	}

	b.conn.DelTable(table)
	err = b.conn.Flush()
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("nftlib: drop everything: %w", err)
	}
	b.mu.Lock()
	b.invalidateCache()
	b.mu.Unlock()
	return nil
}

// ResetTable rebuilds CFM table state via native lifecycle operations and
// then triggers delegated policy hook re-apply so hybrid behavior stays aligned
// with the exec backend expectations.
func (b *Backend) ResetTable() error {
	if err := b.DropEverything(); err != nil {
		return fmt.Errorf("nftlib: reset table (drop): %w", err)
	}
	if err := b.EnsureBase(); err != nil {
		return fmt.Errorf("nftlib: reset table (ensure): %w", err)
	}
	if err := b.reapplyPolicyHooks(); err != nil {
		return fmt.Errorf("nftlib: reset table (reapply hooks): %w", err)
	}
	return nil
}

func (b *Backend) reapplyPolicyHooks() error {
	if b.cli == nil {
		return nil
	}
	return b.cli.EnsureBase()
}

// EnsureSetDynamic creates a named dynamic set if it does not exist.
// The cache entry for that set is cleared so the next lookup re-fetches it.
func (b *Backend) EnsureSetDynamic(name string, v6 bool, isNet bool) error {
	keyType, interval := setShape(v6, isNet)
	table := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.conn.AddSet(&nftables.Set{
		Table:      table,
		Name:       name,
		KeyType:    keyType,
		HasTimeout: true,
		Interval:   interval,
	}, nil)
	err := b.conn.Flush()
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("nftlib: ensure dynamic set %q: %w", name, err)
	}
	b.mu.Lock()
	delete(b.namedSets, name)
	b.mu.Unlock()
	return nil
}

// DeleteSetIfExists removes a named set, ignoring not-found errors.
func (b *Backend) DeleteSetIfExists(name string) error {
	b.mu.Lock()
	ns, err := b.lookupSet(name)
	b.mu.Unlock()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib: delete set %q: %w", name, err)
	}
	b.conn.DelSet(ns)
	err = b.conn.Flush()
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("nftlib: delete set %q: %w", name, err)
	}
	b.mu.Lock()
	delete(b.namedSets, name)
	b.mu.Unlock()
	return nil
}

func setShape(v6 bool, isNet bool) (nftables.SetDatatype, bool) {
	if v6 {
		return nftables.TypeIP6Addr, isNet
	}
	return nftables.TypeIPAddr, isNet
}

// FlushSet empties a named set by family/table/set path.
func (b *Backend) FlushSet(family, table, set string) error {
	if !strings.EqualFold(family, "inet") || table != cfmTableName {
		return fmt.Errorf("nftlib: unsupported set path %s %s %s", family, table, set)
	}
	b.mu.Lock()
	ns, err := b.lookupSet(set)
	b.mu.Unlock()
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("nftlib: flush set %s %s %s: %w", family, table, set, err)
	}

	b.conn.FlushSet(ns)
	if err := b.conn.Flush(); err != nil {
		if isNotFound(err) {
			b.mu.Lock()
			b.invalidateCache()
			b.mu.Unlock()
			return nil
		}
		return fmt.Errorf("nftlib: flush set %s %s %s: %w", family, table, set, err)
	}
	return nil
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such") || strings.Contains(s, "not found")
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "already exists")
}
