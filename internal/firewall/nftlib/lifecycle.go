//go:build linux

package nftlib

// EnsureBase delegates to the embedded nft.Backend to create all CFM-owned
// tables, chains, and sets. The local set handle cache is invalidated so the
// next nftlib operation re-fetches handles from the kernel.
func (b *Backend) EnsureBase() error {
	if err := b.cli.EnsureBase(); err != nil {
		return err
	}
	b.mu.Lock()
	b.invalidateCache()
	b.mu.Unlock()
	return nil
}

// DropEverything delegates to cli; removes all CFM-owned firewall state.
func (b *Backend) DropEverything() error {
	err := b.cli.DropEverything()
	b.mu.Lock()
	b.invalidateCache()
	b.mu.Unlock()
	return err
}

// ResetTable flushes and rebuilds rules from current in-memory config.
func (b *Backend) ResetTable() error {
	err := b.cli.ResetTable()
	b.mu.Lock()
	b.invalidateCache()
	b.mu.Unlock()
	return err
}

// EnsureSetDynamic creates a named dynamic set if it does not exist.
// The cache entry for that set is cleared so the next lookup re-fetches it.
func (b *Backend) EnsureSetDynamic(name string, v6 bool, isNet bool) error {
	err := b.cli.EnsureSetDynamic(name, v6, isNet)
	if err == nil {
		b.mu.Lock()
		delete(b.namedSets, name)
		b.mu.Unlock()
	}
	return err
}

// DeleteSetIfExists removes a named set, ignoring not-found errors.
func (b *Backend) DeleteSetIfExists(name string) error {
	err := b.cli.DeleteSetIfExists(name)
	b.mu.Lock()
	delete(b.namedSets, name)
	b.mu.Unlock()
	return err
}

// FlushSet empties a named set by family/table/set path, delegating to cli.
func (b *Backend) FlushSet(family, table, set string) error {
	return b.cli.FlushSet(family, table, set)
}
