//go:build linux

package nftlib

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"cfm/internal/blocklists"
	"cfm/internal/firewall/nft"
)

// ApplyFeed installs one external blocklist/allowlist feed result.
// All element writes go through nftlib's own ReplaceSetFlushAdd (zero forks).
func (b *Backend) ApplyFeed(_ context.Context, f blocklists.Feed, res *blocklists.FetchResult) error {
	if res == nil {
		return nil
	}
	feedKey := nft.SanitizeFeedName(f.Name)
	isAllow := f.Type == blocklists.TypeAllow
	base := "block_ext"
	if isAllow {
		base = "allow_ext"
	}

	h4, n4 := splitHostsNets(res.V4, false)
	h6, n6 := splitHostsNets(res.V6, true)
	ttl := f.TTL

	// Cache in memory so RebuildExternalUnions never reads the kernel.
	b.extFeedMu.Lock()
	fd := extFeedData{H4: h4, N4: n4, H6: h6, N6: n6, TTL: ttl}
	if isAllow {
		b.extAllow[feedKey] = fd
	} else {
		b.extBlock[feedKey] = fd
	}
	b.extFeedMu.Unlock()

	// Write per-feed sets. EnsureSetDynamic delegates to cli (rare operation);
	// ReplaceSetFlushAdd is nftlib-native (zero forks, one Flush per set).
	nameH4 := fmt.Sprintf("%s_v4_hosts_%s", base, feedKey)
	nameN4 := fmt.Sprintf("%s_v4_nets_%s", base, feedKey)
	nameH6 := fmt.Sprintf("%s_v6_hosts_%s", base, feedKey)
	nameN6 := fmt.Sprintf("%s_v6_nets_%s", base, feedKey)

	if err := b.EnsureSetDynamic(nameH4, false, false); err == nil {
		_ = b.ReplaceSetFlushAdd(nameH4, h4, ttl)
	}
	if err := b.EnsureSetDynamic(nameN4, false, true); err == nil {
		_ = b.ReplaceSetFlushAdd(nameN4, n4, ttl)
	}
	if err := b.EnsureSetDynamic(nameH6, true, false); err == nil {
		_ = b.ReplaceSetFlushAdd(nameH6, h6, ttl)
	}
	if err := b.EnsureSetDynamic(nameN6, true, true); err == nil {
		_ = b.ReplaceSetFlushAdd(nameN6, n6, ttl)
	}

	b.extFeedMu.Lock()
	b.feedKeys[feedKey] = struct{}{}
	b.extFeedMu.Unlock()

	return b.RebuildExternalUnions()
}

// RebuildExternalUnions flushes and repopulates the eight union sets from the
// in-memory feed cache. All writes go through nftlib ReplaceSetFlushAdd.
func (b *Backend) RebuildExternalUnions() error {
	var (
		allowH4, allowN4, allowH6, allowN6 []string
		blockH4, blockN4, blockH6, blockN6 []string
	)

	b.extFeedMu.RLock()
	for _, fd := range b.extAllow {
		allowH4 = append(allowH4, fd.H4...)
		allowN4 = append(allowN4, fd.N4...)
		allowH6 = append(allowH6, fd.H6...)
		allowN6 = append(allowN6, fd.N6...)
	}
	for _, fd := range b.extBlock {
		blockH4 = append(blockH4, fd.H4...)
		blockN4 = append(blockN4, fd.N4...)
		blockH6 = append(blockH6, fd.H6...)
		blockN6 = append(blockN6, fd.N6...)
	}
	b.extFeedMu.RUnlock()

	allowH4 = dedupKeepOrder(allowH4)
	allowN4 = dedupKeepOrder(allowN4)
	allowH6 = dedupKeepOrder(allowH6)
	allowN6 = dedupKeepOrder(allowN6)
	blockH4 = dedupKeepOrder(blockH4)
	blockN4 = dedupKeepOrder(blockN4)
	blockH6 = dedupKeepOrder(blockH6)
	blockN6 = dedupKeepOrder(blockN6)

	_ = b.EnsureSetDynamic("allow_ext_v4_hosts", false, false)
	_ = b.EnsureSetDynamic("allow_ext_v4_nets", false, true)
	_ = b.EnsureSetDynamic("allow_ext_v6_hosts", true, false)
	_ = b.EnsureSetDynamic("allow_ext_v6_nets", true, true)
	_ = b.EnsureSetDynamic("block_ext_v4_hosts", false, false)
	_ = b.EnsureSetDynamic("block_ext_v4_nets", false, true)
	_ = b.EnsureSetDynamic("block_ext_v6_hosts", true, false)
	_ = b.EnsureSetDynamic("block_ext_v6_nets", true, true)

	_ = b.ReplaceSetFlushAdd("allow_ext_v4_hosts", allowH4, nil)
	_ = b.ReplaceSetFlushAdd("allow_ext_v4_nets", allowN4, nil)
	_ = b.ReplaceSetFlushAdd("allow_ext_v6_hosts", allowH6, nil)
	_ = b.ReplaceSetFlushAdd("allow_ext_v6_nets", allowN6, nil)
	_ = b.ReplaceSetFlushAdd("block_ext_v4_hosts", blockH4, nil)
	_ = b.ReplaceSetFlushAdd("block_ext_v4_nets", blockN4, nil)
	_ = b.ReplaceSetFlushAdd("block_ext_v6_hosts", blockH6, nil)
	_ = b.ReplaceSetFlushAdd("block_ext_v6_nets", blockN6, nil)

	return nil
}

// PruneExternalFeeds removes sets whose key is not in activeKeys.
// Set discovery uses the nftlib set handle cache (no subprocess).
func (b *Backend) PruneExternalFeeds(activeKeys []string) error {
	allowed := make(map[string]struct{}, len(activeKeys))
	for _, k := range activeKeys {
		allowed[nft.SanitizeFeedName(k)] = struct{}{}
	}

	allNames, err := b.listSetsByPrefix("allow_ext_", "block_ext_")
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`^(allow|block)_ext_(v4|v6)_(hosts|nets)_(.+)$`)
	for _, name := range allNames {
		m := re.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		key := m[4]
		if _, ok := allowed[key]; ok {
			continue
		}
		_ = b.DeleteSetIfExists(name)
		b.extFeedMu.Lock()
		delete(b.feedKeys, key)
		delete(b.extAllow, key)
		delete(b.extBlock, key)
		b.extFeedMu.Unlock()
	}
	return b.RebuildExternalUnions()
}

// DropFeedSets removes all eight per-feed sets for a given feed name.
func (b *Backend) DropFeedSets(feedName string) {
	suff := nft.SanitizeFeedName(feedName)
	for _, pfx := range []string{"allow_ext", "block_ext"} {
		for _, fam := range []string{"v4", "v6"} {
			for _, kind := range []string{"hosts", "nets"} {
				_ = b.DeleteSetIfExists(fmt.Sprintf("%s_%s_%s_%s", pfx, fam, kind, suff))
			}
		}
	}
	b.extFeedMu.Lock()
	delete(b.feedKeys, suff)
	delete(b.extAllow, suff)
	delete(b.extBlock, suff)
	b.extFeedMu.Unlock()
}

// RemoveFeedByKey removes all per-feed sets for a sanitized feed key and
// rebuilds the union sets.
func (b *Backend) RemoveFeedByKey(feedKey string) error {
	b.DropFeedSets(feedKey)
	return b.RebuildExternalUnions()
}

// listSetsByPrefix returns names of all sets in the inet cfm table whose name
// starts with any of the given prefixes. Uses conn.GetSets — no subprocess.
func (b *Backend) listSetsByPrefix(prefixes ...string) ([]string, error) {
	b.mu.Lock()
	t, err := b.lookupTable()
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}

	sets, err := b.conn.GetSets(t)
	if err != nil {
		return nil, fmt.Errorf("nftlib listSetsByPrefix: %w", err)
	}

	var names []string
	for _, s := range sets {
		for _, pfx := range prefixes {
			if strings.HasPrefix(s.Name, pfx) {
				names = append(names, s.Name)
				break
			}
		}
	}
	return names, nil
}

// ── Feed helpers (pure functions, no engine dependency) ──────────────────────

// splitHostsNets separates a mixed IP/CIDR slice into host IPs and network
// prefixes, validating address-family consistency.
func splitHostsNets(elems []string, isV6 bool) (hosts, nets []string) {
	seenH := make(map[string]struct{})
	seenN := make(map[string]struct{})
	maxBits := 32
	if isV6 {
		maxBits = 128
	}
	for _, s := range elems {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			ones, bits := n.Mask.Size()
			if bits != maxBits {
				continue
			}
			if ones == maxBits {
				ip := n.IP.String()
				if _, ok := seenH[ip]; !ok {
					seenH[ip] = struct{}{}
					hosts = append(hosts, ip)
				}
			} else {
				canon := n.String()
				if _, ok := seenN[canon]; !ok {
					seenN[canon] = struct{}{}
					nets = append(nets, canon)
				}
			}
		} else {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if !isV6 && ip.To4() == nil {
				continue
			}
			if isV6 && (ip.To16() == nil || ip.To4() != nil) {
				continue
			}
			ipS := ip.String()
			if _, ok := seenH[ipS]; !ok {
				seenH[ipS] = struct{}{}
				hosts = append(hosts, ipS)
			}
		}
	}
	return
}

func dedupKeepOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, x := range in {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}
