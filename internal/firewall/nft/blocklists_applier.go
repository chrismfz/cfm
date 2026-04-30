package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"cfm/internal/blocklists"
	"cfm/internal/firewall/feedutil"
)

// --- Applier: καλείται από τον blocklists.Manager για κάθε feed ----

func (b *Backend) ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error {
	if res == nil {
		return nil
	}
	feedKey := SanitizeFeedName(f.Name)

	isAllow := (f.Type == blocklists.TypeAllow)
	base := "block_ext"
	if isAllow {
		base = "allow_ext"
	}

	// χώρισε hosts vs nets, v4/v6
	h4, n4 := feedutil.SplitHostsNets(res.V4, false)
	h6, n6 := feedutil.SplitHostsNets(res.V6, true)

	ttl := f.TTL // *time.Duration

	// cache raw elems in-memory so union rebuild never needs `nft -j list set`
	b.cacheExternalFeed(isAllow, feedKey, h4, n4, h6, n6, ttl)

	// per-feed δυναμικά sets
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

	// μετά από κάθε apply, ξαναχτίσε τα unions που κοιτούν οι rules
	b.registerFeedKey(feedKey)
	return b.RebuildExternalUnions()
}

// RebuildExternalUnions: union όλων των per-feed sets σε 4 “global” sets

func (b *Backend) RebuildExternalUnions() error {
	// Build the 8 unions purely from in-memory feed caches.
	// This avoids the extremely expensive `nft -j list set ...` that blocks startup on huge sets.
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

	// Optional: dedup (keeps unions stable if multiple feeds overlap)
	allowH4 = feedutil.DedupKeepOrder(allowH4)
	allowN4 = feedutil.DedupKeepOrder(allowN4)
	allowH6 = feedutil.DedupKeepOrder(allowH6)
	allowN6 = feedutil.DedupKeepOrder(allowN6)
	blockH4 = feedutil.DedupKeepOrder(blockH4)
	blockN4 = feedutil.DedupKeepOrder(blockN4)
	blockH6 = feedutil.DedupKeepOrder(blockH6)
	blockN6 = feedutil.DedupKeepOrder(blockN6)

	// Ensure unions exist (they are referenced by the base rules)
	_ = b.EnsureSetDynamic("allow_ext_v4_hosts", false, false)
	_ = b.EnsureSetDynamic("allow_ext_v4_nets", false, true)
	_ = b.EnsureSetDynamic("allow_ext_v6_hosts", true, false)
	_ = b.EnsureSetDynamic("allow_ext_v6_nets", true, true)
	_ = b.EnsureSetDynamic("block_ext_v4_hosts", false, false)
	_ = b.EnsureSetDynamic("block_ext_v4_nets", false, true)
	_ = b.EnsureSetDynamic("block_ext_v6_hosts", true, false)
	_ = b.EnsureSetDynamic("block_ext_v6_nets", true, true)

	// Flush & add (even if empty → union becomes empty)
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

// --- Helpers -------------------------------------------------------------

// Επιστρέφει τα elements ενός set ως raw []string (IP ή CIDR), χωρίς parsing σε net.IP
func (b *Backend) ListSetElementsRaw(setName string) ([]string, error) {
	res, err := runNFTCommand(context.Background(), "-j", "list", "set", family, tableName, setName)
	raw := []byte(res.Stdout + res.Stderr)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	nftables, _ := root["nftables"].([]any)
	var out []string
	for _, it := range nftables {
		m, _ := it.(map[string]any)
		setObj, _ := m["set"].(map[string]any)
		if setObj == nil {
			continue
		}
		arr, _ := setObj["elem"].([]any)
		if len(arr) == 0 {
			arr, _ = setObj["elements"].([]any)
		}
		for _, e := range arr {
			switch v := e.(type) {
			case string:
				s := strings.TrimSpace(v)
				if s != "" {
					out = append(out, s)
				}
			case map[string]any:
				// JSON formats ποικίλουν: πιάσε val όπου υπάρχει
				if inner, ok := v["elem"].(map[string]any); ok {
					val := toStr(inner["val"])
					val = strings.TrimSpace(val)
					if val != "" {
						out = append(out, val)
					}
				} else if val := strings.TrimSpace(toStr(v["elem"])); val != "" {
					out = append(out, val)
				}
				// (σε “interval” sets το nft συνήθως επιστρέφει CIDR ως string, οπότε τα καλύψαμε ήδη)
			}
		}
	}
	return out, nil
}

// Optional: remove all per-feed sets for a given sanitized feed key
func (b *Backend) RemoveFeedByKey(feedKey string) error {
	names := []string{
		fmt.Sprintf("allow_ext_v4_hosts_%s", feedKey),
		fmt.Sprintf("allow_ext_v4_nets_%s", feedKey),
		fmt.Sprintf("allow_ext_v6_hosts_%s", feedKey),
		fmt.Sprintf("allow_ext_v6_nets_%s", feedKey),
		fmt.Sprintf("block_ext_v4_hosts_%s", feedKey),
		fmt.Sprintf("block_ext_v4_nets_%s", feedKey),
		fmt.Sprintf("block_ext_v6_hosts_%s", feedKey),
		fmt.Sprintf("block_ext_v6_nets_%s", feedKey),
	}
	for _, n := range names {
		_ = b.DeleteSetIfExists(n) // best-effort
	}
	return b.RebuildExternalUnions()
}

// Bulk prune: delete per-feed sets whose key is NOT in activeKeys
func (b *Backend) PruneExternalFeeds(activeKeys []string) error {
	allowed := map[string]struct{}{}
	for _, k := range activeKeys {
		allowed[SanitizeFeedName(k)] = struct{}{}
	}

	allNames := append(b.listSetsWithPrefix("allow_ext_"), b.listSetsWithPrefix("block_ext_")...)
	re := regexp.MustCompile(`^(allow|block)_ext_(v4|v6)_(hosts|nets)_(.+)$`)
	for _, name := range allNames {
		m := re.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		key := m[4] // suffix after last underscore(s)
		if _, ok := allowed[key]; !ok {
			_ = b.DeleteSetIfExists(name)
			b.unregisterFeedKey(key)
			b.dropExternalFeedCache(key)
		}
	}
	return b.RebuildExternalUnions()
}

func (b *Backend) DeleteSetIfExists(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	args := []string{"delete", "set", family, tableName, name}
	res, err := runNFTCommand(ctx, args...)
	out := []byte(res.Stdout + res.Stderr)
	_ = out
	_ = err // ignore; it's fine if the set wasn't there
	return nil
}
